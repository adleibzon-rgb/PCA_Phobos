package com.pca.phobos.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * PCA Phobos VPN — client: imports a phobos:// link from the panel, runs the
 * bundled wg-obfuscator + userspace WireGuard, split tunnelling by apps.
 * The app itself is always outside the tunnel so the obfuscator reaches the server directly.
 */
public class MainActivity extends Activity {
    static final int LPORT = 13255;
    static final String ACTION_TOGGLE = "com.pca.phobos.vpn.TOGGLE";
    static final String MODE_ALL = "all", MODE_ONLY = "only", MODE_EXCEPT = "except";

    static GoBackend backend;
    static Process obfuscator, relay;
    static final int TCP_LPORT = 13256;
    static volatile String transport = "";      // "UDP" | "TCP" | "Облако" while up
    static WsRelay wsRelay;
    static V6Relay v6Relay;
    static final int V6_LPORT = 13257;
    static final Object LOCK = new Object();
    /** Panel subscription (# pca-sub): servers in the panel's order, IPv6 entries last; failover walks them round-robin. */
    static org.json.JSONArray sub = new org.json.JSONArray();
    static volatile int subIndex;
    static volatile String curConf = "";         // profile pointed at the server in use
    static volatile long watchGen;               // bumped on connect/disconnect: stops the old watcher
    static final long SILENCE_MS = 40000;        // no server reply this long -> next server
    static final Tunnel TUNNEL = new Tunnel() {
        public String getName() { return "phobos"; }
        public void onStateChange(Tunnel.State s) { }
    };

    private final ExecutorService bg = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;
    private boolean dark;
    private TextView status, traffic, server;
    private Button power;
    private long lastRx, lastTx, lastT;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("vpn", MODE_PRIVATE);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        if (backend == null) backend = new GoBackend(getApplicationContext());
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 8);
        }
        handleIntent(getIntent());
        render();
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        handleIntent(i);
        render();
    }

    private void handleIntent(Intent i) {
        if (i != null && ACTION_TOGGLE.equals(i.getAction())) {
            setIntent(new Intent());
            // tile: toggle and get out of the way, unless Android must ask for the VPN permission first
            if (!isUp() && !prefs.getString("conf", "").isEmpty() && VpnService.prepare(this) == null) { bg.execute(this::up); finish(); return; }
            if (isUp()) { bg.execute(this::down); finish(); return; }
            toggle();
            return;
        }
        if (i != null && i.getData() != null && "phobos".equals(i.getData().getScheme())) {
            importLink(i.getDataString());
        }
    }

    // ── colors / widgets ──────────────────────────────────────────────────
    private int bg() { return dark ? 0xFF0F172A : 0xFFF1F5F9; }
    private int card() { return dark ? 0xFF1E293B : 0xFFFFFFFF; }
    private int text() { return dark ? 0xFFE2E8F0 : 0xFF0F172A; }
    private int muted() { return dark ? 0xFF94A3B8 : 0xFF64748B; }
    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private GradientDrawable round(int color, int r) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(r));
        return g;
    }

    private Button button(String label, int color, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(Color.WHITE);
        b.setBackground(round(color, 10));
        b.setOnClickListener(l);
        return b;
    }

    private TextView tv(String s, int color, int size, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(color);
        t.setTextSize(size);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private LinearLayout.LayoutParams mw(int top) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(top);
        return lp;
    }

    // ── profile ───────────────────────────────────────────────────────────
    /** phobos://<urlsafe-base64 of conf>#name  (format produced by the PCA Phobos panel). */
    private void importLink(String link) { importText(link, "Phobos"); }

    /** A phobos:// link, or the text of a client .conf ([Interface] + [Peer] + [instance]). */
    private void importText(String text, String name) {
        try {
            String s = text.replace("\uFEFF", "").trim(), conf = s;
            if (s.startsWith("phobos://")) {
                int hash = s.indexOf('#');
                if (hash > 0) { name = Uri.decode(s.substring(hash + 1)); s = s.substring(0, hash); }
                s = s.replaceFirst("^phobos://", "").trim();
                conf = new String(Base64.decode(s, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING), StandardCharsets.UTF_8);
            }
            if (!conf.contains("[Interface]") || !conf.contains("[instance]"))
                throw new IllegalArgumentException("нужен конфиг Phobos: секции [Interface], [Peer] и [instance]");
            Config.parse(new BufferedReader(new StringReader(wgPart(conf, MODE_ALL, "", false))));  // validate
            prefs.edit().putString("conf", conf).putString("name", name).apply();
            toast("Профиль «" + name + "» импортирован");
        } catch (Exception e) {
            toast("Не удалось импортировать: " + e.getMessage());
        }
    }

    /** Split payload into sections: header -> lines (drop "= none" placeholders). */
    private static List<String> section(String conf, String header) {
        List<String> out = new ArrayList<>();
        boolean in = false;
        for (String raw : conf.split("\n")) {
            String ln = raw.trim();
            if (ln.startsWith("[") && ln.endsWith("]")) { in = ln.equalsIgnoreCase(header); continue; }
            if (!in || ln.isEmpty() || !ln.contains("=")) continue;
            if (ln.substring(ln.indexOf('=') + 1).trim().equalsIgnoreCase("none")) continue;
            out.add(ln);
        }
        return out;
    }

    private static String key(String line) { return line.substring(0, line.indexOf('=')).trim().toLowerCase(); }
    private static String val(String line) { return line.substring(line.indexOf('=') + 1).trim(); }

    String wgPart(String conf, String mode, String apps, boolean ruRoutes) {
        StringBuilder sb = new StringBuilder("[Interface]\n");
        for (String ln : section(conf, "[Interface]")) {
            String k = key(ln);
            if (k.equals("excludedapplications") || k.equals("includedapplications")) continue;
            if (k.equals("dns") && !myDns().isEmpty()) continue;
            sb.append(ln).append('\n');
        }
        if (!myDns().isEmpty()) sb.append("DNS = ").append(myDns()).append('\n');
        List<String> sel = new ArrayList<>();
        for (String a : apps.split(",")) if (!a.trim().isEmpty()) sel.add(a.trim());
        if (MODE_ONLY.equals(mode) && !sel.isEmpty()) {
            sel.remove(getPackageNameSafe());
            sb.append("IncludedApplications = ").append(String.join(", ", sel)).append('\n');
        } else {
            Set<String> ex = new LinkedHashSet<>();
            ex.add(getPackageNameSafe());          // obfuscator must bypass the tunnel
            if (MODE_EXCEPT.equals(mode)) ex.addAll(sel);
            sb.append("ExcludedApplications = ").append(String.join(", ", ex)).append('\n');
        }
        sb.append("\n[Peer]\n");
        String ruBypass = ruRoutes && prefs.getBoolean("ru_direct", true) ? ruBypassAllowedIps() : null;
        for (String ln : section(conf, "[Peer]")) {
            if (key(ln).equals("endpoint")) ln = "Endpoint = 127.0.0.1:" + LPORT;
            if (key(ln).equals("allowedips") && ruBypass != null) ln = "AllowedIPs = " + ruBypass;
            sb.append(ln).append('\n');
        }
        return sb.toString();
    }

    /** Internet minus Russian networks (assets/ru_nets.txt) and the user's own sites; resolves domains, so not on the UI thread. */
    private String ruBypassAllowedIps() {
        List<String> ru = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new java.io.InputStreamReader(
                getAssets().open("ru_nets.txt"), StandardCharsets.UTF_8))) {
            for (String ln; (ln = r.readLine()) != null; ) {
                if (!ln.startsWith("#") && ln.contains("/")) for (String c : ln.split(",")) ru.add(c.trim());
            }
        } catch (Exception e) { log("ru_nets: " + e); }
        return RuNets.allowed(ru, lines(prefs.getString("my_direct", "")), lines(prefs.getString("my_vpn", "")));
    }

    private static List<String> lines(String s) {
        List<String> out = new ArrayList<>();
        for (String l : s.split("[\\n,\\s]+")) if (!l.trim().isEmpty()) out.add(l.trim());
        return out;
    }

    /** User's own DNS servers ("1.1.1.1, 8.8.8.8"); empty = the profile's. */
    private String myDns() { return prefs.getString("dns", ""); }

    private static String getPackageNameSafe() { return "com.pca.phobos.vpn"; }

    private static final java.util.Set<String> OBF_KEYS = new java.util.HashSet<>(java.util.Arrays.asList(
            "target", "key", "masking", "idle-timeout", "max-dummy", "static-bindings", "max-clients", "target-if", "allow-clean", "in-timeout", "resolve-interval"));

    private String obfPart(String conf, String targetOverride) {
        StringBuilder sb = new StringBuilder("[instance]\nsource-if = 127.0.0.1\nsource-lport = " + LPORT + "\n");
        for (String ln : section(conf, "[instance]")) {
            String k = key(ln);
            if (k.equals("source-if") || k.equals("source-lport") || k.equals("verbose")) continue;
            // configs from other Phobos builds carry keys our wg-obfuscator v1.6 rejects (obfuscate-bytes…)
            if (!OBF_KEYS.contains(k)) continue;
            if (targetOverride != null && k.equals("target")) ln = "target = " + targetOverride;
            sb.append(ln).append('\n');
        }
        sb.append("verbose = INFO\n");
        return sb.toString();
    }

    /** "# pca-tcp = 443" written by the panel when the server has the TCP fallback. */
    private static String tcpPort(String conf) {
        for (String ln : conf.split("\n")) {
            String t = ln.trim();
            if (t.startsWith("#") && t.contains("pca-tcp") && t.contains("=")) return val(t);
        }
        return "";
    }

    /** wss:// of the user's Keenetic (KeenDNS cloud subdomain -> wsgw): set in the app, or "# pca-ws = wss://…" in the link. */
    private String wsUrl(String conf) {
        String u = prefs.getString("ws_url", "");
        if (!u.isEmpty()) return u;
        for (String ln : conf.split("\n")) {
            String t = ln.trim();
            if (t.startsWith("#") && t.contains("pca-ws") && t.contains("=")) return val(t);
        }
        return "";
    }

    /** "# pca-sub = http://panel/api/phone-sub/<client>?token=…" */
    private static String subUrl(String conf) {
        for (String ln : conf.split("\n")) {
            String t = ln.trim();
            if (t.startsWith("#") && t.contains("pca-sub") && t.contains("=")) return val(t);
        }
        return "";
    }

    /** Same profile pointed at another subscription server (address, obfuscator key, server WG key, TCP port). */
    static String applying(String conf, org.json.JSONObject s) {
        String host = s.optString("host"), sec = "";
        if (host.contains(":")) host = "[" + host + "]";
        StringBuilder sb = new StringBuilder();
        for (String raw : conf.split("\n", -1)) {
            String ln = raw.trim();
            if (ln.startsWith("[") && ln.endsWith("]")) sec = ln.toLowerCase();
            else if (ln.startsWith("#")) { if (ln.contains("pca-tcp")) continue; }
            else if (ln.contains("=")) {
                String k = key(ln);
                if (sec.equals("[instance]") && k.equals("target")) { sb.append("target = ").append(host).append(':').append(s.optInt("port")).append('\n'); continue; }
                if (sec.equals("[instance]") && k.equals("key")) { sb.append("key = ").append(s.optString("key")).append('\n'); continue; }
                if (sec.equals("[peer]") && k.equals("publickey")) { sb.append("PublicKey = ").append(s.optString("wg_pub")).append('\n'); continue; }
            }
            sb.append(raw).append('\n');
        }
        if (s.optInt("tcp") != 0) sb.append("# pca-tcp = ").append(s.optInt("tcp")).append('\n');
        return sb.toString();
    }

    /** Pull the server list from the panel (the app is outside the tunnel); cached when the panel is unreachable. */
    private void refreshSub(String conf) {
        String u = subUrl(conf);
        if (u.isEmpty()) { sub = new org.json.JSONArray(); return; }
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(u).openConnection();
            c.setConnectTimeout(6000); c.setReadTimeout(6000);
            try (java.io.InputStream in = c.getInputStream()) {
                String body = new String(readAll(in), StandardCharsets.UTF_8);
                org.json.JSONArray a = new org.json.JSONObject(body).getJSONArray("servers");
                if (a.length() > 0) prefs.edit().putString("sub", a.toString()).apply();
            }
        } catch (Exception e) { log("sub: " + e); }
        try { sub = new org.json.JSONArray(prefs.getString("sub", "[]")); } catch (Exception e) { sub = new org.json.JSONArray(); }
    }

    private static byte[] readAll(java.io.InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) > 0; ) o.write(buf, 0, n);
        return o.toByteArray();
    }

    private String target(String conf) {
        for (String ln : section(conf, "[instance]")) if (key(ln).equals("target")) return val(ln);
        return "?";
    }

    // ── connect / disconnect ──────────────────────────────────────────────
    private boolean isUp() { return tunnelUp(); }

    static boolean tunnelUp() {
        try { return backend != null && backend.getState(TUNNEL) == Tunnel.State.UP; } catch (Exception e) { return false; }
    }

    /** Ongoing notification = shield in the status bar while the VPN is on (GoBackend's service has none). */
    private void notifyState(boolean up) {
        android.app.NotificationManager nm = (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (!up) { nm.cancel(1); PhobosTile.refresh(this); return; }
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new android.app.NotificationChannel("vpn", "VPN", android.app.NotificationManager.IMPORTANCE_LOW));
        }
        android.app.PendingIntent open = android.app.PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), android.app.PendingIntent.FLAG_IMMUTABLE);
        android.app.Notification.Builder b = android.os.Build.VERSION.SDK_INT >= 26
                ? new android.app.Notification.Builder(this, "vpn") : new android.app.Notification.Builder(this);
        b.setSmallIcon(R.drawable.ic_vpn).setContentTitle("VPN")
                .setContentText("Сервер: " + target(curConf.isEmpty() ? prefs.getString("conf", "") : curConf))
                .setOngoing(true).setContentIntent(open);
        try { nm.notify(1, b.build()); } catch (SecurityException ignored) { }
        PhobosTile.refresh(this);
    }

    private void toggle() {
        if (isUp()) { bg.execute(this::down); return; }
        if (prefs.getString("conf", "").isEmpty()) { toast("Сначала импортируйте ссылку phobos:// из панели"); return; }
        Intent prep = VpnService.prepare(this);
        if (prep != null) startActivityForResult(prep, 7);
        else bg.execute(this::up);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == 9) {
            if (res != RESULT_OK || data == null || data.getData() == null) return;
            String name = "Phobos";
            try (android.database.Cursor c = getContentResolver().query(data.getData(), null, null, null, null)) {
                int i = c == null ? -1 : c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                if (i >= 0 && c.moveToFirst()) name = c.getString(i).replaceFirst("\\.[^.]*$", "");
            } catch (Exception ignored) { }
            try (java.io.InputStream in = getContentResolver().openInputStream(data.getData())) {
                importText(new String(readAll(in), StandardCharsets.UTF_8), name);
            } catch (Exception e) { toast("Не удалось прочитать файл: " + e.getMessage()); }
            applyIfUp();
            render();
            return;
        }
        if (req == 7 && res == RESULT_OK) bg.execute(this::up);
        else if (req == 7) toast("Без разрешения на VPN подключиться нельзя");
    }

    /** Start (or restart) obfuscator; via TCP / cloud it dials the local relay on TCP_LPORT. */
    private void startTransport(String conf, String via) throws Exception {
        stopObfuscator();
        String lib = getApplicationInfo().nativeLibraryDir;
        boolean viaTcp = "tcp".equals(via), viaWs = "cloud".equals(via);
        if (viaWs) {
            if (wsUrl(conf).isEmpty()) throw new IllegalStateException("не задан адрес роутера (wss://…) для канала «Облако»");
            wsRelay = new WsRelay(TCP_LPORT, wsUrl(conf), this::log);
            wsRelay.start();
        }
        String target = target(conf), host = target.replaceAll(":\\d+$", "").replaceAll("[\\[\\]]", "");
        String override = viaTcp || viaWs ? "127.0.0.1:" + TCP_LPORT : null;
        if (!viaTcp && !viaWs && host.contains(":")) {
            v6Relay = new V6Relay(V6_LPORT, host, Integer.parseInt(target.replaceAll("^.*:", "")));
            v6Relay.start();
            override = "127.0.0.1:" + V6_LPORT;
        }
        if (viaTcp) {
            relay = new ProcessBuilder(lib + "/libudptcp.so", "-c", "127.0.0.1:" + TCP_LPORT, host + ":" + tcpPort(conf))
                    .redirectErrorStream(true).redirectOutput(new File(getFilesDir(), "tcp.log")).start();
        }
        File cfg = new File(getFilesDir(), "obf.conf");
        try (FileOutputStream o = new FileOutputStream(cfg)) { o.write(obfPart(conf, override).getBytes(StandardCharsets.UTF_8)); }
        obfuscator = new ProcessBuilder(lib + "/libwgobfuscator.so", "-c", cfg.getAbsolutePath())
                .redirectErrorStream(true).redirectOutput(new File(getFilesDir(), "obf.log")).start();
        Thread.sleep(600);
        if (!obfuscator.isAlive()) throw new IllegalStateException("обфускатор завершился, код " + obfuscator.exitValue() + " — см. «Журнал»");
        if (relay != null && !relay.isAlive()) throw new IllegalStateException("TCP-канал не запустился — см. «Журнал»");
        transport = viaWs ? "Облако" : viaTcp ? "TCP" : "UDP";
        log("transport " + transport + " -> " + (viaWs ? wsUrl(conf) : target(conf) + (viaTcp ? " tcp:" + tcpPort(conf) : "")));
    }

    private void up() {
        synchronized (LOCK) {
            try {
                String base = prefs.getString("conf", "");
                refreshSub(base);
                subIndex = 0;
                connect(sub.length() > 0 ? applying(base, sub.getJSONObject(0)) : base);
                log("up ok, mode " + prefs.getString("mode", MODE_ALL) + ", servers " + Math.max(1, sub.length()));
                notifyState(true);
                post("Подключено (" + transport + ")");
                if (sub.length() > 1 && !"cloud".equals(prefs.getString("transport", "auto"))) watchServer(base);
            } catch (Throwable e) {
                stopObfuscator();
                log("up failed: " + e);
                post("Ошибка: " + e.getMessage());
            }
        }
    }

    /** Obfuscator (+ relay) and WireGuard for one server; called again in place on failover. */
    private void connect(String conf) throws Exception {
        String mode = prefs.getString("transport", "auto");
        boolean tcpAvail = !tcpPort(conf).isEmpty();
        if ("tcp".equals(mode) && !tcpAvail && sub.length() == 0) throw new IllegalStateException("на сервере нет TCP-канала — обновите панель и заново импортируйте ссылку");
        startTransport(conf, "tcp".equals(mode) && !tcpAvail ? "udp" : "auto".equals(mode) ? "udp" : mode);
        Config c = Config.parse(new BufferedReader(new StringReader(
                wgPart(conf, prefs.getString("mode", MODE_ALL), prefs.getString("apps", ""), true))));
        backend.setState(TUNNEL, Tunnel.State.UP, c);
        curConf = conf;
        if ("auto".equals(mode) && tcpAvail) watchUdp(conf);
    }

    /** Server answered nothing for SILENCE_MS -> next subscription server. Runs while the VPN service keeps the process alive. */
    private void watchServer(String base) {
        final long gen = ++watchGen;
        new Thread(() -> {
            long lastRx = -1, since = System.currentTimeMillis();
            while (gen == watchGen) {
                try { Thread.sleep(5000); } catch (InterruptedException e) { return; }
                if (gen != watchGen || !isUp()) return;
                long rx;
                try { rx = backend.getStatistics(TUNNEL).totalRx(); } catch (Exception e) { continue; }
                long now = System.currentTimeMillis();
                if (rx != lastRx) { lastRx = rx; since = now; continue; }
                if (now - since < SILENCE_MS) continue;
                since = now;
                synchronized (LOCK) {
                    if (gen != watchGen) return;
                    try {
                        subIndex = (subIndex + 1) % sub.length();
                        org.json.JSONObject s = sub.getJSONObject(subIndex);
                        log("server silent -> " + s.optString("host") + ":" + s.optInt("port"));
                        connect(applying(base, s));
                        notifyState(true);
                        post("Сервер не отвечал — перешёл на " + target(curConf));
                    } catch (Throwable e) { log("failover: " + e); }
                }
            }
        }, "phobos-watch").start();
    }

    /** Auto: no bytes back over UDP within 15 s -> UDP is cut, move the obfuscator to TCP. */
    private void watchUdp(String conf) {
        new Thread(() -> {
            try {
                long rx0 = backend.getStatistics(TUNNEL).totalRx();
                Thread.sleep(15000);
                if (!isUp() || !"UDP".equals(transport) || !conf.equals(curConf)) return;
                if (backend.getStatistics(TUNNEL).totalRx() > rx0) return;
                log("UDP: no answer in 15 s -> switching to TCP");
                startTransport(conf, "tcp");
                post("UDP не отвечает — переключился на TCP");
            } catch (Throwable e) { log("watchUdp: " + e); }
        }).start();
    }

    private void down() {
        watchGen++;
        curConf = "";
        try { backend.setState(TUNNEL, Tunnel.State.DOWN, null); } catch (Throwable ignored) { }
        stopObfuscator();
        transport = "";
        notifyState(false);
        post("Отключено");
    }

    private static void stopObfuscator() {
        if (obfuscator != null) { obfuscator.destroy(); obfuscator = null; }
        if (relay != null) { relay.destroy(); relay = null; }
        if (wsRelay != null) { wsRelay.stop(); wsRelay = null; }
        if (v6Relay != null) { v6Relay.stop(); v6Relay = null; }
    }

    private void post(String msg) { ui.post(() -> { toast(msg); refresh(); }); }

    // ── UI ────────────────────────────────────────────────────────────────
    private void render() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bg());

        LinearLayout h = new LinearLayout(this);
        h.setBackgroundColor(0xFF1E1B4B);
        h.setPadding(dp(16), dp(14), dp(16), dp(14));
        h.addView(tv("🛡 PCA Phobos VPN", 0xFFC7D2FE, 18, true));
        root.addView(h);

        ScrollView sv = new ScrollView(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(16), dp(16), dp(24));
        sv.addView(box);

        String conf = prefs.getString("conf", "");
        LinearLayout prof = new LinearLayout(this);
        prof.setOrientation(LinearLayout.VERTICAL);
        prof.setBackground(round(card(), 14));
        prof.setPadding(dp(16), dp(14), dp(16), dp(14));
        if (conf.isEmpty()) {
            prof.addView(tv("Профиль не импортирован", text(), 16, true));
            prof.addView(tv("В панели PCA Phobos откройте клиента → 📱 Android → нажмите ссылку phobos:// "
                    + "на этом устройстве, или скопируйте её и нажмите «Импорт».", muted(), 14, false));
        } else {
            prof.addView(tv(prefs.getString("name", "Phobos"), text(), 18, true));
            server = tv("", muted(), 14, false);
            prof.addView(server);
        }
        box.addView(prof, mw(0));

        power = new Button(this);
        power.setAllCaps(false);
        power.setTextColor(Color.WHITE);
        power.setTextSize(20);
        power.setTypeface(Typeface.DEFAULT_BOLD);
        power.setOnClickListener(v -> toggle());
        LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(dp(180), dp(180));
        plp.gravity = Gravity.CENTER_HORIZONTAL;
        plp.topMargin = dp(24);
        box.addView(power, plp);

        status = tv("", text(), 16, true);
        status.setGravity(Gravity.CENTER);
        box.addView(status, mw(12));
        traffic = tv("", muted(), 14, false);
        traffic.setGravity(Gravity.CENTER);
        box.addView(traffic, mw(2));

        // split tunnelling
        LinearLayout split = new LinearLayout(this);
        split.setOrientation(LinearLayout.VERTICAL);
        split.setBackground(round(card(), 14));
        split.setPadding(dp(16), dp(14), dp(16), dp(14));
        split.addView(tv("Раздельный трафик", text(), 16, true));
        RadioGroup rg = new RadioGroup(this);
        String mode = prefs.getString("mode", MODE_ALL);
        String[][] modes = {{MODE_ALL, "Весь трафик через VPN"}, {MODE_ONLY, "Только выбранные приложения"},
                {MODE_EXCEPT, "Все, кроме выбранных приложений"}};
        for (String[] m : modes) {
            RadioButton r = new RadioButton(this);
            r.setText(m[1]);
            r.setTextColor(text());
            r.setId(View.generateViewId());
            r.setChecked(m[0].equals(mode));
            r.setOnClickListener(v -> { prefs.edit().putString("mode", m[0]).apply(); applyIfUp(); refresh(); });
            rg.addView(r);
        }
        split.addView(rg);
        android.widget.CheckBox ru = new android.widget.CheckBox(this);
        ru.setText("Российские сайты — напрямую, без VPN");
        ru.setTextColor(text());
        ru.setChecked(prefs.getBoolean("ru_direct", true));
        ru.setOnCheckedChangeListener((b, on) -> { prefs.edit().putBoolean("ru_direct", on).apply(); applyIfUp(); });
        split.addView(ru, mw(4));
        split.addView(tv("Канал до сервера", text(), 14, true), mw(8));
        RadioGroup tg = new RadioGroup(this);
        tg.setOrientation(RadioGroup.HORIZONTAL);
        String tmode = prefs.getString("transport", "auto");
        for (String[] m : new String[][]{{"auto", "Авто"}, {"udp", "UDP"}, {"tcp", "TCP"}, {"cloud", "Облако"}}) {
            RadioButton r = new RadioButton(this);
            r.setText(m[1]);
            r.setTextColor(text());
            r.setId(View.generateViewId());
            r.setChecked(m[0].equals(tmode));
            r.setOnClickListener(v -> {
                prefs.edit().putString("transport", m[0]).apply();
                if ("cloud".equals(m[0])) wsDialog(); else applyIfUp();
            });
            tg.addView(r);
        }
        split.addView(tg);
        int ns = lines(prefs.getString("my_direct", "")).size() + lines(prefs.getString("my_vpn", "")).size();
        split.addView(button("Свои сайты (" + ns + ")", 0xFF475569, v -> sitesDialog()), mw(4));
        int n = prefs.getString("apps", "").isEmpty() ? 0 : prefs.getString("apps", "").split(",").length;
        split.addView(button("Выбрать приложения (" + n + ")", 0xFF475569, v -> pickApps()), mw(8));
        split.addView(button("Свой DNS" + (myDns().isEmpty() ? "" : " (" + myDns() + ")"), 0xFF475569, v -> dnsDialog()), mw(8));
        split.addView(tv("Изменения применяются сразу. Само приложение всегда идёт напрямую — так обфускатор держит связь с сервером.",
                muted(), 12, false), mw(6));
        box.addView(split, mw(20));

        box.addView(button("Импорт ссылки phobos://", 0xFF4F46E5, v -> importDialog()), mw(16));
        box.addView(button("Импорт из файла .conf", 0xFF4F46E5, v -> startActivityForResult(
                new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 9)), mw(8));
        box.addView(button("Проверить скорость", 0xFF0EA5E9, v -> speedtest()), mw(8));
        box.addView(button("Журнал", 0xFF475569, v -> showLog()), mw(8));
        root.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
        refresh();
        ui.removeCallbacksAndMessages(null);
        ui.postDelayed(new Runnable() { public void run() { refresh(); ui.postDelayed(this, 2000); } }, 2000);
    }

    private void refresh() {
        if (power == null) return;
        boolean up = isUp();
        power.setText(up ? "Отключить" : "Подключить");
        String conf = prefs.getString("conf", "");
        if (server != null && !conf.isEmpty()) server.setText("Сервер: " + target(up && !curConf.isEmpty() ? curConf : conf));
        power.setBackground(round(up ? 0xFF16A34A : 0xFF4F46E5, 90));
        status.setText(up ? "🟢 VPN включён" + (transport.isEmpty() ? "" : " · " + transport) : "⚪ VPN выключен");
        if (up) {
            try {
                Statistics st = backend.getStatistics(TUNNEL);
                long rx = st.totalRx(), tx = st.totalTx(), now = System.currentTimeMillis();
                String speed = "";
                if (lastT > 0 && now > lastT) {
                    double s = (now - lastT) / 1000.0;
                    speed = String.format("  ·  ↓ %.1f / ↑ %.1f Мбит/с", (rx - lastRx) * 8 / s / 1e6, (tx - lastTx) * 8 / s / 1e6);
                }
                lastRx = rx; lastTx = tx; lastT = now;
                traffic.setText(String.format("Получено %.1f МБ · Отправлено %.1f МБ", rx / 1048576.0, tx / 1048576.0) + speed);
            } catch (Exception e) { traffic.setText(""); }
        } else { traffic.setText(""); lastT = 0; }
    }

    private void applyIfUp() { if (isUp()) bg.execute(() -> { down(); up(); }); }

    private void importDialog() {
        final EditText e = new EditText(this);
        e.setHint("phobos://…");
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null && cm.getPrimaryClip() != null && cm.getPrimaryClip().getItemCount() > 0) {
            CharSequence c = cm.getPrimaryClip().getItemAt(0).getText();
            if (c != null && c.toString().trim().startsWith("phobos://")) e.setText(c);
        }
        new AlertDialog.Builder(this).setTitle("Ссылка из панели").setView(e)
                .setPositiveButton("Импорт", (d, w) -> { importLink(e.getText().toString()); applyIfUp(); render(); })
                .setNegativeButton("Отмена", null).show();
    }

    private void dnsDialog() {
        final EditText e = new EditText(this);
        e.setHint("1.1.1.1, 8.8.8.8");
        e.setText(myDns());
        new AlertDialog.Builder(this).setTitle("Свой DNS").setView(e)
                .setMessage("Адреса DNS-серверов через запятую. Пусто — DNS из профиля.")
                .setPositiveButton("Сохранить", (d, w) -> {
                    String v = String.join(", ", lines(e.getText().toString()));
                    if (!v.isEmpty() && !v.matches("[0-9a-fA-F:., ]+")) { toast("DNS — только IP-адреса, например 1.1.1.1"); return; }
                    prefs.edit().putString("dns", v).apply();
                    applyIfUp();
                    render();
                })
                .setNegativeButton("Отмена", null).show();
    }

    /** Channel "Облако": address of the user's Keenetic web app (KeenDNS cloud) with wsgw behind it. */
    private void wsDialog() {
        final EditText e = new EditText(this);
        e.setHint("wss://phobos.имя.keenetic.pro/");
        e.setText(wsUrl(prefs.getString("conf", "")));
        new AlertDialog.Builder(this).setTitle("Адрес роутера (KeenDNS)").setView(e)
                .setMessage("Канал через облако Keenetic: телефон → облако KeenDNS → ваш роутер → сервер.")
                .setPositiveButton("Сохранить", (d, w) -> {
                    String u = e.getText().toString().trim();
                    if (!u.isEmpty() && !u.startsWith("wss://")) u = "wss://" + u.replaceFirst("^\\w+://", "");
                    prefs.edit().putString("ws_url", u).apply();
                    applyIfUp();
                })
                .setNegativeButton("Отмена", null).show();
    }

    /** User's own exceptions to "Russian sites directly": domains, IPs or networks, one per line. */
    private void sitesDialog() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(16), dp(8), dp(16), 0);
        l.addView(tv("Напрямую, без VPN (по одному на строку):", text(), 14, true));
        final EditText direct = new EditText(this);
        direct.setHint("mysite.ru\n1.2.3.4\n5.6.0.0/16");
        direct.setText(prefs.getString("my_direct", ""));
        direct.setMinLines(3);
        l.addView(direct);
        l.addView(tv("Всегда через VPN, даже если российский:", text(), 14, true), mw(8));
        final EditText vpn = new EditText(this);
        vpn.setHint("rutracker.org");
        vpn.setText(prefs.getString("my_vpn", ""));
        vpn.setMinLines(3);
        l.addView(vpn);
        l.addView(tv("Работает, когда включено «Российские сайты — напрямую». Сайт берётся по его текущим адресам при подключении.", muted(), 12, false), mw(6));
        ScrollView sv = new ScrollView(this);
        sv.addView(l);
        new AlertDialog.Builder(this).setTitle("Свои сайты").setView(sv)
                .setPositiveButton("Сохранить", (d, w) -> {
                    prefs.edit().putString("my_direct", direct.getText().toString().trim())
                            .putString("my_vpn", vpn.getText().toString().trim()).apply();
                    applyIfUp();
                    render();
                })
                .setNegativeButton("Отмена", null).show();
    }

    private void pickApps() {
        PackageManager pm = getPackageManager();
        Intent main = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> ris = pm.queryIntentActivities(main, 0);
        List<String[]> apps = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (ResolveInfo ri : ris) {
            String p = ri.activityInfo.packageName;
            if (p.equals(getPackageName()) || !seen.add(p)) continue;
            apps.add(new String[]{String.valueOf(ri.loadLabel(pm)), p});
        }
        Collections.sort(apps, (a, b) -> a[0].compareToIgnoreCase(b[0]));
        final Set<String> chosen = new LinkedHashSet<>(Arrays.asList(prefs.getString("apps", "").split(",")));
        chosen.remove("");
        String[] labels = new String[apps.size()];
        boolean[] checked = new boolean[apps.size()];
        for (int i = 0; i < apps.size(); i++) { labels[i] = apps.get(i)[0]; checked[i] = chosen.contains(apps.get(i)[1]); }
        new AlertDialog.Builder(this).setTitle("Приложения")
                .setMultiChoiceItems(labels, checked, (d, i, on) -> { if (on) chosen.add(apps.get(i)[1]); else chosen.remove(apps.get(i)[1]); })
                .setPositiveButton("Готово", (d, w) -> { prefs.edit().putString("apps", String.join(",", chosen)).apply(); applyIfUp(); render(); })
                .setNegativeButton("Отмена", null).show();
    }

    /** Real speed through the tunnel: the browser is inside the VPN (unless excluded by the split). */
    private void speedtest() {
        if (!isUp()) { toast("Сначала подключитесь"); return; }
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://speed.cloudflare.com/")));
    }

    private void log(String s) {
        try (FileOutputStream o = new FileOutputStream(new File(getFilesDir(), "app.log"), true)) {
            o.write((new java.util.Date() + " " + s + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) { }
    }

    private static String tail(File f, int max) {
        try {
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
                byte[] buf = new byte[8192];
                for (int n; (n = in.read(buf)) > 0; ) o.write(buf, 0, n);
            }
            String t = new String(o.toByteArray(), StandardCharsets.UTF_8);
            return t.length() > max ? t.substring(t.length() - max) : t;
        } catch (Exception e) { return ""; }
    }

    private void showLog() {
        String t = "— приложение —\n" + tail(new File(getFilesDir(), "app.log"), 3000)
                + "\n— обфускатор —\n" + tail(new File(getFilesDir(), "obf.log"), 3000)
                + "\n— TCP-канал —\n" + tail(new File(getFilesDir(), "tcp.log"), 1500)
                + "\nобфускатор запущен: " + (obfuscator != null && obfuscator.isAlive());
        TextView v = tv(t, text(), 12, false);
        v.setTextIsSelectable(true);
        v.setPadding(dp(16), dp(8), dp(16), dp(8));
        ScrollView sv = new ScrollView(this);
        sv.addView(v);
        new AlertDialog.Builder(this).setTitle("Журнал").setView(sv).setPositiveButton("OK", null).show();
    }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }
}
