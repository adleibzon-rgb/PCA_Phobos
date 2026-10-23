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
    static final String MODE_ALL = "all", MODE_ONLY = "only", MODE_EXCEPT = "except";

    static GoBackend backend;
    static Process obfuscator, relay;
    static final int TCP_LPORT = 13256;
    static volatile String transport = "";      // "UDP" | "TCP" while up
    static final Tunnel TUNNEL = new Tunnel() {
        public String getName() { return "phobos"; }
        public void onStateChange(Tunnel.State s) { }
    };

    private final ExecutorService bg = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;
    private boolean dark;
    private TextView status, traffic;
    private Button power;
    private long lastRx, lastTx, lastT;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("vpn", MODE_PRIVATE);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        if (backend == null) backend = new GoBackend(getApplicationContext());
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
    private void importLink(String link) {
        try {
            String s = link.trim();
            String name = "Phobos";
            int hash = s.indexOf('#');
            if (hash > 0) { name = Uri.decode(s.substring(hash + 1)); s = s.substring(0, hash); }
            s = s.replaceFirst("^phobos://", "").trim();
            String conf = new String(Base64.decode(s, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING), StandardCharsets.UTF_8);
            if (!conf.contains("[Interface]") || !conf.contains("[instance]")) throw new IllegalArgumentException("not a Phobos config");
            Config.parse(new BufferedReader(new StringReader(wgPart(conf, MODE_ALL, ""))));  // validate
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

    String wgPart(String conf, String mode, String apps) {
        StringBuilder sb = new StringBuilder("[Interface]\n");
        for (String ln : section(conf, "[Interface]")) {
            String k = key(ln);
            if (k.equals("excludedapplications") || k.equals("includedapplications")) continue;
            sb.append(ln).append('\n');
        }
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
        String ruBypass = prefs != null && prefs.getBoolean("ru_direct", true) ? ruBypassAllowedIps() : null;
        for (String ln : section(conf, "[Peer]")) {
            if (key(ln).equals("endpoint")) ln = "Endpoint = 127.0.0.1:" + LPORT;
            if (key(ln).equals("allowedips") && ruBypass != null) ln = "AllowedIPs = " + ruBypass;
            sb.append(ln).append('\n');
        }
        return sb.toString();
    }

    private String ruCache;

    /** Internet minus Russian networks (assets/ru_bypass.txt, generated from ipdeny). */
    private String ruBypassAllowedIps() {
        if (ruCache != null) return ruCache;
        try (BufferedReader r = new BufferedReader(new java.io.InputStreamReader(
                getAssets().open("ru_bypass.txt"), StandardCharsets.UTF_8))) {
            for (String ln; (ln = r.readLine()) != null; ) {
                if (!ln.startsWith("#") && ln.contains("/")) { ruCache = ln.trim(); break; }
            }
        } catch (Exception e) { log("ru_bypass: " + e); }
        return ruCache;
    }

    private static String getPackageNameSafe() { return "com.pca.phobos.vpn"; }

    private static final java.util.Set<String> OBF_KEYS = new java.util.HashSet<>(java.util.Arrays.asList(
            "target", "key", "masking", "idle-timeout", "max-dummy", "static-bindings", "max-clients", "target-if", "allow-clean", "in-timeout", "resolve-interval"));

    private String obfPart(String conf, boolean viaTcp) {
        StringBuilder sb = new StringBuilder("[instance]\nsource-if = 127.0.0.1\nsource-lport = " + LPORT + "\n");
        for (String ln : section(conf, "[instance]")) {
            String k = key(ln);
            if (k.equals("source-if") || k.equals("source-lport") || k.equals("verbose")) continue;
            // configs from other Phobos builds carry keys our wg-obfuscator v1.6 rejects (obfuscate-bytes…)
            if (!OBF_KEYS.contains(k)) continue;
            if (viaTcp && k.equals("target")) ln = "target = 127.0.0.1:" + TCP_LPORT;
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

    private String target(String conf) {
        for (String ln : section(conf, "[instance]")) if (key(ln).equals("target")) return val(ln);
        return "?";
    }

    // ── connect / disconnect ──────────────────────────────────────────────
    private boolean isUp() {
        try { return backend.getState(TUNNEL) == Tunnel.State.UP; } catch (Exception e) { return false; }
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
        if (req == 7 && res == RESULT_OK) bg.execute(this::up);
        else if (req == 7) toast("Без разрешения на VPN подключиться нельзя");
    }

    /** Start (or restart) obfuscator; via TCP it dials the local udptcp relay. */
    private void startTransport(String conf, boolean viaTcp) throws Exception {
        stopObfuscator();
        String lib = getApplicationInfo().nativeLibraryDir;
        if (viaTcp) {
            String host = target(conf).replaceAll(":\\d+$", "");
            relay = new ProcessBuilder(lib + "/libudptcp.so", "-c", "127.0.0.1:" + TCP_LPORT, host + ":" + tcpPort(conf))
                    .redirectErrorStream(true).redirectOutput(new File(getFilesDir(), "tcp.log")).start();
        }
        File cfg = new File(getFilesDir(), "obf.conf");
        try (FileOutputStream o = new FileOutputStream(cfg)) { o.write(obfPart(conf, viaTcp).getBytes(StandardCharsets.UTF_8)); }
        obfuscator = new ProcessBuilder(lib + "/libwgobfuscator.so", "-c", cfg.getAbsolutePath())
                .redirectErrorStream(true).redirectOutput(new File(getFilesDir(), "obf.log")).start();
        Thread.sleep(600);
        if (!obfuscator.isAlive()) throw new IllegalStateException("обфускатор завершился, код " + obfuscator.exitValue() + " — см. «Журнал»");
        if (relay != null && !relay.isAlive()) throw new IllegalStateException("TCP-канал не запустился — см. «Журнал»");
        transport = viaTcp ? "TCP" : "UDP";
        log("transport " + transport + " -> " + target(conf) + (viaTcp ? " tcp:" + tcpPort(conf) : ""));
    }

    private void up() {
        try {
            String conf = prefs.getString("conf", "");
            String mode = prefs.getString("transport", "auto");
            boolean tcpAvail = !tcpPort(conf).isEmpty();
            if ("tcp".equals(mode) && !tcpAvail) throw new IllegalStateException("на сервере нет TCP-канала — обновите панель и заново импортируйте ссылку");
            startTransport(conf, "tcp".equals(mode));
            Config c = Config.parse(new BufferedReader(new StringReader(
                    wgPart(conf, prefs.getString("mode", MODE_ALL), prefs.getString("apps", "")))));
            backend.setState(TUNNEL, Tunnel.State.UP, c);
            log("up ok, mode " + prefs.getString("mode", MODE_ALL) + ", transport " + mode);
            post("Подключено (" + transport + ")");
            if ("auto".equals(mode) && tcpAvail) watchUdp(conf);
        } catch (Throwable e) {
            stopObfuscator();
            log("up failed: " + e);
            post("Ошибка: " + e.getMessage());
        }
    }

    /** Auto: no bytes back over UDP within 15 s -> UDP is cut, move the obfuscator to TCP. */
    private void watchUdp(String conf) {
        new Thread(() -> {
            try {
                Thread.sleep(15000);
                if (!isUp() || !"UDP".equals(transport)) return;
                if (backend.getStatistics(TUNNEL).totalRx() > 0) return;
                log("UDP: no answer in 15 s -> switching to TCP");
                startTransport(conf, true);
                post("UDP не отвечает — переключился на TCP");
            } catch (Throwable e) { log("watchUdp: " + e); }
        }).start();
    }

    private void down() {
        try { backend.setState(TUNNEL, Tunnel.State.DOWN, null); } catch (Throwable ignored) { }
        stopObfuscator();
        transport = "";
        post("Отключено");
    }

    private static void stopObfuscator() {
        if (obfuscator != null) { obfuscator.destroy(); obfuscator = null; }
        if (relay != null) { relay.destroy(); relay = null; }
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
            prof.addView(tv("Сервер: " + target(conf), muted(), 14, false));
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
        for (String[] m : new String[][]{{"auto", "Авто"}, {"udp", "UDP"}, {"tcp", "TCP"}}) {
            RadioButton r = new RadioButton(this);
            r.setText(m[1]);
            r.setTextColor(text());
            r.setId(View.generateViewId());
            r.setChecked(m[0].equals(tmode));
            r.setOnClickListener(v -> { prefs.edit().putString("transport", m[0]).apply(); applyIfUp(); });
            tg.addView(r);
        }
        split.addView(tg);
        int n = prefs.getString("apps", "").isEmpty() ? 0 : prefs.getString("apps", "").split(",").length;
        split.addView(button("Выбрать приложения (" + n + ")", 0xFF475569, v -> pickApps()), mw(8));
        split.addView(tv("Изменения применяются сразу. Само приложение всегда идёт напрямую — так обфускатор держит связь с сервером.",
                muted(), 12, false), mw(6));
        box.addView(split, mw(20));

        box.addView(button("Импорт ссылки phobos://", 0xFF4F46E5, v -> importDialog()), mw(16));
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
