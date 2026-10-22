package com.pca.phobos;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * PCA Phobos — admin app: a list of your Phobos panels, each opens in a WebView.
 * phobos:// links are handed to PhobosWG, downloads go to the system browser.
 */
public class MainActivity extends Activity {
    private SharedPreferences prefs;
    private WebView web;
    private ProgressBar progress;
    private TextView title;
    private boolean dark;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("phobos", MODE_PRIVATE);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        JSONArray list = panels();
        String last = prefs.getString("last", "");
        if (!last.isEmpty() && b == null) openPanel(last, nameFor(last));
        else if (list.length() == 0) showEditor(null, -1);
        else showList();
    }

    // ── colors ────────────────────────────────────────────────────────────
    private int bg() { return dark ? 0xFF0F172A : 0xFFF1F5F9; }
    private int card() { return dark ? 0xFF1E293B : 0xFFFFFFFF; }
    private int text() { return dark ? 0xFFE2E8F0 : 0xFF0F172A; }
    private int muted() { return dark ? 0xFF94A3B8 : 0xFF64748B; }
    private static final int ACCENT = 0xFF4F46E5;
    private static final int HEADER = 0xFF1E1B4B;

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private GradientDrawable round(int color, int radius) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(radius));
        return g;
    }

    private Button button(String label, int color, View.OnClickListener l) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setAllCaps(false);
        btn.setTextColor(Color.WHITE);
        btn.setBackground(round(color, 10));
        btn.setOnClickListener(l);
        return btn;
    }

    private LinearLayout header(String text, View right) {
        LinearLayout h = new LinearLayout(this);
        h.setBackgroundColor(HEADER);
        h.setGravity(Gravity.CENTER_VERTICAL);
        h.setPadding(dp(16), dp(12), dp(8), dp(12));
        TextView t = new TextView(this);
        t.setText("🛡 " + text);
        t.setTextColor(0xFFC7D2FE);
        t.setTextSize(18);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setSingleLine(true);
        h.addView(t, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        if (right != null) h.addView(right);
        title = t;
        return h;
    }

    // ── storage ───────────────────────────────────────────────────────────
    private JSONArray panels() {
        try { return new JSONArray(prefs.getString("panels", "[]")); }
        catch (Exception e) { return new JSONArray(); }
    }

    private void savePanels(JSONArray a) { prefs.edit().putString("panels", a.toString()).apply(); }

    private String nameFor(String url) {
        JSONArray a = panels();
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.optJSONObject(i);
            if (o != null && url.equals(o.optString("url"))) return o.optString("name", url);
        }
        return url;
    }

    static String normalize(String raw) {
        String u = raw.trim();
        if (u.isEmpty()) return "";
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "http://" + u;
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        return u;
    }

    // ── screens ───────────────────────────────────────────────────────────
    private void showList() {
        web = null;
        prefs.edit().remove("last").apply();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bg());
        root.addView(header("PCA Phobos", null));

        ScrollView sv = new ScrollView(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(16), dp(16), dp(16));
        sv.addView(box);

        TextView hint = new TextView(this);
        hint.setText("Ваши серверы Phobos. Нажмите — откроется панель. Долгое нажатие — изменить.");
        hint.setTextColor(muted());
        hint.setPadding(0, 0, 0, dp(12));
        box.addView(hint);

        final JSONArray a = panels();
        for (int i = 0; i < a.length(); i++) {
            final int idx = i;
            final JSONObject o = a.optJSONObject(i);
            if (o == null) continue;
            LinearLayout c = new LinearLayout(this);
            c.setOrientation(LinearLayout.VERTICAL);
            c.setBackground(round(card(), 12));
            c.setPadding(dp(16), dp(14), dp(16), dp(14));
            TextView n = new TextView(this);
            n.setText(o.optString("name"));
            n.setTextColor(text());
            n.setTextSize(17);
            n.setTypeface(Typeface.DEFAULT_BOLD);
            TextView u = new TextView(this);
            u.setText(o.optString("url"));
            u.setTextColor(muted());
            c.addView(n);
            c.addView(u);
            c.setOnClickListener(v -> openPanel(o.optString("url"), o.optString("name")));
            c.setOnLongClickListener(v -> { showEditor(o, idx); return true; });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.bottomMargin = dp(10);
            box.addView(c, lp);
        }
        box.addView(button("＋ Добавить сервер", ACCENT, v -> showEditor(null, -1)));
        root.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
    }

    private void showEditor(final JSONObject existing, final int idx) {
        web = null;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bg());
        root.addView(header(existing == null ? "Новый сервер" : "Изменить сервер", null));
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(16), dp(16), dp(16));

        final EditText name = field("Название (например: Амстердам)", existing == null ? "" : existing.optString("name"));
        final EditText url = field("Адрес панели: http://IP:порт или https://домен", existing == null ? "" : existing.optString("url"));
        url.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        box.addView(label("Название"));
        box.addView(name);
        box.addView(label("Адрес панели"));
        box.addView(url);
        TextView tip = new TextView(this);
        tip.setText("Адрес и порт панели печатает установщик в конце установки (или: cat /opt/phobos-panel/.port). "
                + "Если задан домен в «Настройках» панели — используйте https://домен.");
        tip.setTextColor(muted());
        tip.setPadding(0, dp(4), 0, dp(16));
        box.addView(tip);

        box.addView(button("Сохранить и открыть", ACCENT, v -> {
            String u = normalize(url.getText().toString());
            if (u.isEmpty()) { toast("Введите адрес панели"); return; }
            String n = name.getText().toString().trim();
            if (n.isEmpty()) n = Uri.parse(u).getHost();
            try {
                JSONArray a = panels();
                JSONObject o = new JSONObject().put("name", n).put("url", u);
                if (idx >= 0) a.put(idx, o); else a.put(o);
                savePanels(a);
            } catch (Exception ignored) { }
            openPanel(u, n);
        }));
        if (existing != null) {
            Button del = button("Удалить из списка", 0xFFDC2626, v -> {
                JSONArray a = panels(), out = new JSONArray();
                for (int i = 0; i < a.length(); i++) if (i != idx) out.put(a.opt(i));
                savePanels(out);
                showList();
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = dp(10);
            box.addView(del, lp);
        }
        if (panels().length() > 0) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = dp(10);
            box.addView(button("Назад", 0xFF475569, v -> showList()), lp);
        }
        root.addView(box);
        setContentView(root);
    }

    private TextView label(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(muted());
        t.setPadding(0, dp(8), 0, dp(4));
        return t;
    }

    private EditText field(String hint, String value) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setText(value);
        e.setSingleLine(true);
        e.setTextColor(text());
        e.setHintTextColor(muted());
        e.setBackground(round(card(), 10));
        e.setPadding(dp(12), dp(12), dp(12), dp(12));
        return e;
    }

    private void openPanel(final String url, String name) {
        prefs.edit().putString("last", url).apply();
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bg());

        LinearLayout actions = new LinearLayout(this);
        TextView reload = headerAction("⟳", v -> { if (web != null) web.reload(); });
        TextView servers = headerAction("☰", v -> showList());
        actions.addView(reload);
        actions.addView(servers);
        root.addView(header(name, actions));

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        root.addView(progress, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(3)));

        web = new WebView(this);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setBuiltInZoomControls(true);
        s.setDisplayZoomControls(false);
        s.setUserAgentString(s.getUserAgentString() + " PCAPhobosApp/1.4.0");
        CookieManager.getInstance().setAcceptCookie(true);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                String scheme = u.getScheme() == null ? "" : u.getScheme();
                if (scheme.equals("http") || scheme.equals("https")) {
                    Uri base = Uri.parse(url);
                    // other sites (GitHub, Boosty, Telegram…) -> system browser / apps
                    if (u.getHost() != null && !u.getHost().equals(base.getHost())) { external(u); return true; }
                    return false;
                }
                external(u);   // phobos:// -> PhobosWG, tg:// -> Telegram
                return true;
            }

            @Override
            public void onPageFinished(WebView view, String u) {
                progress.setVisibility(View.GONE);
                CookieManager.getInstance().flush();
            }

            @Override
            public void onReceivedError(WebView view, int code, String desc, String failing) {
                if (failing != null && failing.startsWith(url)) {
                    view.loadDataWithBaseURL(null, errorPage(url, desc), "text/html", "utf-8", null);
                }
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int p) {
                progress.setVisibility(p < 100 ? View.VISIBLE : View.GONE);
                progress.setProgress(p);
            }
        });
        web.setDownloadListener((dlUrl, ua, cd, mime, len) -> external(Uri.parse(dlUrl)));
        root.addView(web, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
        web.loadUrl(url + "/");
    }

    private TextView headerAction(String s, View.OnClickListener l) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(0xFFC7D2FE);
        t.setTextSize(22);
        t.setPadding(dp(14), 0, dp(14), 0);
        t.setOnClickListener(l);
        return t;
    }

    private String errorPage(String url, String desc) {
        String bgc = dark ? "#0f172a" : "#f1f5f9", fg = dark ? "#e2e8f0" : "#0f172a";
        return "<html><body style='font-family:sans-serif;background:" + bgc + ";color:" + fg
                + ";padding:24px;text-align:center'><h2>Панель недоступна</h2><p>" + url + "</p><p style='color:#64748b'>"
                + desc + "</p><p>Проверьте адрес и порт, интернет и что сервер включён. Кнопка ⟳ — повторить.</p></body></html>";
    }

    private void external(Uri u) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, u));
        } catch (ActivityNotFoundException e) {
            if ("phobos".equals(u.getScheme())) {
                new AlertDialog.Builder(this)
                        .setTitle("Нужно приложение PhobosWG")
                        .setMessage("Ссылки phobos:// открывает приложение PhobosWG. Скачайте его на странице Android-клиента в панели (кнопка «Скачать приложение PhobosWG»).")
                        .setPositiveButton("OK", null).show();
            } else {
                toast("Нет приложения для " + u.getScheme());
            }
        }
    }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) { web.goBack(); return; }
        if (web != null && panels().length() > 0) { showList(); return; }
        super.onBackPressed();
    }
}
