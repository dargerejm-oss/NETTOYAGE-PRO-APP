package com.jmdargere.nettoyage;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.window.OnBackInvokedDispatcher;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * NETTOYAGE PRO : l'outil NETTOYAGE ANDROID PRO dans une vraie appli, sans Termux.
 * Python (Chaquopy) lance le serveur local, la page s'affiche dans un WebView.
 */
public class MainActivity extends Activity {

    static final int PORT = 8877;
    static final String URL = "http://127.0.0.1:" + PORT + "/?app=1";

    private WebView web;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean starting = false;
    private volatile boolean loaded = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        web = new WebView(this);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#232a31"));
        root.addView(web, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);
        web.setBackgroundColor(Color.parseColor("#232a31"));

        if (Build.VERSION.SDK_INT >= 30) {
            root.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
                return WindowInsets.CONSUMED;
            });
        }
        if (Build.VERSION.SDK_INT >= 33) {
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT, () -> {
                        if (web.canGoBack()) {
                            web.goBack();
                        } else {
                            finish();
                        }
                    });
        }

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                String u = r.getUrl().toString();
                if (u.startsWith("retry://")) {
                    loaded = false;
                    begin();
                    return true;
                }
                if (u.startsWith("access://")) {
                    askAccess();
                    return true;
                }
                return false;
            }

            @Override
            public void onReceivedError(WebView v, WebResourceRequest r, WebResourceError e) {
                if (r.isForMainFrame() && r.getUrl().toString().startsWith("http")) {
                    show(page("La page ne répond pas",
                            "<p>Le moteur de nettoyage est arrêté.</p>"
                                    + "<a class='b' href='retry://go'>RÉESSAYER</a>"));
                }
            }
        });
        show(page("🧹 NETTOYAGE PRO", "<p>Démarrage…</p>"));
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!loaded) {
            begin();
        }
    }

    // ----------------------------------------------------------- autorisation
    private boolean hasAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        }
        return checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void askAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                Intent i = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName()));
                startActivity(i);
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        } else {
            requestPermissions(new String[]{
                    android.Manifest.permission.READ_EXTERNAL_STORAGE,
                    android.Manifest.permission.WRITE_EXTERNAL_STORAGE}, 1);
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] res) {
        super.onRequestPermissionsResult(code, perms, res);
        begin();
    }

    // -------------------------------------------------------------- demarrage
    private void begin() {
        if (loaded || starting) {
            return;
        }
        if (!hasAccess()) {
            show(page("🧹 NETTOYAGE PRO",
                    "<p>Pour analyser et nettoyer le stockage, l'appli a besoin de "
                            + "l'autorisation <b>« Accès à tous les fichiers »</b>.</p>"
                            + "<p>Touche le bouton, puis active l'interrupteur "
                            + "<b>NETTOYAGE PRO</b> et reviens ici.</p>"
                            + "<a class='b' href='access://go'>AUTORISER L'ACCÈS</a>"));
            return;
        }
        starting = true;
        show(page("🧹 NETTOYAGE PRO", "<p>Démarrage du moteur…</p>"));
        new Thread(() -> {
            try {
                if (!up()) {
                    File web = new File(getFilesDir(), "web");
                    web.mkdirs();
                    copyAsset("index.html", new File(web, "index.html"));
                    if (!Python.isStarted()) {
                        Python.start(new AndroidPlatform(this));
                    }
                    PyObject mod = Python.getInstance().getModule("server");
                    String root = Environment.getExternalStorageDirectory().getAbsolutePath();
                    mod.callAttr("start", root, PORT, web.getAbsolutePath());
                }
                for (int i = 0; i < 60; i++) {
                    if (up()) {
                        loaded = true;
                        ui.post(() -> web.loadUrl(URL));
                        return;
                    }
                    Thread.sleep(500);
                }
                ui.post(() -> show(page("Le moteur ne démarre pas",
                        "<a class='b' href='retry://go'>RÉESSAYER</a>")));
            } catch (Throwable e) {
                final String msg = String.valueOf(e);
                ui.post(() -> show(page("Erreur au démarrage",
                        "<p><code>" + msg.replace("<", "&lt;") + "</code></p>"
                                + "<a class='b' href='retry://go'>RÉESSAYER</a>")));
            } finally {
                starting = false;
            }
        }).start();
    }

    private boolean up() {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", PORT), 300);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            try {
                s.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void copyAsset(String name, File dest) throws Exception {
        try (InputStream in = getAssets().open(name);
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
    }

    // ------------------------------------------------------------------ pages
    private void show(String html) {
        web.loadDataWithBaseURL(null, html, "text/html", "utf-8", null);
    }

    private String page(String title, String body) {
        return "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
                + "<style>body{margin:0;padding:24px;background:#232a31;color:#fff;"
                + "font:18px system-ui,sans-serif}h1{font-size:26px}"
                + "code{background:#14181c;color:#cfe3d4;padding:2px 6px;border-radius:6px;font-size:14px;"
                + "word-break:break-all}.b{display:block;text-align:center;background:#2e9e44;color:#fff;"
                + "text-decoration:none;font-weight:800;border-radius:16px;padding:20px;margin-top:20px}"
                + "</style></head><body><h1>" + title + "</h1>" + body + "</body></html>";
    }

    @Override
    public void onBackPressed() {
        if (web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
