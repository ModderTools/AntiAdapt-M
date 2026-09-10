package com.antiadapt.m;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.database.Cursor;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.animation.ObjectAnimator;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    public static final String PREFS = "aam_prefs";
    private static final int REQ_FILE = 11;

    public static class P {
        public boolean isDark;
        public int bg, text, sub, card, border, accent, btnText;
        public int gradTop, gradBottom, glow, ripple;
    }

    private TextView statusView, logView;
    private TextView[] stageViews = new TextView[ApkEngine.STAGES.length];
    private TextView[] dotViews = new TextView[ApkEngine.STAGES.length];
    private ScrollView logScroll;
    private ProgressBar progress;
    private Button fileBtn, appBtn, cancelBtn;
    private View processCard, logCard;

    private P p = new P();
    private volatile boolean cancelled = false;
    private volatile boolean busy = false;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private Runnable blinker;
    private ObjectAnimator progressAnim;

    public static boolean resolveDark(Activity a, String mode) {
        if ("dark".equals(mode)) return true;
        if ("light".equals(mode)) return false;
        int m = a.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return m == Configuration.UI_MODE_NIGHT_YES;
    }

    public static P makePalette(boolean dark) {
        P p = new P();
        p.isDark = dark;
        if (dark) {
            p.bg = 0xFF0B1F33; p.text = 0xFFEAF2FB; p.sub = 0xFF8FA9C4;
            p.card = 0xFF0F2A47; p.border = 0xFF1D4066;
            p.accent = 0xFFFFF7E6; p.btnText = 0xFF102E4A;
            p.gradTop = 0xFF0C2340; p.gradBottom = 0xFF050D18;
            p.glow = 0xFF63D1FF; p.ripple = 0x40FFFFFF;
        } else {
            p.bg = 0xFFFFF7E6; p.text = 0xFF102E4A; p.sub = 0xFF5A7186;
            p.card = 0xFFFFFCF2; p.border = 0xFFE3D5B8;
            p.accent = 0xFF102E4A; p.btnText = 0xFFFFF7E6;
            p.gradTop = 0xFFFFF7E6; p.gradBottom = 0xFFF0E4C9;
            p.glow = 0xFF102E4A; p.ripple = 0x33000000;
        }
        return p;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        boolean dark = resolveDark(this, sp.getString("theme_mode", "system"));
        setTheme(dark ? android.R.style.Theme_Material_NoActionBar
                : android.R.style.Theme_Material_Light_NoActionBar);
        super.onCreate(savedInstanceState);
        p = makePalette(dark);
        buildUi();
        ensurePermissions();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ensureOutputFolder();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopBlink();
    }

    // ================================================================
    // UI
    // ================================================================

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private GradientDrawable rounded(int color, int radiusDp, int strokeColor, int strokeDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(radiusDp));
        if (strokeDp > 0) g.setStroke(dp(strokeDp), strokeColor);
        return g;
    }

    private Drawable rip(GradientDrawable content) {
        return new RippleDrawable(ColorStateList.valueOf(p.ripple), content, content);
    }

    private LinearLayout.LayoutParams lp(int w, int h, int topMargin) {
        LinearLayout.LayoutParams l = new LinearLayout.LayoutParams(w, h);
        l.topMargin = dp(topMargin);
        return l;
    }

    private void animateIn(View v, long delay) {
        v.setAlpha(0f);
        v.setTranslationY(dp(30));
        v.animate().alpha(1f).translationY(0f).setDuration(430)
                .setStartDelay(delay)
                .setInterpolator(new DecelerateInterpolator(1.5f))
                .start();
    }

    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        root.setBackground(new GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{p.gradTop, p.gradBottom}));

        ScrollView scroller = new ScrollView(this);
        scroller.setFillViewport(true);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(22), dp(28), dp(22), dp(110));
        scroller.addView(col, new ViewGroup.LayoutParams(-1, -2));
        root.addView(scroller, new FrameLayout.LayoutParams(-1, -1));

        TextView title = new TextView(this);
        title.setText("AntiAdapt M");
        title.setTextSize(27);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(p.text);
        title.setLetterSpacing(0.04f);
        col.addView(title);

        TextView sub = new TextView(this);
        sub.setText("APK · XAPK · AAB · ZIP  →  Installable APK");
        sub.setTextSize(13);
        sub.setTextColor(p.sub);
        col.addView(sub, lp(-2, -2, 3));

        // ---- process card ----
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(rip(rounded(p.card, 18, p.border, 1)));
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        col.addView(card, lp(-1, -2, dp(22)));
        processCard = card;

        TextView procLabel = new TextView(this);
        procLabel.setText("PROCESS");
        procLabel.setTextSize(11);
        procLabel.setTypeface(Typeface.DEFAULT_BOLD);
        procLabel.setLetterSpacing(0.1f);
        procLabel.setTextColor(p.sub);
        card.addView(procLabel);

        for (int i = 0; i < ApkEngine.STAGES.length; i++) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            TextView dot = new TextView(this);
            dot.setText("○");
            dot.setTextSize(13);
            dot.setTextColor(p.sub);
            dot.setPadding(0, dp(4), dp(9), dp(4));
            TextView name = new TextView(this);
            name.setText(ApkEngine.STAGES[i]);
            name.setTextSize(13);
            name.setTextColor(p.sub);
            row.addView(dot);
            row.addView(name);
            card.addView(row);
            dotViews[i] = dot;
            stageViews[i] = name;
        }

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.setProgressTintList(ColorStateList.valueOf(p.glow));
        progress.setProgressBackgroundTintList(ColorStateList.valueOf(p.border));
        card.addView(progress, lp(-1, -2, dp(14)));

        statusView = new TextView(this);
        statusView.setText("Ready");
        statusView.setTextSize(12);
        statusView.setTextColor(p.sub);
        card.addView(statusView, lp(-2, -2, dp(6)));

        // ---- buttons ----
        fileBtn = bigButton("Select File from Storage");
        fileBtn.setOnClickListener(v -> pickFile());
        col.addView(fileBtn, lp(-1, dp(56), dp(22)));

        appBtn = bigButton("Select App from Installed");
        appBtn.setOnClickListener(v -> pickInstalledApp());
        col.addView(appBtn, lp(-1, dp(56), dp(12)));

        cancelBtn = bigButton("Cancel Processing");
        cancelBtn.setOnClickListener(v -> { cancelled = true; appendLog("Cancelling..."); });
        cancelBtn.setVisibility(View.GONE);
        col.addView(cancelBtn, lp(-1, dp(48), dp(12)));

        // ---- logs ----
        TextView logLabel = new TextView(this);
        logLabel.setText("LOGS");
        logLabel.setTextSize(11);
        logLabel.setTypeface(Typeface.DEFAULT_BOLD);
        logLabel.setLetterSpacing(0.1f);
        logLabel.setTextColor(p.sub);
        col.addView(logLabel, lp(-2, -2, dp(24)));

        logScroll = new ScrollView(this);
        logScroll.setBackground(rounded(p.card, 12, p.border, 1));
        logView = new TextView(this);
        logView.setTextSize(11);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextColor(p.sub);
        logView.setPadding(dp(12), dp(10), dp(12), dp(10));
        logScroll.addView(logView, new ViewGroup.LayoutParams(-1, -2));
        col.addView(logScroll, lp(-1, dp(190), dp(8)));
        logCard = logScroll;

        // ---- FAB ----
        FrameLayout fab = new FrameLayout(this);
        fab.setBackground(rip(rounded(p.accent, 28, 0, 0)));
        fab.setElevation(dp(7));
        TextView gear = new TextView(this);
        gear.setText("⚙");
        gear.setTextSize(22);
        gear.setTextColor(p.btnText);
        gear.setGravity(Gravity.CENTER);
        fab.addView(gear, new FrameLayout.LayoutParams(-1, -1));
        FrameLayout.LayoutParams flp =
                new FrameLayout.LayoutParams(dp(56), dp(56), Gravity.BOTTOM | Gravity.END);
        flp.rightMargin = dp(20);
        flp.bottomMargin = dp(24);
        root.addView(fab, flp);
        fab.setOnClickListener(v -> {
            fab.animate().rotation(fab.getRotation() + 180).setDuration(350).start();
            startActivity(new Intent(this, SettingsActivity.class));
        });
        fab.setScaleX(0f); fab.setScaleY(0f);
        fab.animate().scaleX(1f).scaleY(1f).setDuration(520).setStartDelay(620)
                .setInterpolator(new OvershootInterpolator(2.4f)).start();

        setContentView(root);

        animateIn(title, 40);
        animateIn(sub, 100);
        animateIn(processCard, 170);
        animateIn(fileBtn, 250);
        animateIn(appBtn, 320);
        animateIn(cancelBtn, 380);
        animateIn(logLabel, 430);
        animateIn(logCard, 470);
    }

    private Button bigButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(15);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setTextColor(p.btnText);
        b.setBackground(rip(rounded(p.accent, 14, 0, 0)));
        b.setGravity(Gravity.CENTER);
        b.setElevation(dp(2));
        return b;
    }

    // ================================================================
    // PERMISSIONS + OUTPUT FOLDER
    // ================================================================

    private void ensurePermissions() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                appendLog("All-files storage access is required to save APKs.");
                try {
                    startActivity(new Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:" + getPackageName())));
                } catch (Exception e) {
                    try {
                        startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                    } catch (Exception ignored) {}
                }
            }
        } else if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission("android.permission.READ_EXTERNAL_STORAGE")
                    != PackageManager.PERMISSION_GRANTED
                    || checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE")
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{
                        "android.permission.READ_EXTERNAL_STORAGE",
                        "android.permission.WRITE_EXTERNAL_STORAGE"}, 9);
            }
        }
    }

    private boolean hasStorageAccess() {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        if (Build.VERSION.SDK_INT >= 23)
            return checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE")
                    == PackageManager.PERMISSION_GRANTED;
        return true;
    }

    private void ensureOutputFolder() {
        new Thread(() -> {
            try {
                if (!hasStorageAccess()) return;
                File d = new File(Environment.getExternalStorageDirectory(), "AntiAdapt M");
                boolean createdNow = !d.exists();
                if (createdNow) d.mkdirs();
                if (d.isDirectory()) {
                    SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
                    if (!sp.getBoolean("folder_created", false) || createdNow) {
                        sp.edit().putBoolean("folder_created", true).apply();
                        appendLog("Output folder ready: " + d.getAbsolutePath());
                    }
                }
            } catch (Exception e) {
                appendLog("Folder creation failed: " + e.getMessage());
            }
        }).start();
    }

    // ================================================================
    // FILE SELECTION
    // ================================================================

    private void pickFile() {
        if (busy) return;
        try {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                    "application/octet-stream",
                    "application/vnd.android.package-archive",
                    "application/zip",
                    "application/x-zip-compressed",
                    "application/java-archive"});
            startActivityForResult(i, REQ_FILE);
        } catch (Exception e) {
            Toast.makeText(this, "File picker unavailable: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int req, int code, Intent data) {
        super.onActivityResult(req, code, data);
        if (code != RESULT_OK || data == null || data.getData() == null) return;
        if (req == REQ_FILE) handlePickedFile(data.getData());
    }

    private void handlePickedFile(Uri uri) {
        try {
            String name = displayName(uri);
            if (name == null) name = "input.bin";
            File in = new File(ApkEngine.cacheDir(this),
                    "in_" + System.currentTimeMillis() + "_"
                            + name.replaceAll("[^A-Za-z0-9._-]", "_"));
            ApkEngine.copyStream(getContentResolver().openInputStream(uri),
                    new FileOutputStream(in));
            String low = name.toLowerCase(Locale.US);
            final File f = in;
            final String n = name;
            boolean resign = getSharedPreferences(PREFS, MODE_PRIVATE)
                    .getBoolean("resign", true);

            if (low.endsWith(".apk")) {
                startWork(() -> ApkEngine.processApkFile(this, f, n, resign, cbRef()));
            } else if (low.endsWith(".xapk") || low.endsWith(".apks") || low.endsWith(".zip")) {
                startWork(() -> ApkEngine.processArchive(this, f, n, resign, cbRef()));
            } else if (low.endsWith(".aab")) {
                startWork(() -> ApkEngine.processAab(this, f, n, cbRef()));
            } else if (isZip(in)) {
                startWork(() -> ApkEngine.processArchive(this, f, n, resign, cbRef()));
            } else {
                in.delete();
                showError("Unsupported format",
                        "Please select an APK, XAPK, APKS, AAB or ZIP file.");
            }
        } catch (Exception e) {
            showError("Could not read file",
                    e.getMessage() == null ? "Unknown error" : e.getMessage());
        }
    }

    private String displayName(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) return c.getString(idx);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) c.close();
        }
        String s = uri.getLastPathSegment();
        return s == null ? null : s.substring(s.lastIndexOf('/') + 1);
    }

    private boolean isZip(File f) {
        InputStream in = null;
        try {
            in = new FileInputStream(f);
            return in.read() == 'P' && in.read() == 'K';
        } catch (Exception e) {
            return false;
        } finally {
            try { if (in != null) in.close(); } catch (Exception ignored) {}
        }
    }

    // ================================================================
    // INSTALLED APP SELECTION (fast: instant dialog + lazy icons)
    // ================================================================

    private AlertDialog loadingDlg;

    private void showLoading(String msg) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER);
        box.setPadding(dp(34), dp(30), dp(34), dp(30));
        ProgressBar pb = new ProgressBar(this);
        box.addView(pb, new LinearLayout.LayoutParams(dp(42), dp(42)));
        TextView t = new TextView(this);
        t.setText(msg);
        t.setTextSize(13);
        t.setTextColor(p.sub);
        t.setGravity(Gravity.CENTER);
        box.addView(t, lp(-2, -2, 12));
        loadingDlg = new AlertDialog.Builder(this).setView(box).setCancelable(false).create();
        loadingDlg.show();
    }

    private void pickInstalledApp() {
        if (busy) return;
        showLoading("Loading apps...");
        final PackageManager pm = getPackageManager();
        new Thread(() -> {
            try {
                List<ApplicationInfo> all = pm.getInstalledApplications(0);
                List<Object[]> user = new ArrayList<>();
                List<Object[]> sys = new ArrayList<>();
                Collator col = Collator.getInstance();
                for (ApplicationInfo ai : all) {
                    if (ai.sourceDir == null) continue;
                    CharSequence l = pm.getApplicationLabel(ai);
                    String label = l == null ? ai.packageName : l.toString();
                    if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) sys.add(new Object[]{label, ai});
                    else user.add(new Object[]{label, ai});
                }
                Collections.sort(user, (a, b) -> col.compare((String) a[0], (String) b[0]));
                Collections.sort(sys, (a, b) -> col.compare((String) a[0], (String) b[0]));
                List<ApplicationInfo> merged = new ArrayList<>();
                for (Object[] o : user) merged.add((ApplicationInfo) o[1]);
                for (Object[] o : sys) merged.add((ApplicationInfo) o[1]);
                final int userCount = user.size();
                runOnUiThread(() -> {
                    if (loadingDlg != null) loadingDlg.dismiss();
                    appendLog(userCount + " user apps, "
                            + (merged.size() - userCount) + " system apps (blue).");
                    showAppDialog(merged, userCount);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (loadingDlg != null) loadingDlg.dismiss();
                    appendLog("Could not list apps: " + e.getMessage());
                });
            }
        }).start();
    }

    private void showAppDialog(final List<ApplicationInfo> apps, int userCount) {
        ListView lv = new ListView(this);
        lv.setDivider(null);
        lv.setPadding(dp(4), dp(4), dp(4), dp(4));
        lv.setAdapter(new AppListAdapter(apps));

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        TextView hint = new TextView(this);
        hint.setText(userCount + " user apps · System apps in blue");
        hint.setTextSize(11);
        hint.setTextColor(p.sub);
        hint.setPadding(dp(18), dp(10), dp(18), dp(4));
        box.addView(hint);
        box.addView(lv, new LinearLayout.LayoutParams(-1, -1));

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle("Select App (" + apps.size() + ")")
                .setView(box)
                .setNegativeButton("Cancel", null)
                .create();
        lv.setOnItemClickListener((parent, v, pos, id) -> {
            dlg.dismiss();
            processInstalled(apps.get(pos));
        });
        dlg.show();
        try {
            WindowManager.LayoutParams wlp = new WindowManager.LayoutParams();
            wlp.copyFrom(dlg.getWindow().getAttributes());
            wlp.width = (int) (getResources().getDisplayMetrics().widthPixels * 0.92);
            wlp.height = (int) (getResources().getDisplayMetrics().heightPixels * 0.78);
            dlg.getWindow().setAttributes(wlp);
        } catch (Exception ignored) {}
    }

    private class AppListAdapter extends BaseAdapter {
        private final List<ApplicationInfo> items;
        private final PackageManager pm;
        private final HashMap<String, Drawable> iconCache = new HashMap<>();

        AppListAdapter(List<ApplicationInfo> items) {
            this.items = items;
            this.pm = getPackageManager();
        }

        @Override public int getCount() { return items.size(); }
        @Override public Object getItem(int position) { return items.get(position); }
        @Override public long getItemId(int position) { return position; }

        @Override public View getView(int position, View convertView, ViewGroup parent) {
            VH h;
            if (convertView == null) {
                h = new VH();
                LinearLayout row = new LinearLayout(MainActivity.this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(dp(14), dp(9), dp(14), dp(9));

                h.icon = new ImageView(MainActivity.this);
                LinearLayout.LayoutParams ilp =
                        new LinearLayout.LayoutParams(dp(42), dp(42));
                ilp.rightMargin = dp(12);
                h.icon.setLayoutParams(ilp);
                h.icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
                row.addView(h.icon);

                LinearLayout col2 = new LinearLayout(MainActivity.this);
                col2.setOrientation(LinearLayout.VERTICAL);
                h.name = new TextView(MainActivity.this);
                h.name.setTextSize(15);
                h.name.setTypeface(Typeface.DEFAULT_BOLD);
                h.name.setMaxLines(1);
                col2.addView(h.name);
                h.pkg = new TextView(MainActivity.this);
                h.pkg.setTextSize(11);
                h.pkg.setMaxLines(1);
                col2.addView(h.pkg, lp(-1, -2, 2));

                row.addView(col2, new LinearLayout.LayoutParams(-1, -2));
                convertView = row;
                row.setTag(h);
            } else {
                h = (VH) convertView.getTag();
            }

            ApplicationInfo ai = items.get(position);
            boolean system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            Drawable ic = iconCache.get(ai.packageName);
            if (ic == null) {
                try { ic = pm.getApplicationIcon(ai); }
                catch (Exception e) {
                    ic = getResources().getDrawable(android.R.drawable.sym_def_app_icon);
                }
                iconCache.put(ai.packageName, ic);
            }
            h.icon.setImageDrawable(ic);
            CharSequence label = null;
            try { label = pm.getApplicationLabel(ai); } catch (Exception ignored) {}
            h.name.setText(label == null ? ai.packageName : label.toString());
            h.pkg.setText(ai.packageName);

            int blue = p.isDark ? 0xFF6FC8FF : 0xFF1565C0;
            h.name.setTextColor(system ? blue : p.text);
            h.pkg.setTextColor(p.sub);
            return convertView;
        }

        class VH { ImageView icon; TextView name; TextView pkg; }
    }

    private void processInstalled(ApplicationInfo ai) {
        CharSequence l = getPackageManager().getApplicationLabel(ai);
        final String label = l == null ? ai.packageName : l.toString();
        startWork(() -> {
            List<File> parts = new ArrayList<>();
            parts.add(cacheCopy(new File(ai.sourceDir), label + "_base.apk"));
            if (ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0) {
                int i = 0;
                for (String s : ai.splitSourceDirs) {
                    File sf = new File(s);
                    parts.add(cacheCopy(sf, label + "_split" + (i++) + "_" + sf.getName()));
                }
                appendLog("Split APKs detected: " + i);
            }
            boolean resign = getSharedPreferences(PREFS, MODE_PRIVATE)
                    .getBoolean("resign", true);
            return ApkEngine.processInstalledApk(this, parts, label, resign, cbRef());
        });
    }

    private File cacheCopy(File src, String name) throws Exception {
        File dst = new File(ApkEngine.cacheDir(this),
                "in_" + System.currentTimeMillis() + "_"
                        + name.replaceAll("[^A-Za-z0-9._-]", "_"));
        ApkEngine.copyStream(new FileInputStream(src), new FileOutputStream(dst));
        return dst;
    }

    // ================================================================
    // WORK ORCHESTRATION
    // ================================================================

    private interface Work { String run() throws Exception; }

    private ApkEngine.Callback cbRef() { return cb; }

    private final ApkEngine.Callback cb = new ApkEngine.Callback() {
        @Override public void onStage(final int i) { runOnUiThread(() -> setStage(i)); }
        @Override public void onLog(final String s) { runOnUiThread(() -> appendLog(s)); }
        @Override public void onProgress(final int v) { runOnUiThread(() -> animateProgress(v)); }
        @Override public boolean isCancelled() { return cancelled; }
    };

    private void startWork(final Work w) {
        if (busy) return;
        busy = true;
        cancelled = false;
        fileBtn.setEnabled(false); appBtn.setEnabled(false);
        fileBtn.setAlpha(0.5f); appBtn.setAlpha(0.5f);
        cancelBtn.setVisibility(View.VISIBLE);
        setStage(0);
        progress.setProgress(0);
        appendLog("----------------------------");
        ApkEngine.cleanupCache(this);

        new Thread(() -> {
            try {
                String out = w.run();
                setStage(ApkEngine.ST_DONE);
                animateProgress(100);
                runOnUiThread(() -> new AlertDialog.Builder(MainActivity.this)
                        .setTitle("✅ Completed")
                        .setMessage("Processed successfully.\n\nSaved to:\n" + out)
                        .setPositiveButton("OK", null)
                        .show());
            } catch (Exception e) {
                String msg = e.getMessage() == null ? e.toString() : e.getMessage();
                if ("CANCELLED".equals(msg)) {
                    appendLog("Processing cancelled by user.");
                    setStage(-1);
                    animateProgress(0);
                } else {
                    appendLog("ERROR: " + msg);
                    runOnUiThread(() -> showError("Processing Failed", msg));
                }
            } finally {
                runOnUiThread(() -> {
                    busy = false;
                    fileBtn.setEnabled(true); appBtn.setEnabled(true);
                    fileBtn.setAlpha(1f); appBtn.setAlpha(1f);
                    cancelBtn.setVisibility(View.GONE);
                });
            }
        }).start();
    }

    // ================================================================
    // STATUS / LOG / ANIMATION
    // ================================================================

    private void setStage(int idx) {
        stopBlink();
        for (int i = 0; i < stageViews.length; i++) {
            TextView dot = dotViews[i], name = stageViews[i];
            if (idx >= 0 && i < idx) {
                dot.setText("✓"); dot.setTextColor(p.glow);
                name.setTextColor(p.glow); name.setTypeface(Typeface.DEFAULT_BOLD);
            } else if (i == idx) {
                dot.setText("●"); dot.setTextColor(p.glow);
                name.setTextColor(p.glow); name.setTypeface(Typeface.DEFAULT_BOLD);
            } else {
                dot.setText("○"); dot.setTextColor(p.sub);
                name.setTextColor(p.sub); name.setTypeface(Typeface.DEFAULT);
            }
        }
        if (idx >= 0 && idx < ApkEngine.ST_DONE) startBlink(dotViews[idx]);
        statusView.setText(idx < 0 ? "Ready"
                : (idx == ApkEngine.ST_DONE ? "Completed ✔"
                : "Processing: " + ApkEngine.STAGES[idx] + "..."));
    }

    private void startBlink(final TextView dot) {
        blinker = new Runnable() {
            int state = 0;
            @Override public void run() {
                state ^= 1;
                dot.setAlpha(state == 0 ? 1f : 0.25f);
                ui.postDelayed(this, 420);
            }
        };
        ui.post(blinker);
    }

    private void stopBlink() {
        if (blinker != null) { ui.removeCallbacks(blinker); blinker = null; }
        for (TextView d : dotViews) d.setAlpha(1f);
    }

    private void animateProgress(int to) {
        if (progressAnim != null) progressAnim.cancel();
        progressAnim = ObjectAnimator.ofInt(progress, "progress", progress.getProgress(), to);
        progressAnim.setDuration(320);
        progressAnim.setInterpolator(new DecelerateInterpolator());
        progressAnim.start();
    }

    private void appendLog(String s) {
        runOnUiThread(() -> {
            logView.append("› " + s + "\n");
            if (logView.length() > 12000)
                logView.setText(logView.getText()
                        .subSequence(logView.length() - 8000, logView.length()));
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void showError(String t, String m) {
        new AlertDialog.Builder(this).setTitle(t).setMessage(m)
                .setPositiveButton("OK", null).show();
    }
}
