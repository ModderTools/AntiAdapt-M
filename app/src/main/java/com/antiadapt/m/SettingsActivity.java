package com.antiadapt.m;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class SettingsActivity extends Activity {

    private static final int REQ_TREE = 21;

    private MainActivity.P p;
    private TextView outPathView, keyView;

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences sp = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE);
        boolean dark = MainActivity.resolveDark(this, sp.getString("theme_mode", "system"));
        setTheme(dark ? android.R.style.Theme_Material_NoActionBar
                : android.R.style.Theme_Material_Light_NoActionBar);
        super.onCreate(savedInstanceState);
        p = MainActivity.makePalette(dark);
        buildUi();
    }

    private TextView label(String s, int size, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(size);
        t.setTextColor(p.text);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private LinearLayout card(View... children) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(rounded(p.card, 14, p.border, 1));
        l.setPadding(dp(14), dp(14), dp(14), dp(14));
        for (int i = 0; i < children.length; i++) {
            if (i > 0) {
                LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(-2, -2);
                mp.topMargin = dp(10);
                l.addView(children[i], mp);
            } else {
                l.addView(children[i]);
            }
        }
        return l;
    }

    private LinearLayout section(String title, View... children) {
        LinearLayout wrap = new LinearLayout(this);
        wrap.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(-2, -2);
        wlp.topMargin = dp(22);
        wrap.setLayoutParams(wlp);
        TextView t = new TextView(this);
        t.setText(title);
        t.setTextSize(11);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextColor(p.sub);
        wrap.addView(t);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(-1, -2);
        clp.topMargin = dp(8);
        wrap.addView(card(children), clp);
        return wrap;
    }

    private Button smallBtn(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(13);
        b.setTextColor(p.btnText);
        b.setBackground(rounded(p.accent, 10, 0, 0));
        return b;
    }

    private TextView infoText(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(12);
        t.setTextColor(p.sub);
        return t;
    }

    private void buildUi() {
        ScrollView sc = new ScrollView(this);
        sc.setBackgroundColor(p.bg);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(20), dp(24), dp(20), dp(40));
        sc.addView(col, new ViewGroup.LayoutParams(-1, -2));
        setContentView(sc);

        col.addView(label("⚙  Settings", 22, true));

        SharedPreferences sp = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE);

        // ---- APPEARANCE ----
        RadioGroup rg = new RadioGroup(this);
        String mode = sp.getString("theme_mode", "system");
        String[] vals = {"dark", "light", "system"};
        String[] disp = {"Dark Mode", "Light Mode", "Follow System"};
        for (int i = 0; i < 3; i++) {
            RadioButton rb = new RadioButton(this);
            rb.setText(disp[i]);
            rb.setTextSize(14);
            rb.setTextColor(p.text);
            rb.setChecked(vals[i].equals(mode));
            final String v = vals[i];
            rb.setOnCheckedChangeListener((b, c) -> {
                if (c) {
                    sp.edit().putString("theme_mode", v).apply();
                    recreate();
                }
            });
            rg.addView(rb);
        }
        col.addView(section("APPEARANCE", rg));

        // ---- OUTPUT DIRECTORY ----
        outPathView = infoText(currentOutText());
        Button pick = smallBtn("Choose Custom Folder");
        pick.setOnClickListener(v -> {
            try {
                startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQ_TREE);
            } catch (Exception e) {
                Toast.makeText(this, "Folder picker unavailable", Toast.LENGTH_SHORT).show();
            }
        });
        Button reset = smallBtn("Reset to Default (AntiAdapt M)");
        reset.setOnClickListener(v -> {
            sp.edit().remove("out_tree_uri").apply();
            outPathView.setText(currentOutText());
            Toast.makeText(this, "Output folder reset", Toast.LENGTH_SHORT).show();
        });
        col.addView(section("OUTPUT DIRECTORY", outPathView, pick, reset));

        // ---- SIGNING KEY ----
        keyView = infoText(ApkEngine.keyInfo(this));
        Button regen = smallBtn("Regenerate Signing Key");
        regen.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Regenerate key?")
                .setMessage("Old key will be removed. Previously exported APKs stay valid; "
                        + "new exports will use the new key.")
                .setPositiveButton("Regenerate", (d, w) -> new Thread(() -> {
                    boolean ok = ApkEngine.regenerateKey(SettingsActivity.this);
                    runOnUiThread(() -> {
                        keyView.setText(ApkEngine.keyInfo(SettingsActivity.this));
                        Toast.makeText(this, ok ? "New key generated" : "Key generation failed",
                                Toast.LENGTH_SHORT).show();
                    });
                }).start())
                .setNegativeButton("Cancel", null)
                .show());
        col.addView(section("SIGNING KEY", keyView, regen));

        // ---- PROCESSING ----
        CheckBox resign = new CheckBox(this);
        resign.setText("Kill Verification & re-sign outputs");
        resign.setTextSize(14);
        resign.setTextColor(p.text);
        resign.setChecked(sp.getBoolean("resign", true));
        resign.setOnCheckedChangeListener((b, c) -> sp.edit().putBoolean("resign", c).apply());
        TextView hint = infoText("Recommended for converted files. Disable to keep the "
                + "original signature untouched.");
        col.addView(section("PROCESSING", resign, hint));

        // ---- ABOUT ----
        TextView about = infoText("AntiAdapt M v1.1\nAPK conversion & build utility.\n\n"
        + "Kill Verification replaces existing v2/v3 signature blocks and "
        + "re-signs with the managed key. Stale v1 files are ignored by "
        + "Android 7.0+. It does not modify DRM, licensing or anti-tamper "
        + "protections.");
        col.addView(section("ABOUT", about));
    }

    private String currentOutText() {
        SharedPreferences sp = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE);
        String tree = sp.getString("out_tree_uri", null);
        if (tree != null && tree.length() > 4)
            return "Custom folder selected:\n" + tree;
        return "Default:\n/storage/emulated/0/AntiAdapt M";
    }

    @Override
    protected void onActivityResult(int req, int code, Intent data) {
        super.onActivityResult(req, code, data);
        if (req == REQ_TREE && code == RESULT_OK && data != null && data.getData() != null) {
            Uri uri = data.getData();
            try {
                getContentResolver().takePersistableUriPermission(uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            } catch (Exception ignored) {}
            getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE)
                    .edit().putString("out_tree_uri", uri.toString()).apply();
            outPathView.setText(currentOutText());
        }
    }
}
