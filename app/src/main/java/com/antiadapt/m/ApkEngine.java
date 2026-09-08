package com.antiadapt.m;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Environment;

import androidx.documentfile.provider.DocumentFile;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class ApkEngine {

    public interface Callback {
        void onStage(int stageIndex);
        void onLog(String line);
        void onProgress(int percent);
        boolean isCancelled();
    }

    public static final String[] STAGES = {
            "Analyzing", "Converting / Building", "Kill Verification",
            "APK Signing", "APK Validation", "Completed"
    };

    public static final int ST_ANALYZE = 0, ST_BUILD = 1, ST_KILL = 2,
            ST_SIGN = 3, ST_VALIDATE = 4, ST_DONE = 5;

    private static final String KEY_ALIAS = "antiadapt";
    private static final char[] STORE_PASS = "antiadapt_m_key".toCharArray();

    private ApkEngine() {}

    // ================================================================
    // PUBLIC PIPELINES
    // ================================================================

    public static String processApkFile(Context ctx, File input, String sourceName,
                                        boolean resign, Callback cb) throws Exception {
        cb.onStage(ST_ANALYZE);
        cb.onLog("Input: " + sourceName + " (" + fmtSize(input.length()) + ")");
        requireValidApkZip(input);
        cb.onLog("APK structure verified.");
        cb.onProgress(25);

        cb.onStage(ST_BUILD);
        cb.onLog("Preparing APK for processing...");
        return finishPipeline(ctx, input, stripExt(sourceName), ".apk", resign, cb);
    }

    public static String processArchive(Context ctx, File input, String sourceName,
                                        boolean resign, Callback cb) throws Exception {
        cb.onStage(ST_ANALYZE);
        cb.onLog("Opening package: " + sourceName + " (" + fmtSize(input.length()) + ")");
        File tmp = new File(cacheDir(ctx), "arc_" + System.currentTimeMillis());
        tmp.mkdirs();
        try {
            List<File> apks = extractApksFromZip(input, tmp, cb);
            cb.onProgress(25);
            if (apks.size() == 1) {
                cb.onStage(ST_BUILD);
                cb.onLog("Base APK found: " + apks.get(0).getName());
                requireValidApkZip(apks.get(0));
                return finishPipeline(ctx, apks.get(0), stripExt(sourceName), ".apk", resign, cb);
            } else {
                cb.onStage(ST_BUILD);
                cb.onLog(apks.size() + " split APKs - creating .apks bundle...");
                File bundle = new File(tmp, "bundle.apks");
                writeStoredZip(apks, bundle);
                String saved = saveToOutput(ctx, bundle, stripExt(sourceName), ".apks", cb);
                cb.onProgress(100);
                cb.onStage(ST_DONE);
                cb.onLog("Saved bundle: " + saved);
                cb.onLog("Note: split bundles install via split-APK installers (e.g. SAI).");
                return saved;
            }
        } finally {
            deleteDir(tmp);
        }
    }

    public static String processAab(Context ctx, File input, String sourceName,
                                    Callback cb) throws Exception {
        cb.onStage(ST_ANALYZE);
        cb.onLog("Analyzing AAB: " + sourceName);
        ZipFile zf;
        try { zf = new ZipFile(input); }
        catch (Exception ex) { throw new IOException("Corrupted AAB file (cannot open as ZIP)."); }
        boolean base = zf.getEntry("base/manifest/AndroidManifest.xml") != null;
        zf.close();
        if (!base) throw new IOException("Not a valid AAB (base module missing).");
        cb.onLog("Valid Android App Bundle detected.");
        cb.onProgress(30);
        throw new IOException(
                "AAB to APK conversion needs Google's bundletool, which is not bundled "
                        + "in this build.\n\nOn a PC run:\n"
                        + "bundletool build-apks --bundle=app.aab --output=app.apks "
                        + "--mode=universal\n\nThen open the resulting .apks file here.");
    }

    public static String processInstalledApk(Context ctx, List<File> apkFiles, String appName,
                                             boolean resign, Callback cb) throws Exception {
        cb.onStage(ST_ANALYZE);
        cb.onLog("Installed app: " + appName);
        if (apkFiles.size() == 1) {
            requireValidApkZip(apkFiles.get(0));
            cb.onLog("APK extracted (" + fmtSize(apkFiles.get(0).length()) + ")");
            cb.onProgress(25);
            cb.onStage(ST_BUILD);
            cb.onLog("Preparing APK...");
            return finishPipeline(ctx, apkFiles.get(0), appName, ".apk", resign, cb);
        }
        cb.onLog(apkFiles.size() + " split APKs - creating .apks bundle...");
        cb.onProgress(40);
        cb.onStage(ST_BUILD);
        File bundle = File.createTempFile("inst_", ".apks", cacheDir(ctx));
        writeStoredZip(apkFiles, bundle);
        String saved = saveToOutput(ctx, bundle, appName, ".apks", cb);
        cb.onProgress(100);
        cb.onStage(ST_DONE);
        cb.onLog("Saved bundle: " + saved);
        return saved;
    }

    // ================================================================
    // CORE PIPELINE  (no ZIP rewriting - signer replaces blocks directly)
    // ================================================================

    private static String finishPipeline(Context ctx, File workApk, String baseName,
                                         String ext, boolean resign, Callback cb) throws Exception {
        File finalApk;
        if (resign) {
            cb.onStage(ST_KILL);
            cb.onLog("Kill Verification: scanning signature protection...");
            List<String> sigFiles = findV1SignatureFiles(workApk);
            if (!sigFiles.isEmpty()) {
                cb.onLog("JAR (v1) signature files found: " + sigFiles.size());
                for (String s : sigFiles) cb.onLog("  - " + s);
                cb.onLog("These will be neutralized by v2/v3 signing.");
            } else {
                cb.onLog("No JAR (v1) signature files found.");
            }
            cb.onLog("Existing v2/v3 signature blocks (if any) will be replaced.");
            if (cb.isCancelled()) throw new IOException("CANCELLED");
            cb.onProgress(40);

            cb.onStage(ST_SIGN);
            cb.onLog("Signing APK (v2 + v3 schemes)...");
            getOrCreateKey(ctx);
            File signed = new File(cacheDir(ctx),
                    "signed_" + System.currentTimeMillis() + ".apk");
            signApk(workApk, signed, ctx);
            cb.onLog("Signed with AntiAdapt M managed key (RSA-2048).");
            cb.onLog("Old signature blocks replaced - package re-signed.");
            cb.onLog("Note: v2/v3 signed APKs install on Android 7.0+.");
            cb.onProgress(75);
            finalApk = signed;
        } else {
            cb.onStage(ST_KILL);
            cb.onLog("Kill Verification: skipped (preserving original signature).");
            cb.onProgress(40);
            cb.onStage(ST_SIGN);
            cb.onLog("APK Signing: skipped (original signature preserved).");
            cb.onProgress(75);
            finalApk = workApk;
        }

        cb.onStage(ST_VALIDATE);
        cb.onLog("Validating final APK structure & signature...");
        verifyApk(finalApk);
        cb.onLog("Validation passed - APK is installable.");

        String saved = saveToOutput(ctx, finalApk, baseName, ext, cb);
        cb.onProgress(100);
        cb.onStage(ST_DONE);
        cb.onLog("Saved: " + saved);
        return saved;
    }

    // ================================================================
    // SIGNATURE DETECTION
    // ================================================================

    private static List<String> findV1SignatureFiles(File apk) throws IOException {
        List<String> out = new ArrayList<>();
        ZipFile zf;
        try { zf = new ZipFile(apk); }
        catch (Exception ex) { throw new IOException("Corrupted package (cannot open as ZIP)."); }
        try {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                String n = en.nextElement().getName();
                if (n.startsWith("META-INF/")) {
                    String u = n.toUpperCase(Locale.US);
                    if (u.endsWith(".SF") || u.endsWith(".RSA")
                            || u.endsWith(".DSA") || u.endsWith(".EC")) out.add(n);
                }
            }
        } finally {
            zf.close();
        }
        return out;
    }

    // ================================================================
    // HELPERS: extraction / validation
    // ================================================================

    private static List<File> extractApksFromZip(File archive, File destDir,
                                                 Callback cb) throws IOException {
        List<File> out = new ArrayList<>();
        List<ZipEntry> apkEntries = new ArrayList<>();
        List<ZipEntry> obbEntries = new ArrayList<>();
        boolean project = false;
        ZipFile zf;
        try { zf = new ZipFile(archive); }
        catch (Exception ex) { throw new IOException("Corrupted package (cannot open as ZIP)."); }
        try {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                String low = n.toLowerCase(Locale.US);
                if (low.endsWith(".apk") && !low.startsWith("meta-inf/")) apkEntries.add(e);
                else if (low.endsWith(".obb")) obbEntries.add(e);
                if (n.equals("apktool.yml") || low.startsWith("smali/")
                        || low.startsWith("smali_classes")) project = true;
            }
            if (apkEntries.isEmpty()) {
                if (project) throw new IOException(
                        "Decompiled APK project detected (smali/apktool). Rebuilding needs "
                                + "APKTool + aapt2 - not supported in this build.");
                throw new IOException("No APK found inside this package.");
            }
            cb.onLog(apkEntries.size() + " APK file(s) found in package.");
            for (ZipEntry e : apkEntries) {
                if (cb.isCancelled()) throw new IOException("CANCELLED");
                File dst = new File(destDir, new File(e.getName()).getName());
                InputStream is = zf.getInputStream(e);
                if (is == null) throw new IOException("Corrupted package (unreadable entry).");
                copyStream(is, new FileOutputStream(dst));
                out.add(dst);
                cb.onLog("Extracted: " + dst.getName() + " (" + fmtSize(dst.length()) + ")");
            }
            if (!obbEntries.isEmpty()) copyObb(zf, obbEntries, cb);
        } finally {
            zf.close();
        }
        return out;
    }

    private static void copyObb(ZipFile zf, List<ZipEntry> obbEntries, Callback cb) {
        try {
            String pkg = null;
            ZipEntry mj = zf.getEntry("manifest.json");
            if (mj != null) {
                ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                copyStream(zf.getInputStream(mj), bo);
                try {
                    pkg = new JSONObject(new String(bo.toByteArray(), "UTF-8"))
                            .getString("package_name");
                } catch (Exception ignored) {}
            }
            if (pkg == null) { cb.onLog("OBB found but package name unknown - OBB not copied."); return; }
            File dir = new File(Environment.getExternalStorageDirectory(), "Android/obb/" + pkg);
            if (!(dir.exists() || dir.mkdirs())) {
                cb.onLog("OBB skipped (cannot write Android/obb)."); return;
            }
            for (ZipEntry e : obbEntries) {
                File dst = new File(dir, new File(e.getName()).getName());
                copyStream(zf.getInputStream(e), new FileOutputStream(dst));
                cb.onLog("OBB copied: " + dst.getName());
            }
        } catch (Exception e) {
            cb.onLog("OBB copy failed: " + e.getMessage());
        }
    }

    private static void requireValidApkZip(File f) throws IOException {
        ZipFile zf;
        try { zf = new ZipFile(f); }
        catch (Exception ex) { throw new IOException("Corrupted or unsupported package (cannot open as ZIP)."); }
        try {
            boolean hasManifest = zf.getEntry("AndroidManifest.xml") != null;
            boolean project = zf.getEntry("apktool.yml") != null;
            if (project) throw new IOException(
                    "Decompiled APK project detected. Rebuild it with APKTool first.");
            if (!hasManifest) throw new IOException("Not a valid APK (AndroidManifest.xml missing).");
            if (zf.size() < 3) throw new IOException("Corrupted APK package.");
        } finally {
            zf.close();
        }
    }

    private static void writeStoredZip(List<File> files, File out) throws IOException {
        ZipOutputStream zos = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(out), 1 << 16));
        byte[] buf = new byte[1 << 16];
        try {
            for (File f : files) {
                ZipEntry e = new ZipEntry(f.getName());
                e.setMethod(ZipEntry.STORED);
                e.setSize(f.length());
                e.setCompressedSize(f.length());
                CRC32 crc = new CRC32();
                InputStream in = new FileInputStream(f);
                int r;
                while ((r = in.read(buf)) > 0) crc.update(buf, 0, r);
                in.close();
                e.setCrc(crc.getValue());
                zos.putNextEntry(e);
                in = new FileInputStream(f);
                while ((r = in.read(buf)) > 0) zos.write(buf, 0, r);
                in.close();
                zos.closeEntry();
            }
        } finally {
            zos.close();
        }
    }

    public static void verifyApk(File apk) throws Exception {
        ApkVerifier.Result res = new ApkVerifier.Builder(apk)
                .setMinCheckedPlatformVersion(24)
                .build()
                .verify();
        if (!res.isVerified()) {
            StringBuilder sb = new StringBuilder("APK validation failed");
            for (Object err : res.getErrors()) sb.append("\n- ").append(err);
            throw new IOException(sb.toString());
        }
    }

    // ================================================================
    // SIGNING KEY MANAGEMENT
    // ================================================================

    private static File keyFile(Context c) {
        return new File(c.getFilesDir(), "antiadapt_signer.p12");
    }

    public static synchronized void getOrCreateKey(Context ctx) throws Exception {
        File f = keyFile(ctx);
        if (f.exists() && f.length() > 0) return;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=AntiAdapt M, OU=Tools, O=AntiAdapt, C=US");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(now),
                new Date(now - 86400000L), new Date(now + 3650L * 86400000L),
                subject, kp.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(cs));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(KEY_ALIAS, kp.getPrivate(), STORE_PASS, new Certificate[]{cert});
        FileOutputStream fos = new FileOutputStream(f);
        ks.store(fos, STORE_PASS);
        fos.close();
    }

    public static void signApk(File in, File out, Context ctx) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(keyFile(ctx));
        ks.load(fis, STORE_PASS);
        fis.close();
        PrivateKey pk = (PrivateKey) ks.getKey(KEY_ALIAS, STORE_PASS);
        X509Certificate cert = (X509Certificate) ks.getCertificate(KEY_ALIAS);
        ApkSigner.SignerConfig cfg = new ApkSigner.SignerConfig.Builder(
                "AntiAdapt M", pk, Collections.singletonList(cert)).build();
        new ApkSigner.Builder(Collections.singletonList(cfg))
                .setInputApk(in)
                .setOutputApk(out)
                .setMinSdkVersion(24)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign();
    }

    public static String keyInfo(Context ctx) {
        try {
            File f = keyFile(ctx);
            if (!f.exists()) return "No signing key yet (created automatically on first export).";
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(f);
            ks.load(fis, STORE_PASS);
            fis.close();
            X509Certificate c = (X509Certificate) ks.getCertificate(KEY_ALIAS);
            return "RSA-2048 / PKCS12\nSubject: " + c.getSubjectX500Principal().getName()
                    + "\nValid until: " + c.getNotAfter();
        } catch (Exception e) {
            return "Key error: " + e.getMessage();
        }
    }

    public static boolean regenerateKey(Context ctx) {
        keyFile(ctx).delete();
        try { getOrCreateKey(ctx); return true; }
        catch (Exception e) { return false; }
    }

    // ================================================================
    // OUTPUT SAVING
    // ================================================================

    private static String saveToOutput(Context ctx, File src, String baseName,
                                       String ext, Callback cb) throws IOException {
        String name = safeName(baseName) + "_" + stamp() + ext;
        SharedPreferences p = ctx.getSharedPreferences("aam_prefs", Context.MODE_PRIVATE);
        String tree = p.getString("out_tree_uri", null);
        if (tree != null && tree.length() > 4) {
            try {
                DocumentFile dir = DocumentFile.fromTreeUri(ctx, Uri.parse(tree));
                if (dir != null && dir.canWrite()) {
                    DocumentFile nf = dir.createFile(
                            "application/vnd.android.package-archive", name);
                    if (nf != null) {
                        OutputStream os = ctx.getContentResolver().openOutputStream(nf.getUri());
                        if (os == null) throw new IOException("Cannot open output stream.");
                        copyStream(new FileInputStream(src), os);
                        return name + " (selected folder)";
                    }
                }
            } catch (Exception e) {
                if (cb != null) cb.onLog("Custom folder failed: " + e.getMessage()
                        + " - using default folder.");
            }
        }
        File d = defaultOutputDir(ctx, cb);
        File out = new File(d, name);
        copyFile(src, out);
        return out.getAbsolutePath();
    }

    public static File defaultOutputDir(Context ctx, Callback cb) throws IOException {
        File d = new File(Environment.getExternalStorageDirectory(), "AntiAdapt M");
        if (!d.exists()) d.mkdirs();
        if (!d.isDirectory() || !d.canWrite()) {
            File fb = new File(ctx.getExternalFilesDir(null), "AntiAdapt M");
            if (!fb.exists()) fb.mkdirs();
            if (!fb.canWrite()) throw new IOException(
                    "Storage not writable - grant 'All files access' to AntiAdapt M in system settings.");
            if (cb != null) cb.onLog("Using app folder fallback: " + fb.getAbsolutePath());
            return fb;
        }
        return d;
    }

    public static void cleanupCache(Context ctx) {
        File d = cacheDir(ctx);
        File[] f = d.listFiles();
        if (f == null) return;
        long cutoff = System.currentTimeMillis() - 1800000L;
        for (File x : f) {
            String n = x.getName();
            if (x.lastModified() < cutoff && (n.startsWith("in_") || n.startsWith("clean_")
                    || n.startsWith("signed_") || n.startsWith("arc_") || n.startsWith("inst_")))
                deleteDir(x);
        }
    }

    public static File cacheDir(Context ctx) {
        File ext = ctx.getExternalCacheDir();
        return ext != null ? ext : ctx.getCacheDir();
    }

    // ================================================================
    // UTILS
    // ================================================================

    public static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] b = new byte[1 << 16];
        try {
            int r;
            while ((r = in.read(b)) > 0) out.write(b, 0, r);
        } finally {
            try { in.close(); } catch (IOException ignored) {}
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    static void copyFile(File in, File out) throws IOException {
        copyStream(new FileInputStream(in), new FileOutputStream(out));
    }

    private static void deleteDir(File d) {
        File[] f = d.listFiles();
        if (f != null) for (File x : f) { if (x.isDirectory()) deleteDir(x); else x.delete(); }
        d.delete();
    }

    private static String stripExt(String n) {
        if (n == null) return "app";
        int i = n.lastIndexOf('.');
        return i > 0 ? n.substring(0, i) : n;
    }

    private static String safeName(String b) {
        if (b == null) return "app";
        String s = b.replaceAll("[^A-Za-z0-9._ -]", "_").trim();
        if (s.length() > 40) s = s.substring(0, 40).trim();
        return s.length() == 0 ? "app" : s;
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
    }

    private static String fmtSize(long v) {
        if (v < 1024) return v + " B";
        if (v < 1048576) return String.format(Locale.US, "%.1f KB", v / 1024f);
        if (v < 1073741824) return String.format(Locale.US, "%.1f MB", v / 1048576f);
        return String.format(Locale.US, "%.2f GB", v / 1073741824f);
    }
}
