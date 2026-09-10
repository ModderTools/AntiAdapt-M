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
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
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
        return finishPipeline(ctx, input, stripExt(sourceName), ".apk", resign, false, cb);
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
                return finishPipeline(ctx, apks.get(0), stripExt(sourceName), ".apk", resign, false, cb);
            }
            cb.onStage(ST_BUILD);
            cb.onProgress(30);
            if (!resign) {
                cb.onLog("Kill Verification disabled - keeping splits as .apks bundle.");
                return bundleFallback(ctx, apks, stripExt(sourceName), cb);
            }
            cb.onLog(apks.size() + " split APKs detected - SmartMerge to single APK...");
            try {
                File basePick = pickBaseApk(apks);
                List<File> others = new ArrayList<>(apks);
                others.remove(basePick);
                File merged = mergeSplits(ctx, basePick, others, cb);
                return finishPipeline(ctx, merged, stripExt(sourceName), ".apk", true, true, cb);
            } catch (Exception me) {
                if ("CANCELLED".equals(me.getMessage())) throw me;
                cb.onLog("SmartMerge failed: " + me.getMessage());
                cb.onLog("Falling back to .apks bundle (install via SAI).");
                return bundleFallback(ctx, apks, stripExt(sourceName), cb);
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
        cb.onProgress(15);
        if (apkFiles.size() == 1) {
            requireValidApkZip(apkFiles.get(0));
            cb.onLog("APK extracted (" + fmtSize(apkFiles.get(0).length()) + ")");
            cb.onProgress(30);
            cb.onStage(ST_BUILD);
            cb.onLog("Preparing APK...");
            return finishPipeline(ctx, apkFiles.get(0), appName, ".apk", resign, false, cb);
        }
        cb.onProgress(30);
        cb.onStage(ST_BUILD);
        if (!resign) {
            cb.onLog("Kill Verification disabled - keeping splits as .apks bundle.");
            return bundleFallback(ctx, apkFiles, appName, cb);
        }
        cb.onLog(apkFiles.size() + " split APKs detected - SmartMerge to single APK...");
        try {
            File basePick = apkFiles.get(0);
            List<File> others = new ArrayList<>(apkFiles.subList(1, apkFiles.size()));
            File merged = mergeSplits(ctx, basePick, others, cb);
            return finishPipeline(ctx, merged, appName, ".apk", true, true, cb);
        } catch (Exception me) {
            if ("CANCELLED".equals(me.getMessage())) throw me;
            cb.onLog("SmartMerge failed: " + me.getMessage());
            cb.onLog("Falling back to .apks bundle (install via SAI).");
            return bundleFallback(ctx, apkFiles, appName, cb);
        }
    }

    private static String bundleFallback(Context ctx, List<File> apks, String name,
                                         Callback cb) throws IOException {
        File bundle = new File(cacheDir(ctx),
                "bundle_" + System.currentTimeMillis() + ".apks");
        writeStoredZip(apks, bundle);
        String saved = saveToOutput(ctx, bundle, name, ".apks", cb);
        cb.onProgress(100);
        cb.onStage(ST_DONE);
        cb.onLog("Saved bundle: " + saved);
        return saved;
    }

    // ================================================================
    // CORE PIPELINE
    // ================================================================

    private static String finishPipeline(Context ctx, File workApk, String baseName,
                                         String ext, boolean resign, boolean alreadyClean,
                                         Callback cb) throws Exception {
        File finalApk;
        if (resign) {
            cb.onStage(ST_KILL);
            if (alreadyClean) {
                cb.onLog("Kill Verification: old signature blocks dropped during build.");
            } else {
                cb.onLog("Kill Verification: scanning signature protection...");
                List<String> v1 = findV1SignatureFiles(workApk);
                boolean v23 = hasV2orV3Block(workApk);
                cb.onLog("Detected: v1 (JAR) signature files: " + v1.size()
                        + (v23 ? " | v2/v3 block: PRESENT" : " | v2/v3 block: none"));
                for (String s : v1) cb.onLog("  - " + s);
                cb.onLog("Action: v2/v3 blocks will be REPLACED, stale v1 files removed "
                        + "and re-created by fresh signing.");
            }
            if (cb.isCancelled()) throw new IOException("CANCELLED");
            cb.onProgress(45);

            cb.onStage(ST_SIGN);
            cb.onLog("Signing APK (v1 + v2 + v3 schemes)...");
            getOrCreateKey(ctx);
            File signed = new File(cacheDir(ctx),
                    "signed_" + System.currentTimeMillis() + ".apk");
            signApk(workApk, signed, ctx);
            cb.onLog("Signed with AntiAdapt M managed key (RSA-2048).");
            cb.onProgress(80);
            finalApk = signed;
        } else {
            cb.onStage(ST_KILL);
            cb.onLog("Kill Verification: skipped (preserving original signature).");
            cb.onProgress(45);
            cb.onStage(ST_SIGN);
            cb.onLog("APK Signing: skipped (original signature preserved).");
            cb.onProgress(80);
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
    // SMART MERGE: split APKs -> single APK
    // ================================================================

    private static File mergeSplits(Context ctx, File baseApk, List<File> others,
                                    Callback cb) throws Exception {
        cb.onLog("SmartMerge: base = " + baseApk.getName());
        Set<String> baseNames = new HashSet<>();
        byte[] baseArsc = null;
        ZipFile bz = new ZipFile(baseApk);
        try {
            Enumeration<? extends ZipEntry> en = bz.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                baseNames.add(e.getName());
                if (e.getName().equals("resources.arsc")) baseArsc = readZipEntry(bz, e);
            }
        } finally { bz.close(); }
        if (baseArsc == null) throw new IOException("Base APK has no resources.arsc.");

        String chosen = null;
        String[] abiPref = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"};
        for (String abi : abiPref) {
            for (File f : others) {
                ZipFile z = new ZipFile(f);
                try {
                    Enumeration<? extends ZipEntry> en = z.entries();
                    while (en.hasMoreElements()) {
                        String n = en.nextElement().getName();
                        if (n.startsWith("lib/" + abi + "/")) { chosen = abi; break; }
                    }
                } finally { z.close(); }
                if (chosen != null) break;
            }
            if (chosen != null) break;
        }
        cb.onLog(chosen == null ? "No native libraries in splits."
                : "Native ABI selected: " + chosen);

        Set<String> used = new HashSet<>(baseNames);
        List<NewEntry> adds = new ArrayList<>();
        List<byte[]> splitArscs = new ArrayList<>();
        int dexIdx = 2;
        while (used.contains("classes" + dexIdx + ".dex")) dexIdx++;
        int resCount = 0, assetCount = 0, libCount = 0;

        for (File f : others) {
            if (cb.isCancelled()) throw new IOException("CANCELLED");
            ZipFile z = new ZipFile(f);
            try {
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    String n = e.getName();
                    if (e.isDirectory()) continue;
                    if (n.equals("resources.arsc")) {
                        splitArscs.add(readZipEntry(z, e));
                        continue;
                    }
                    if (n.equals("AndroidManifest.xml") || n.startsWith("META-INF/")) continue;
                    if (n.startsWith("lib/")) {
                        String abi = n.substring(4);
                        int s = abi.indexOf('/');
                        if (s <= 0) continue;
                        abi = abi.substring(0, s);
                        if (!abi.equals(chosen) || used.contains(n)) continue;
                        used.add(n);
                        adds.add(new NewEntry(n, readZipEntry(z, e), true, 4096));
                        libCount++;
                        cb.onLog("Native lib added: " + n + " (" + fmtSize(e.getSize()) + ")");
                        continue;
                    }
                    if (n.startsWith("res/") || n.startsWith("assets/")) {
                        if (used.contains(n)) continue;
                        used.add(n);
                        adds.add(new NewEntry(n, readZipEntry(z, e), false, 0));
                        if (n.startsWith("res/")) resCount++; else assetCount++;
                        continue;
                    }
                    if (n.endsWith(".dex") && !n.contains("/")) {
                        if (dexIdx > 200) throw new IOException("Too many dex files.");
                        String nn = "classes" + dexIdx + ".dex";
                        while (used.contains(nn)) { dexIdx++; nn = "classes" + dexIdx + ".dex"; }
                        dexIdx++;
                        used.add(nn);
                        cb.onLog("Dex renamed: " + n + " -> " + nn);
                        adds.add(new NewEntry(nn, readZipEntry(z, e), false, 0));
                        continue;
                    }
                    if (!n.contains("/") && !used.contains(n)) {
                        used.add(n);
                        adds.add(new NewEntry(n, readZipEntry(z, e), false, 0));
                    }
                }
            } finally { z.close(); }
        }
        cb.onLog("Collected: " + resCount + " res, " + assetCount + " assets, "
                + libCount + " native libs, " + splitArscs.size() + " resource tables.");

        if (splitArscs.isEmpty()) {
            cb.onLog("No split resource tables - keeping base resources.arsc.");
        } else {
            cb.onLog("Merging " + (splitArscs.size() + 1) + " resource tables (ARSC)...");
            byte[] mergedArsc = mergeArsc(baseArsc, splitArscs);
            adds.add(0, new NewEntry("resources.arsc", mergedArsc, true, 4));
            cb.onLog("Resource table merged (" + fmtSize(mergedArsc.length) + ").");
        }

        Set<String> omit = new HashSet<>();
        omit.add("resources.arsc");
        for (String n : baseNames) if (isSignatureEntry(n)) omit.add(n);

        File out = new File(cacheDir(ctx), "merged_" + System.currentTimeMillis() + ".apk");
        buildMergedApk(baseApk, adds, out, omit, cb);
        cb.onLog("Merged APK built (" + fmtSize(out.length()) + ") - self-check OK.");
        return out;
    }

    private static File pickBaseApk(List<File> apks) {
        for (File f : apks) if (f.getName().equalsIgnoreCase("base.apk")) return f;
        List<File> cands = new ArrayList<>();
        for (File f : apks) {
            String n = f.getName().toLowerCase(Locale.US);
            if (!n.contains("config.") && !n.startsWith("split_")) cands.add(f);
        }
        if (cands.isEmpty()) cands = apks;
        File best = cands.get(0);
        for (File f : cands) if (f.length() > best.length()) best = f;
        return best;
    }

        private static byte[] readZipEntry(ZipFile zf, ZipEntry e) throws IOException {
        InputStream is = zf.getInputStream(e);
        if (is == null) throw new IOException("Unreadable entry: " + e.getName());
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream(65536);
            byte[] buf = new byte[1 << 15];
            int r;
            while ((r = is.read(buf)) > 0) bo.write(buf, 0, r);
            return bo.toByteArray();
        } finally {
            try { is.close(); } catch (IOException ignored) {}
        }
    }

    static class NewEntry {
        String name; byte[] data; boolean stored; int align;
        NewEntry(String n, byte[] d, boolean s, int a) {
            name = n; data = d; stored = s; align = a;
        }
    }

    // ================================================================
    // ARSC (ANDROID RESOURCE TABLE) BINARY MERGER
    // ================================================================

    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_TABLE_PACKAGE_TYPE = 0x0200;
    private static final int RES_TABLE_TYPE_TYPE = 0x0201;

    static class SP {
        boolean utf8;
        final List<byte[]> raw = new ArrayList<>();
        final List<String> str = new ArrayList<>();
        final HashMap<String, Integer> indexOf = new HashMap<>();
        byte[] stylesRaw;
        int size() { return raw.size(); }
        int intern(byte[] rawStr, String s) {
            Integer i = indexOf.get(s);
            if (i != null) return i;
            int idx = raw.size();
            raw.add(rawStr); str.add(s); indexOf.put(s, idx);
            return idx;
        }
    }

    static class RV { int res0, dataType; long data; }
    static class MapIt { long ident; RV v; }

    static class Ent {
        int flags, key; byte[] extra; boolean complex;
        RV val; long parent; List<MapIt> maps;
    }

    static class Cfg { byte[] cfg; final HashMap<Integer, Ent> entries = new HashMap<>(); }

    static class Typ {
        int id; String name; int total;
        final List<Cfg> configs = new ArrayList<>();
        final HashMap<String, Integer> keyIndex = new HashMap<>();
    }

    static class Pkg {
        int id, headerSize = 284, typeIdOffset; String name = "";
        SP types = new SP(), keys = new SP();
        final HashMap<String, Typ> byName = new HashMap<>();
        final List<Typ> typeList = new ArrayList<>();
    }

    static class Arsc {
        SP global;
        final List<Pkg> pkgs = new ArrayList<>();
        final List<byte[]> unknown = new ArrayList<>();
    }

    private static byte[] mergeArsc(byte[] baseBytes, List<byte[]> splitBytes) throws IOException {
        Arsc A = parseTable(baseBytes);
        if (A.global == null) A.global = new SP();
        Pkg P = A.pkgs.isEmpty() ? null : A.pkgs.get(0);
        if (P == null) throw new IOException("Base ARSC has no package.");
        List<Object[]> pending = new ArrayList<>();
        int merged = 0;
        for (byte[] sb2 : splitBytes) {
            Arsc S = parseTable(sb2);
            Pkg Q = null;
            for (Pkg q : S.pkgs) if (q.id == P.id) { Q = q; break; }
            if (Q == null) continue;
            mergePackageInto(P, Q, S.global != null ? S.global : new SP(), A.global, pending);
            merged++;
        }
        if (merged == 0) throw new IOException("No compatible split resource packages.");
        resolveIdents(P, pending);
        return writeTable(A);
    }

    private static Arsc parseTable(byte[] d) throws IOException {
        if (d.length < 12 || u16(d, 0) != 0x0002) throw new IOException("Not a valid resource table.");
        Arsc a = new Arsc();
        int hs = u16(d, 2);
        int total = (int) u32(d, 4);
        if (total > d.length) total = d.length;
        int pos = hs;
        boolean firstPool = true;
        while (pos + 8 <= total) {
            int type = u16(d, pos);
            int hsz = u16(d, pos + 2);
            int size = (int) u32(d, pos + 4);
            if (hsz < 8 || size < hsz || pos + size > total) break;
            if (type == RES_STRING_POOL_TYPE && firstPool) {
                a.global = parsePool(d, pos);
                firstPool = false;
            } else if (type == RES_TABLE_PACKAGE_TYPE) {
                a.pkgs.add(parsePkg(d, pos, size));
            } else if (a.global != null) {
                a.unknown.add(Arrays.copyOfRange(d, pos, pos + size));
            }
            pos += size;
            if (size <= 0) break;
        }
        return a;
    }

    private static Pkg parsePkg(byte[] d, int pos, int size) throws IOException {
        Pkg p = new Pkg();
        p.headerSize = u16(d, pos + 2);
        p.id = (int) u32(d, pos + 8);
        StringBuilder nm = new StringBuilder();
        for (int i = 0; i < 128; i++) {
            int cp = pos + 12 + i * 2;
            if (cp + 2 > d.length) break;
            char ch = (char) u16(d, cp);
            if (ch == 0) break;
            nm.append(ch);
        }
        p.name = nm.toString();
        if (p.headerSize == 288) p.typeIdOffset = (int) u32(d, pos + 284);
        else p.headerSize = 284;
        int typeStrings = (int) u32(d, pos + 268);
        int keyStrings = (int) u32(d, pos + 276);
        if (typeStrings > 0 && pos + typeStrings < d.length) p.types = parsePool(d, pos + typeStrings);
        if (keyStrings > 0 && pos + keyStrings < d.length) p.keys = parsePool(d, pos + keyStrings);
        int cpos = pos + p.headerSize;
        int end = pos + size;
        while (cpos + 8 <= end) {
            int type = u16(d, cpos);
            int hsz = u16(d, cpos + 2);
            int csz = (int) u32(d, cpos + 4);
            if (hsz < 8 || csz < hsz || cpos + csz > end) break;
            if (type == RES_TABLE_TYPE_TYPE) parseTypeChunk(p, d, cpos, csz);
            cpos += csz;
            if (csz <= 0) break;
        }
        return p;
    }

    private static void parseTypeChunk(Pkg p, byte[] d, int cs, int csz) {
        try {
            int hs = u16(d, cs + 2);
            int tid = d[cs + 8] & 0xFF;
            int flags = u16(d, cs + 10);
            int count = (int) u32(d, cs + 12);
            int entriesStart = (int) u32(d, cs + 16);
            if (hs < 20 || hs > csz) return;
            byte[] cfg = Arrays.copyOfRange(d, cs + 20, cs + hs);
            int ai = p.typeIdOffset + tid - 1;
            String tname = (ai >= 0 && p.types != null && ai < p.types.size())
                    ? p.types.str.get(ai) : ("?t" + tid);
            Typ t = p.byName.get(tname);
            if (t == null) {
                t = new Typ();
                t.id = ai + 1;
                if (t.id <= 0) t.id = p.byName.size() + 1;
                t.name = tname;
                p.byName.put(tname, t);
                p.typeList.add(t);
            }
            Cfg c = null;
            for (Cfg bc : t.configs) if (Arrays.equals(bc.cfg, cfg)) { c = bc; break; }
            if (c == null) { c = new Cfg(); c.cfg = cfg; t.configs.add(c); }
            if ((flags & 1) != 0) {
                int op = cs + hs;
                for (int i = 0; i < count; i++) {
                    if (op + i * 4 + 4 > cs + csz) break;
                    int idx = u16(d, op + i * 4);
                    int ov = u16(d, op + i * 4 + 2);
                    if (ov == 0 && idx == 0xFFFF) continue;
                    parseEntryAt(p, t, c, d, cs + entriesStart + ov * 4, idx, cs + csz);
                }
            } else {
                int osize = (flags & 2) != 0 ? 2 : 4;
                for (int i = 0; i < count; i++) {
                    int op = cs + hs + i * osize;
                    if (op + osize > cs + csz) break;
                    long v = osize == 2 ? u16(d, op) : u32(d, op);
                    if (v == 0xFFFFFFFFL) continue;
                    parseEntryAt(p, t, c, d, cs + entriesStart + (int) v, i, cs + csz);
                }
            }
        } catch (Exception ignored) {}
    }

    private static void parseEntryAt(Pkg p, Typ t, Cfg c, byte[] d, int es, int idx, int limit) {
        try {
            if (es + 8 > limit) return;
            Ent e = new Ent();
            int size = u16(d, es);
            e.flags = u16(d, es + 2);
            e.key = (int) u32(d, es + 4);
            if (size > 8 && es + size <= limit) e.extra = Arrays.copyOfRange(d, es + 8, es + size);
            if ((e.flags & 1) != 0) {
                e.complex = true;
                int vs = es + size;
                if (vs + 8 > limit) return;
                e.parent = u32(d, vs);
                int cnt = (int) u32(d, vs + 4);
                e.maps = new ArrayList<>();
                int mp = vs + 8;
                for (int i = 0; i < cnt; i++) {
                    if (mp + 12 > limit) break;
                    MapIt m = new MapIt();
                    m.ident = u32(d, mp);
                    RV v = new RV();
                    v.res0 = d[mp + 6] & 0xFF;
                    v.dataType = d[mp + 7] & 0xFF;
                    v.data = u32(d, mp + 8);
                    m.v = v;
                    e.maps.add(m);
                    mp += 12;
                }
            } else {
                int vs = es + size;
                if (vs + 8 > limit) return;
                RV v = new RV();
                v.res0 = d[vs + 2] & 0xFF;
                v.dataType = d[vs + 3] & 0xFF;
                v.data = u32(d, vs + 4);
                e.val = v;
            }
            c.entries.put(idx, e);
            if (idx + 1 > t.total) t.total = idx + 1;
            if (p.keys != null && e.key >= 0 && e.key < p.keys.size()) {
                String kn = p.keys.str.get(e.key);
                if (!t.keyIndex.containsKey(kn)) t.keyIndex.put(kn, idx);
            }
        } catch (Exception ignored) {}
    }

    private static SP parsePool(byte[] d, int off) throws IOException {
        SP sp = new SP();
        if (off + 28 > d.length) throw new IOException("Truncated string pool header.");
        int hsz = u16(d, off + 2);
        int size = (int) u32(d, off + 4);
        int count = (int) u32(d, off + 8);
        int stylesCount = (int) u32(d, off + 12);
        int flags = (int) u32(d, off + 16);
        int stringsStart = (int) u32(d, off + 20);
        int stylesStart = (int) u32(d, off + 24);
        sp.utf8 = (flags & 0x100) != 0;
        if (hsz < 28 || count < 0 || count > 0x100000) throw new IOException("Bad string pool.");
        for (int i = 0; i < count; i++) {
            int op = off + hsz + i * 4;
            if (op + 4 > d.length) throw new IOException("Truncated string offsets.");
            int p2 = off + stringsStart + (int) u32(d, op);
            if (p2 < 0 || p2 >= d.length) throw new IOException("String out of range.");
            if (sp.utf8) {
                int q = p2;
                int a = d[q++] & 0xFF;
                if ((a & 0x80) != 0) a = ((a & 0x7F) << 8) | (d[q++] & 0xFF);
                int b = d[q++] & 0xFF;
                if ((b & 0x80) != 0) b = ((b & 0x7F) << 8) | (d[q++] & 0xFF);
                if (q + b + 1 > d.length) throw new IOException("Truncated string.");
                byte[] raw = Arrays.copyOfRange(d, p2, q + b + 1);
                String s;
                try { s = new String(d, q, b, "UTF-8"); } catch (Exception ex) { s = "?u" + i; }
                sp.intern(raw, s);
            } else {
                int q = p2;
                int a = (d[q] & 0xFF) | ((d[q + 1] & 0xFF) << 8);
                q += 2;
                if ((a & 0x8000) != 0) {
                    a = ((a & 0x7FFF) << 16) | ((d[q] & 0xFF) | ((d[q + 1] & 0xFF) << 8));
                    q += 2;
                }
                if (q + a * 2 + 2 > d.length) throw new IOException("Truncated string.");
                StringBuilder sbv = new StringBuilder(a);
                for (int k = 0; k < a; k++)
                    sbv.append((char) ((d[q + k * 2] & 0xFF) | ((d[q + k * 2 + 1] & 0xFF) << 8)));
                byte[] raw = Arrays.copyOfRange(d, p2, q + a * 2 + 2);
                sp.intern(raw, sbv.toString());
            }
        }
        if (stylesCount > 0 && stylesStart > 0 && off + stylesStart + 8 <= d.length) {
            int st = off + stylesStart;
            int en2 = off + size;
            if (en2 <= d.length && en2 > st) sp.stylesRaw = Arrays.copyOfRange(d, st, en2);
        }
        return sp;
    }

        private static void mergePackageInto(Pkg P, Pkg Q, SP srcG, SP dstG, List<Object[]> pending) throws IOException {
        if (P.types == null || P.keys == null)
            throw new IOException("Base ARSC pools missing.");
        for (Typ qt : Q.typeList) {
            Typ t = P.byName.get(qt.name);
            boolean newType = t == null;
            if (newType) {
                Integer ex = P.types.indexOf.get(qt.name);
                int ti = ex != null ? ex : P.types.intern(encodeString(qt.name, P.types.utf8), qt.name);
                t = new Typ();
                t.id = ti + 1;
                t.name = qt.name;
                P.byName.put(qt.name, t);
                P.typeList.add(t);
            }
            for (Cfg qc : qt.configs) {
                Cfg c = null;
                for (Cfg bc : t.configs) if (Arrays.equals(bc.cfg, qc.cfg)) { c = bc; break; }
                if (c == null) { c = new Cfg(); c.cfg = qc.cfg; t.configs.add(c); }
                int[] order = new int[qc.entries.size()];
                int k = 0;
                for (Integer kk : qc.entries.keySet()) order[k++] = kk;
                Arrays.sort(order);
                for (int oi : order) {
                    Ent e = qc.entries.get(oi);
                    String kn = (e.key >= 0 && e.key < Q.keys.size())
                            ? Q.keys.str.get(e.key) : ("k" + e.key);
                    if (t.keyIndex.containsKey(kn)) continue;
                    int newIdx;
                    if (newType) {
                        newIdx = oi;
                        if (newIdx + 1 > t.total) t.total = newIdx + 1;
                    } else {
                        newIdx = t.total;
                        t.total = newIdx + 1;
                    }
                    Ent copy = cloneEnt(e);
                    Integer xi = P.keys.indexOf.get(kn);
                    copy.key = xi != null ? xi : P.keys.intern(encodeString(kn, P.keys.utf8), kn);
                    remapVals(copy, Q, srcG, dstG, pending);
                    c.entries.put(newIdx, copy);
                    t.keyIndex.put(kn, newIdx);
                }
            }
        }
    }

    private static void remapVals(Ent e, Pkg Q, SP srcG, SP dstG, List<Object[]> pending) {
        if (e.val != null && e.val.dataType == 3)
            e.val.data = gmap(srcG, dstG, (int) e.val.data);
        if (e.maps != null)
            for (MapIt m : e.maps) {
                if (m.v != null && m.v.dataType == 3)
                    m.v.data = gmap(srcG, dstG, (int) m.v.data);
                pending.add(new Object[]{Q, m});
            }
    }

    private static void resolveIdents(Pkg P, List<Object[]> pending) {
        for (Object[] pr : pending) {
            Pkg Q = (Pkg) pr[0];
            MapIt m = (MapIt) pr[1];
            long ident = m.ident;
            int pkgId = (int) ((ident >>> 24) & 0xFF);
            if (pkgId != Q.id) continue;
            int tf = (int) ((ident >>> 16) & 0xFF);
            int ei = (int) (ident & 0xFFFF);
            int ai = Q.typeIdOffset + tf - 1;
            if (ai < 0 || Q.types == null || ai >= Q.types.size()) continue;
            if (Q.keys == null || ei >= Q.keys.size()) continue;
            Typ t = P.byName.get(Q.types.str.get(ai));
            if (t == null) continue;
            Integer ix = t.keyIndex.get(Q.keys.str.get(ei));
            if (ix == null) continue;
            m.ident = ((long) P.id << 24) | ((long) t.id << 16) | ix;
        }
    }

    private static long gmap(SP from, SP to, int idx) {
        if (idx < 0 || idx >= from.size()) return idx;
        String s = from.str.get(idx);
        Integer o = to.indexOf.get(s);
        if (o != null) return o;
        return to.intern(encodeString(s, to.utf8), s);
    }

    private static Ent cloneEnt(Ent e) {
        Ent n = new Ent();
        n.flags = e.flags; n.key = e.key; n.extra = e.extra;
        n.complex = e.complex; n.val = e.val;
        n.parent = e.parent; n.maps = e.maps;
        return n;
    }

    private static byte[] encodeString(String s, boolean utf8) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            if (utf8) {
                byte[] b = s.getBytes("UTF-8");
                int u16 = s.length(), u8 = b.length;
                if (u16 < 0x80) bo.write(u16);
                else { bo.write(0x80 | ((u16 >>> 8) & 0xFF)); bo.write(u16 & 0xFF); }
                if (u8 < 0x80) bo.write(u8);
                else { bo.write(0x80 | ((u8 >>> 8) & 0xFF)); bo.write(u8 & 0xFF); }
                bo.write(b);
                bo.write(0);
            } else {
                int u16 = s.length();
                if (u16 < 0x8000) { bo.write(u16 & 0xFF); bo.write((u16 >>> 8) & 0xFF); }
                else {
                    int h = 0x8000 | ((u16 >>> 16) & 0x7FFF);
                    bo.write(h & 0xFF); bo.write((h >>> 8) & 0xFF);
                    bo.write(u16 & 0xFF); bo.write((u16 >>> 8) & 0xFF);
                }
                for (int i = 0; i < u16; i++) {
                    char ch = s.charAt(i);
                    bo.write(ch & 0xFF); bo.write((ch >>> 8) & 0xFF);
                }
                bo.write(0); bo.write(0);
            }
            return bo.toByteArray();
        } catch (IOException ex) { throw new RuntimeException(ex); }
    }

    private static byte[] writeTable(Arsc a) throws IOException {
        byte[] gp = writePool(a.global);
        List<byte[]> pb = new ArrayList<>();
        for (Pkg p : a.pkgs) pb.add(writePkg(p));
        int total = 12 + gp.length;
        for (byte[] u : a.unknown) total += u.length;
        for (byte[] x : pb) total += x.length;
        byte[] o = new byte[total];
        putShort(o, 0, 0x0002);
        putShort(o, 2, 12);
        putInt(o, 4, total);
        putInt(o, 8, a.pkgs.size());
        int pos = 12;
        System.arraycopy(gp, 0, o, pos, gp.length); pos += gp.length;
        for (byte[] u : a.unknown) { System.arraycopy(u, 0, o, pos, u.length); pos += u.length; }
        for (byte[] x : pb) { System.arraycopy(x, 0, o, pos, x.length); pos += x.length; }
        return o;
    }

    private static byte[] writePkg(Pkg p) throws IOException {
        byte[] tp = writePool(p.types);
        byte[] kp = writePool(p.keys);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        List<Typ> sorted = new ArrayList<>(p.typeList);
        Collections.sort(sorted, (a, b2) -> a.id - b2.id);
        for (Typ t : sorted) {
            int cnt = t.total;
            byte[] spec = new byte[16 + cnt * 4];
            putShort(spec, 0, 0x0202);
            putShort(spec, 2, 16);
            putInt(spec, 4, spec.length);
            spec[8] = (byte) ((t.id - p.typeIdOffset) & 0xFF);
            putInt(spec, 12, cnt);
            body.write(spec, 0, spec.length);
            for (Cfg c : t.configs) {
                byte[] cb2 = writeCfg(p, t, c);
                body.write(cb2, 0, cb2.length);
            }
        }
        byte[] bb = body.toByteArray();
        int size = p.headerSize + tp.length + kp.length + bb.length;
        byte[] o = new byte[size];
        putShort(o, 0, 0x0200);
        putShort(o, 2, p.headerSize);
        putInt(o, 4, size);
        putInt(o, 8, p.id);
        for (int i = 0; i < 128; i++) {
            char ch = i < p.name.length() ? p.name.charAt(i) : '\0';
            putShort(o, 12 + i * 2, ch);
        }
        putInt(o, 268, p.headerSize);
        putInt(o, 272, p.types.size());
        putInt(o, 276, p.headerSize + tp.length);
        putInt(o, 280, p.keys.size());
        if (p.headerSize == 288) putInt(o, 284, p.typeIdOffset);
        System.arraycopy(tp, 0, o, p.headerSize, tp.length);
        System.arraycopy(kp, 0, o, p.headerSize + tp.length, kp.length);
        System.arraycopy(bb, 0, o, p.headerSize + tp.length + kp.length, bb.length);
        return o;
    }

    private static byte[] writeCfg(Pkg p, Typ t, Cfg c) {
        int cnt = t.total;
        int hs = 20 + c.cfg.length;
        int entriesStart = hs + cnt * 4;
        ByteArrayOutputStream eb = new ByteArrayOutputStream();
        int[] offs = new int[cnt];
        Arrays.fill(offs, -1);
        int[] idxs = new int[c.entries.size()];
        int k = 0;
        for (Integer kk : c.entries.keySet()) idxs[k++] = kk;
        Arrays.sort(idxs);
        for (int idx : idxs) {
            int rel = entriesStart + eb.size();
            int pad = (4 - (rel & 3)) & 3;
            for (int z = 0; z < pad; z++) eb.write(0);
            rel += pad;
            offs[idx] = rel;
            Ent e = c.entries.get(idx);
            int sz = 8 + (e.extra != null ? e.extra.length : 0);
            w16(eb, sz); w16(eb, e.flags); w32(eb, e.key);
            if (e.extra != null) eb.write(e.extra, 0, e.extra.length);
            if (e.complex) {
                w32(eb, (int) e.parent);
                w32(eb, e.maps == null ? 0 : e.maps.size());
                if (e.maps != null)
                    for (MapIt m : e.maps) { w32(eb, (int) m.ident); writeVal(eb, m.v); }
            } else writeVal(eb, e.val);
        }
        byte[] entb = eb.toByteArray();
        int size = entriesStart + entb.length;
        byte[] o = new byte[size];
        putShort(o, 0, 0x0201);
        putShort(o, 2, hs);
        putInt(o, 4, size);
        o[8] = (byte) ((t.id - p.typeIdOffset) & 0xFF);
        o[9] = 0;
        putShort(o, 10, 0);
        putInt(o, 12, cnt);
        putInt(o, 16, entriesStart);
        System.arraycopy(c.cfg, 0, o, 20, c.cfg.length);
        for (int i = 0; i < cnt; i++) putInt(o, hs + i * 4, offs[i]);
        System.arraycopy(entb, 0, o, entriesStart, entb.length);
        return o;
    }

    private static void writeVal(ByteArrayOutputStream o, RV v) {
        w16(o, 8);
        if (v == null) { o.write(0); o.write(0); w32(o, 0); return; }
        o.write(v.res0 & 0xFF);
        o.write(v.dataType & 0xFF);
        w32(o, (int) v.data);
    }

    private static void w16(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF); o.write((v >>> 8) & 0xFF);
    }

    private static void w32(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF); o.write((v >>> 8) & 0xFF);
        o.write((v >>> 16) & 0xFF); o.write((v >>> 24) & 0xFF);
    }

    private static byte[] writePool(SP sp) {
        int n = sp.raw.size();
        int[] offs = new int[n];
        int cur = 0;
        for (int i = 0; i < n; i++) {
            int pad = (4 - (cur & 3)) & 3;
            cur += pad;
            offs[i] = cur;
            cur += sp.raw.get(i).length;
        }
        int stringsStart = 28 + n * 4;
        int stylesStart = 0;
        int total = stringsStart + cur;
        if (sp.stylesRaw != null) {
            int pad = (4 - (total & 3)) & 3;
            total += pad;
            stylesStart = total;
            total += sp.stylesRaw.length;
        }
        byte[] o = new byte[total];
        putShort(o, 0, RES_STRING_POOL_TYPE);
        putShort(o, 2, 28);
        putInt(o, 4, total);
        putInt(o, 8, n);
        putInt(o, 12, 0);
        putInt(o, 16, sp.utf8 ? 0x100 : 0);
        putInt(o, 20, stringsStart);
        putInt(o, 24, stylesStart);
        for (int i = 0; i < n; i++) putInt(o, 28 + i * 4, offs[i]);
        int p2 = stringsStart;
        for (int i = 0; i < n; i++) {
            int pad = (4 - ((p2 - stringsStart) & 3)) & 3;
            p2 += pad;
            byte[] s = sp.raw.get(i);
            System.arraycopy(s, 0, o, p2, s.length);
            p2 += s.length;
        }
        if (sp.stylesRaw != null)
            System.arraycopy(sp.stylesRaw, 0, o, stylesStart, sp.stylesRaw.length);
        return o;
    }

    // ================================================================
    // MERGED APK BUILDER (raw-copy ZIP writer + integrity self-check)
    // ================================================================

    static class RawEntry {
        String name; int method; long crc, csize, usize, localOff;
    }

    private static void buildMergedApk(File baseApk, List<NewEntry> adds, File out,
                                       Set<String> omit, Callback cb) throws IOException {
        List<RawEntry> bases = parseCentralDirectory(baseApk);
        RandomAccessFile raf = new RandomAccessFile(baseApk, "r");
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(out), 1 << 17);
        try {
            int dosTime = dosDateTime();
            long offset = 0;
            int totalE = bases.size() + adds.size();
            int doneN = 0;
            List<long[]> cd = new ArrayList<>();
            List<String> names = new ArrayList<>();
            byte[] lh = new byte[30];
            byte[] lhdr = new byte[30];

            for (RawEntry r : bases) {
                if (cb.isCancelled()) throw new IOException("CANCELLED");
                if (omit.contains(r.name)) continue;
                raf.seek(r.localOff);
                raf.readFully(lhdr);
                if ((lhdr[0] & 0xFF) != 0x50 || (lhdr[1] & 0xFF) != 0x4B
                        || (lhdr[2] & 0xFF) != 0x03 || (lhdr[3] & 0xFF) != 0x04)
                    throw new IOException("Corrupted local header: " + r.name);
                int nameLen = (lhdr[26] & 0xFF) | ((lhdr[27] & 0xFF) << 8);
                int extraLen = (lhdr[28] & 0xFF) | ((lhdr[29] & 0xFF) << 8);
                long dataOff = r.localOff + 30 + nameLen + extraLen;
                byte[] nb = r.name.getBytes("UTF-8");
                int extraW = 0;
                if (r.method == 0) {
                    long align = r.name.endsWith(".so") ? 16384 : 4;
                    long dataStart = offset + 30 + nb.length;
                    extraW = (int) ((align - (dataStart % align)) % align);
                }
                writeLocal(bos, lh, nb, extraW, r.method, dosTime, r.crc, r.csize, r.usize);
                if (extraW > 0) bos.write(new byte[extraW]);
                copyRaw(raf, dataOff, r.csize, bos);
                cd.add(new long[]{r.method, r.crc, r.csize, r.usize, nb.length, offset});
                names.add(r.name);
                offset += 30 + nb.length + extraW + r.csize;
                doneN++;
                if (doneN % 300 == 0)
                    cb.onProgress(30 + (int) ((long) doneN * 25L / Math.max(1, totalE)));
            }

            for (NewEntry ne : adds) {
                if (cb.isCancelled()) throw new IOException("CANCELLED");
                byte[] nb = ne.name.getBytes("UTF-8");
                CRC32 c = new CRC32();
                c.update(ne.data);
                long crc = c.getValue(), usize = ne.data.length;
                int method;
                byte[] payload;
                if (ne.stored) {
                    method = 0; payload = ne.data;
                } else {
                    method = 8;
                    ByteArrayOutputStream co = new ByteArrayOutputStream(65536);
                    Deflater def = new Deflater(Deflater.BEST_SPEED, true);
                    java.util.zip.DeflaterOutputStream ds =
                            new java.util.zip.DeflaterOutputStream(co, def, 1 << 16);
                    ds.write(ne.data); ds.finish(); ds.close(); def.end();
                    payload = co.toByteArray();
                }
                long csize = payload.length;
                int extraW = 0;
                if (method == 0 && ne.align > 0) {
                    long dataStart = offset + 30 + nb.length;
                    extraW = (int) ((ne.align - (dataStart % ne.align)) % ne.align);
                }
                writeLocal(bos, lh, nb, extraW, method, dosTime, crc, csize, usize);
                if (extraW > 0) bos.write(new byte[extraW]);
                bos.write(payload);
                cd.add(new long[]{method, crc, csize, usize, nb.length, offset});
                names.add(ne.name);
                offset += 30 + nb.length + extraW + csize;
                doneN++;
                cb.onProgress(30 + (int) ((long) doneN * 25L / Math.max(1, totalE)));
            }
            if (offset > 0xFFFFFFFEL) throw new IOException("Merged APK exceeds 4GB limit.");
            bos.flush();

            long cdStart = offset;
            long cdSize = 0;
            for (int i = 0; i < cd.size(); i++) {
                long[] rec = cd.get(i);
                byte[] nb = names.get(i).getBytes("UTF-8");
                byte[] ch = new byte[46];
                putInt(ch, 0, 0x02014b50);
                putShort(ch, 4, 20); putShort(ch, 6, 20);
                putShort(ch, 8, 0x0800); putShort(ch, 10, (int) rec[0]);
                putShort(ch, 12, dosTime & 0xFFFF);
                putShort(ch, 14, (dosTime >>> 16) & 0xFFFF);
                putInt(ch, 16, (int) rec[1]);
                putInt(ch, 20, (int) rec[2]);
                putInt(ch, 24, (int) rec[3]);
                putShort(ch, 28, (int) rec[4]);
                putShort(ch, 30, 0); putShort(ch, 32, 0);
                putShort(ch, 34, 0); putShort(ch, 36, 0);
                putInt(ch, 38, 0);
                putInt(ch, 42, (int) rec[5]);
                bos.write(ch); bos.write(nb);
                cdSize += 46 + nb.length;
            }
            bos.flush();

            int cnt = cd.size();
            boolean z64 = cnt > 0xFFFF || cdStart > 0xFFFFFFFFL || cdSize > 0xFFFFFFFFL;
            if (z64) {
                byte[] z = new byte[56];
                putInt(z, 0, 0x06064b50);
                putInt(z, 4, 44);
                putShort(z, 12, 45); putShort(z, 14, 45);
                putInt(z, 16, 0); putInt(z, 20, 0);
                putLong(z, 24, cnt); putLong(z, 32, cnt);
                putLong(z, 40, cdSize); putLong(z, 48, cdStart);
                bos.write(z);
                byte[] loc = new byte[20];
                putInt(loc, 0, 0x07064b50);
                putInt(loc, 4, 0);
                putLong(loc, 8, cdStart + cdSize);
                putInt(loc, 16, 1);
                bos.write(loc);
            }
            byte[] eocd = new byte[22];
            putInt(eocd, 0, 0x06054b50);
            putShort(eocd, 4, 0); putShort(eocd, 6, 0);
            putShort(eocd, 8, cnt > 0xFFFF ? 0xFFFF : cnt);
            putShort(eocd, 10, cnt > 0xFFFF ? 0xFFFF : cnt);
            putInt(eocd, 12, cdSize > 0xFFFFFFFFL ? -1 : (int) cdSize);
            putInt(eocd, 16, cdStart > 0xFFFFFFFFL ? -1 : (int) cdStart);
            putShort(eocd, 20, 0);
            bos.write(eocd);
            bos.flush();
        } finally {
            try { raf.close(); } catch (IOException ignored) {}
            try { bos.close(); } catch (IOException ignored) {}
        }

        // ---- integrity self-check: full CRC pass over the built APK ----
        int verified = 0;
        ZipFile vf = new ZipFile(out);
        try {
            Enumeration<? extends ZipEntry> en = vf.entries();
            byte[] buf = new byte[1 << 16];
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                CRC32 cc = new CRC32();
                InputStream is2 = vf.getInputStream(ze);
                if (is2 == null) throw new IOException("Self-check unreadable: " + ze.getName());
                int rr;
                long cnt2 = 0;
                while ((rr = is2.read(buf)) > 0) { cc.update(buf, 0, rr); cnt2 += rr; }
                is2.close();
                if (cnt2 != ze.getSize() || cc.getValue() != ze.getCrc())
                    throw new IOException("Self-check integrity failed: " + ze.getName());
                verified++;
            }
        } finally {
            vf.close();
        }
        cb.onLog("Self-check: " + verified + " entries verified OK.");
    }

    private static List<RawEntry> parseCentralDirectory(File f) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(f, "r");
        try {
            long len = raf.length();
            if (len < 22) throw new IOException("ZIP too small.");
            int tailLen = (int) Math.min(len, 65598L);
            byte[] tail = new byte[tailLen];
            raf.seek(len - tailLen);
            raf.readFully(tail);
            int e = -1;
            for (int i = tail.length - 22; i >= 0; i--)
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B
                        && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) { e = i; break; }
            if (e < 0) throw new IOException("ZIP end marker not found.");
            long cdSize = rl(tail, e + 12);
            long cdOff = rl(tail, e + 16);
            int count = u16(tail, e + 10);
            if (count == 0xFFFF || cdOff == 0xFFFFFFFFL || cdSize == 0xFFFFFFFFL)
                throw new IOException("ZIP64 base APK not supported for merge.");
            List<RawEntry> out = new ArrayList<>();
            long pos = cdOff;
            byte[] h = new byte[46];
            for (int i = 0; i < count && pos + 46 <= len; i++) {
                raf.seek(pos);
                raf.readFully(h);
                if ((h[0] & 0xFF) != 0x50 || (h[1] & 0xFF) != 0x4B
                        || (h[2] & 0xFF) != 0x01 || (h[3] & 0xFF) != 0x02) break;
                RawEntry r = new RawEntry();
                r.method = u16(h, 10);
                r.crc = rl(h, 16);
                r.csize = rl(h, 20);
                r.usize = rl(h, 24);
                int nameLen = u16(h, 28);
                int extraLen = u16(h, 30);
                int commLen = u16(h, 32);
                r.localOff = rl(h, 42);
                byte[] nb = new byte[nameLen];
                raf.seek(pos + 46);
                raf.readFully(nb);
                r.name = new String(nb, "UTF-8");
                out.add(r);
                pos += 46 + nameLen + extraLen + commLen;
            }
            if (out.isEmpty()) throw new IOException("Base APK central directory empty.");
            return out;
        } finally {
            raf.close();
        }
    }

    private static void writeLocal(OutputStream o, byte[] lh, byte[] nb, int extraLen,
                                   int method, int dosTime, long crc,
                                   long csize, long usize) throws IOException {
        Arrays.fill(lh, (byte) 0);
        putInt(lh, 0, 0x04034b50);
        putShort(lh, 4, 20);
        putShort(lh, 6, 0x0800);
        putShort(lh, 8, method);
        putShort(lh, 10, dosTime & 0xFFFF);
        putShort(lh, 12, (dosTime >>> 16) & 0xFFFF);
        putInt(lh, 14, (int) crc);
        putInt(lh, 18, (int) csize);
        putInt(lh, 22, (int) usize);
        putShort(lh, 26, nb.length);
        putShort(lh, 28, extraLen);
        o.write(lh);
        o.write(nb);
    }

    private static void copyRaw(RandomAccessFile raf, long off, long len,
                                OutputStream o) throws IOException {
        raf.seek(off);
        byte[] b = new byte[1 << 16];
        long left = len;
        while (left > 0) {
            int k = raf.read(b, 0, (int) Math.min(b.length, left));
            if (k < 0) throw new IOException("Unexpected EOF in APK data.");
            o.write(b, 0, k);
            left -= k;
        }
    }

    private static long rl(byte[] b, int o) {
        return (b[o] & 0xFFL) | ((b[o + 1] & 0xFFL) << 8)
                | ((b[o + 2] & 0xFFL) << 16) | ((b[o + 3] & 0xFFL) << 24);
    }

    private static void putLong(byte[] b, int o, long v) {
        putInt(b, o, (int) (v & 0xFFFFFFFFL));
        putInt(b, o + 4, (int) ((v >>> 32) & 0xFFFFFFFFL));
    }

    private static int dosDateTime() {
        java.util.Calendar c = java.util.Calendar.getInstance();
        int year = Math.max(0, c.get(java.util.Calendar.YEAR) - 1980);
        return (year << 25) | ((c.get(java.util.Calendar.MONTH) + 1) << 21)
                | (c.get(java.util.Calendar.DAY_OF_MONTH) << 16)
                | (c.get(java.util.Calendar.HOUR_OF_DAY) << 11)
                | (c.get(java.util.Calendar.MINUTE) << 5)
                | (c.get(java.util.Calendar.SECOND) >> 1);
    }

    // ================================================================
    // SIGNATURE DETECTION
    // ================================================================

    private static boolean isSignatureEntry(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String u = name.toUpperCase(Locale.US);
        return u.endsWith(".SF") || u.endsWith(".RSA")
                || u.endsWith(".DSA") || u.endsWith(".EC")
                || u.equals("META-INF/MANIFEST.MF");
    }

    private static boolean hasV2orV3Block(File apk) {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(apk, "r");
            long len = raf.length();
            if (len < 66) return false;
            int tailLen = (int) Math.min(len, 65598L);
            byte[] tail = new byte[tailLen];
            raf.seek(len - tailLen);
            raf.readFully(tail);
            int e = -1;
            for (int i = tail.length - 22; i >= 0; i--)
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B
                        && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) { e = i; break; }
            if (e < 0) return false;
            long cdStart = rl(tail, e + 16);
            if (cdStart < 40 || cdStart + 24 > len) return false;
            byte[] magic = new byte[16];
            raf.seek(cdStart - 16);
            raf.readFully(magic);
            byte[] expect = "APK Sig Block 42".getBytes("UTF-8");
            return Arrays.equals(magic, expect);
        } catch (Exception e2) {
            return false;
        } finally {
            try { if (raf != null) raf.close(); } catch (IOException ignored) {}
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
                    "Storage not writable - grant 'All files access' to AntiAdapt M.");
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
                    || n.startsWith("signed_") || n.startsWith("arc_")
                    || n.startsWith("inst_") || n.startsWith("merged_")
                    || n.startsWith("bundle_")))
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

    private static int u16(byte[] d, int p) {
        return (d[p] & 0xFF) | ((d[p + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] d, int p) {
        return (d[p] & 0xFFL) | ((d[p + 1] & 0xFFL) << 8)
                | ((d[p + 2] & 0xFFL) << 16) | ((d[p + 3] & 0xFFL) << 24);
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) v; b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16); b[off + 3] = (byte) (v >>> 24);
    }

    private static void putShort(byte[] b, int off, int v) {
        b[off] = (byte) v; b[off + 1] = (byte) (v >>> 8);
    }
    
    // ================================================================
    // VALIDATION & EXTRACTION HELPERS
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
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                copyStream(zf.getInputStream(mj), bo);
                try {
                    pkg = new JSONObject(new String(bo.toByteArray(), "UTF-8"))
                            .getString("package_name");
                } catch (Exception ignored) {}
            }
            if (pkg == null) {
                cb.onLog("OBB found but package name unknown - OBB not copied.");
                return;
            }
            File dir = new File(Environment.getExternalStorageDirectory(), "Android/obb/" + pkg);
            if (!(dir.exists() || dir.mkdirs())) {
                cb.onLog("OBB skipped (cannot write Android/obb).");
                return;
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
}
