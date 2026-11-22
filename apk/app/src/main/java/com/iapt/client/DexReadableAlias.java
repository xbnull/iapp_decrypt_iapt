package com.iapt.client;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/**
 * Client-side preparation for the static DEX/source restore entry.
 *
 * The server endpoint stays unchanged.  The client packages src/res plus only
 * DEX-bearing files from project/apk/lib.  Before upload it rewrites unreadable
 * application class descriptors to deterministic same-length aliases, so the
 * returned DEX remains structurally valid while unresolved source references
 * become readable (a1, b1, ... with padding where the DEX string length must be
 * preserved).
 */
final class DexReadableAlias {
    private DexReadableAlias() {}

    static final class BuildResult {
        final File zip;
        final int sourceFiles;
        final int dexContainers;
        final int renamedClasses;
        BuildResult(File zip, int sourceFiles, int dexContainers, int renamedClasses) {
            this.zip = zip;
            this.sourceFiles = sourceFiles;
            this.dexContainers = dexContainers;
            this.renamedClasses = renamedClasses;
        }
    }

    private static final Set<String> TEXT_EXTS = new HashSet<String>(Arrays.asList(
            ".iyu", ".myu", ".mjava", ".ijava", ".java", ".mlua", ".lua",
            ".mjs", ".js", ".txt", ".xml", ".json", ".properties", ".ini"));

    private static final String[] EXCLUDED_PREFIXES = new String[]{
            "Ljava/", "Ljavax/", "Landroid/", "Landroidx/", "Ldalvik/",
            "Lkotlin/", "Lkotlinx/", "Lorg/json/", "Lorg/apache/",
            "Lcom/google/", "Lcom/iapp/app/", "LiApEcPro/", "LDestruction0/"
    };

    static int countDexContainers(File apkLibDir) {
        if (apkLibDir == null || !apkLibDir.isDirectory()) return 0;
        int count = 0;
        ArrayDeque<File> q = new ArrayDeque<File>();
        q.add(apkLibDir);
        while (!q.isEmpty()) {
            File d = q.removeFirst();
            File[] arr = d.listFiles();
            if (arr == null) continue;
            for (File f : arr) {
                if (f == null) continue;
                if (f.isDirectory()) q.addLast(f);
                else if (isDexContainer(f)) count++;
            }
        }
        return count;
    }

    static BuildResult buildProjectZip(File projectDir, boolean includeRes) throws Exception {
        if (projectDir == null || !projectDir.isDirectory()) throw new IOException("项目目录不存在");
        File srcDir = new File(projectDir, "src");
        if (!srcDir.isDirectory()) throw new IOException("项目目录下没有 src");
        File resDir = new File(projectDir, "res");
        if (includeRes && !resDir.isDirectory()) throw new IOException("项目目录下没有 res");
        File apkLibDir = new File(new File(projectDir, "apk"), "lib");
        List<File> containers = listDexContainers(apkLibDir);
        if (containers.isEmpty()) throw new IOException("项目 apk/lib 下没有找到 DEX/APK/ZIP/JAR");

        LinkedHashSet<String> descriptors = new LinkedHashSet<String>();
        int dexCount = 0;
        for (File f : containers) {
            DexScan scan = scanContainer(f);
            descriptors.addAll(scan.descriptors);
            dexCount += scan.dexCount;
        }
        LinkedHashMap<String, String> aliases = buildAliasMap(descriptors);

        File out = File.createTempFile("iapt_dex_restore_project_", ".zip");
        ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out), 1024 * 1024));
        int[] sourceCount = new int[]{0};
        try {
            zipTree(srcDir, srcDir, "src/", zos, aliases, true, sourceCount);
            if (includeRes) zipTree(resDir, resDir, "res/", zos, aliases, false, sourceCount);

            String[] metadata = new String[]{"old_iapp_report.json", "project_metadata.txt"};
            for (String name : metadata) {
                File f = new File(projectDir, name);
                if (f.isFile()) writeFileEntry(zos, name, readAll(f));
            }

            for (File f : containers) {
                String rel = apkLibDir.toURI().relativize(f.toURI()).getPath();
                if (rel == null || rel.length() == 0 || rel.contains("../")) continue;
                byte[] raw = readAll(f);
                byte[] patched;
                if (looksDex(raw)) patched = patchDex(raw, aliases);
                else patched = patchArchive(raw, aliases);
                writeFileEntry(zos, "apk/lib/" + rel.replace('\\', '/'), patched);
            }

            StringBuilder manifest = new StringBuilder();
            manifest.append("iAPT client DEX/source restore package\n");
            manifest.append("source_files=").append(sourceCount[0]).append('\n');
            manifest.append("dex_containers=").append(containers.size()).append('\n');
            manifest.append("dex_files=").append(dexCount).append('\n');
            manifest.append("readable_alias_classes=").append(aliases.size()).append('\n');
            manifest.append("policy=direct-return-backfill; deterministic-constant-fold; unresolved-class-readable-alias\n");
            writeFileEntry(zos, "iapt_project_source_manifest.txt", manifest.toString().getBytes("UTF-8"));

            if (!aliases.isEmpty()) {
                StringBuilder map = new StringBuilder();
                map.append("# iAPT readable DEX class alias map\n");
                for (Map.Entry<String, String> e : aliases.entrySet()) {
                    map.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
                    map.append(descriptorToDot(e.getKey())).append(" -> ")
                            .append(descriptorToDot(e.getValue())).append('\n');
                }
                writeFileEntry(zos, "dex_readable_alias_map.txt", map.toString().getBytes("UTF-8"));
            }
        } finally {
            try { zos.close(); } catch (Exception ignored) {}
        }
        if (sourceCount[0] <= 0) {
            try { out.delete(); } catch (Exception ignored) {}
            throw new IOException("项目源码为空");
        }
        return new BuildResult(out, sourceCount[0], containers.size(), aliases.size());
    }

    private static List<File> listDexContainers(File root) {
        ArrayList<File> out = new ArrayList<File>();
        if (root == null || !root.isDirectory()) return out;
        ArrayDeque<File> q = new ArrayDeque<File>();
        q.add(root);
        while (!q.isEmpty()) {
            File d = q.removeFirst();
            File[] arr = d.listFiles();
            if (arr == null) continue;
            Arrays.sort(arr, new Comparator<File>() {
                public int compare(File a, File b) { return a.getAbsolutePath().compareToIgnoreCase(b.getAbsolutePath()); }
            });
            for (File f : arr) {
                if (f == null) continue;
                if (f.isDirectory()) q.addLast(f);
                else if (isDexContainer(f)) out.add(f);
            }
        }
        return out;
    }

    private static boolean isDexContainer(File f) {
        if (f == null || !f.isFile()) return false;
        String n = f.getName().toLowerCase(Locale.US);
        if (!(n.endsWith(".dex") || n.endsWith(".apk") || n.endsWith(".zip") || n.endsWith(".jar"))) return false;
        try {
            FileInputStream in = new FileInputStream(f);
            byte[] h = new byte[4];
            int r = in.read(h);
            in.close();
            if (r == 4 && h[0] == 'd' && h[1] == 'e' && h[2] == 'x' && h[3] == '\n') return true;
            return n.endsWith(".apk") || n.endsWith(".zip") || n.endsWith(".jar");
        } catch (Exception e) { return false; }
    }

    private static final class DexScan {
        final LinkedHashSet<String> descriptors = new LinkedHashSet<String>();
        int dexCount;
    }

    private static DexScan scanContainer(File f) throws Exception {
        byte[] raw = readAll(f);
        DexScan out = new DexScan();
        if (looksDex(raw)) {
            out.descriptors.addAll(readClassDescriptors(raw));
            out.dexCount = 1;
            return out;
        }
        if (!looksZip(raw)) return out;
        ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(raw));
        try {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                byte[] data = readEntry(zin);
                if (looksDex(data)) {
                    out.descriptors.addAll(readClassDescriptors(data));
                    out.dexCount++;
                }
            }
        } finally { try { zin.close(); } catch (Exception ignored) {} }
        return out;
    }

    private static LinkedHashMap<String, String> buildAliasMap(Collection<String> descriptors) {
        LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
        HashSet<String> used = new HashSet<String>(descriptors);
        int seq = 0;
        for (String d : descriptors) {
            if (!shouldRename(d)) continue;
            String alias;
            do { alias = makeAliasDescriptor(d, seq++); } while (used.contains(alias));
            used.add(alias);
            map.put(d, alias);
        }
        return map;
    }

    private static boolean shouldRename(String d) {
        if (d == null || d.length() < 3 || d.charAt(0) != 'L' || d.charAt(d.length() - 1) != ';') return false;
        for (String p : EXCLUDED_PREFIXES) if (d.startsWith(p)) return false;
        String body = d.substring(1, d.length() - 1);
        String simple = body.substring(body.lastIndexOf('/') + 1);
        if (simple.equals("R") || simple.startsWith("R$") || simple.equals("BuildConfig")) return false;
        String base = simple;
        int dollar = base.indexOf('$');
        if (dollar > 0) base = base.substring(0, dollar);
        if (base.length() <= 3) return true;
        boolean ascii = base.matches("[A-Za-z_$][A-Za-z0-9_$]*");
        if (!ascii) return true;
        String low = base.toLowerCase(Locale.US);
        boolean vowel = low.indexOf('a') >= 0 || low.indexOf('e') >= 0 || low.indexOf('i') >= 0 || low.indexOf('o') >= 0 || low.indexOf('u') >= 0;
        if (!vowel && base.length() <= 10) return true;
        if (base.matches("[A-Za-z]{1,4}[0-9]{1,5}")) return true;
        return false;
    }

    private static String makeAliasDescriptor(String original, int seq) {
        int bodyLen = original.length() - 2;
        String body;
        if (bodyLen >= 4) body = "r/" + fitIdentifier(aliasToken(seq), bodyLen - 2);
        else body = fitIdentifier(aliasToken(seq), bodyLen);
        return "L" + body + ";";
    }

    private static String aliasToken(int seq) {
        int letter = seq % 26;
        int group = seq / 26 + 1;
        return String.valueOf((char)('a' + letter)) + Integer.toString(group, 36);
    }

    private static String fitIdentifier(String seed, int len) {
        if (len <= 0) return "";
        StringBuilder b = new StringBuilder();
        if (seed == null || seed.length() == 0 || !Character.isLetter(seed.charAt(0))) b.append('a');
        if (seed != null) {
            for (int i = 0; i < seed.length() && b.length() < len; i++) {
                char c = seed.charAt(i);
                if (b.length() == 0) b.append(Character.isLetter(c) ? c : 'a');
                else b.append(Character.isLetterOrDigit(c) || c == '_' ? c : '_');
            }
        }
        while (b.length() < len) b.append('_');
        if (b.length() > len) b.setLength(len);
        return b.toString();
    }

    private static void zipTree(File root, File cur, String prefix, ZipOutputStream zos,
                                Map<String, String> aliases, boolean source, int[] count) throws Exception {
        File[] arr = cur.listFiles();
        if (arr == null) return;
        Arrays.sort(arr, new Comparator<File>() {
            public int compare(File a, File b) { return a.getName().compareToIgnoreCase(b.getName()); }
        });
        for (File f : arr) {
            if (f == null) continue;
            if (f.isDirectory()) {
                zipTree(root, f, prefix, zos, aliases, source, count);
                continue;
            }
            String rel = root.toURI().relativize(f.toURI()).getPath();
            if (rel == null || rel.length() == 0 || rel.contains("../")) continue;
            byte[] data = readAll(f);
            if (isTextName(f.getName())) data = rewriteText(data, aliases);
            writeFileEntry(zos, prefix + rel.replace('\\', '/'), data);
            if (source) count[0]++;
        }
    }

    private static boolean isTextName(String name) {
        String low = name == null ? "" : name.toLowerCase(Locale.US);
        for (String ext : TEXT_EXTS) if (low.endsWith(ext)) return true;
        return false;
    }

    private static byte[] rewriteText(byte[] data, Map<String, String> aliases) {
        if (aliases.isEmpty() || data == null || data.length == 0) return data;
        String[] encs = new String[]{"UTF-8", "GB18030", "GBK"};
        for (String enc : encs) {
            try {
                CharsetDecoder dec = Charset.forName(enc).newDecoder();
                dec.onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
                String s = dec.decode(java.nio.ByteBuffer.wrap(data)).toString();
                String out = rewriteString(s, aliases);
                return out.getBytes(enc);
            } catch (Exception ignored) {}
        }
        return data;
    }

    private static String rewriteString(String s, Map<String, String> aliases) {
        String out = s;
        for (Map.Entry<String, String> e : aliases.entrySet()) {
            String od = e.getKey(), nd = e.getValue();
            String os = od.substring(1, od.length() - 1);
            String ns = nd.substring(1, nd.length() - 1);
            out = out.replace(od, nd);
            out = out.replace(os, ns);
            out = out.replace(os.replace('/', '.'), ns.replace('/', '.'));
        }
        return out;
    }

    private static byte[] patchArchive(byte[] raw, Map<String, String> aliases) throws Exception {
        if (!looksZip(raw)) return raw;
        ByteArrayOutputStream bout = new ByteArrayOutputStream(Math.max(4096, raw.length));
        ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(raw));
        ZipOutputStream zout = new ZipOutputStream(new BufferedOutputStream(bout));
        try {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                ZipEntry ne = new ZipEntry(e.getName());
                try { ne.setTime(e.getTime()); } catch (Exception ignored) {}
                zout.putNextEntry(ne);
                if (!e.isDirectory()) {
                    byte[] data = readEntry(zin);
                    if (looksDex(data)) data = patchDex(data, aliases);
                    zout.write(data);
                }
                zout.closeEntry();
            }
        } finally {
            try { zin.close(); } catch (Exception ignored) {}
            try { zout.close(); } catch (Exception ignored) {}
        }
        return bout.toByteArray();
    }

    private static byte[] patchDex(byte[] input, Map<String, String> aliases) throws Exception {
        if (!looksDex(input) || aliases.isEmpty()) return input;
        byte[] out = input.clone();
        int stringCount = u32(out, 0x38);
        int stringOff = u32(out, 0x3c);
        for (int i = 0; i < stringCount; i++) {
            int off = u32(out, stringOff + i * 4);
            StringItem item = readStringItem(out, off);
            if (item == null) continue;
            String replacement = aliases.get(item.value);
            if (replacement == null) {
                for (Map.Entry<String, String> e : aliases.entrySet()) {
                    String os = e.getKey().substring(1, e.getKey().length() - 1);
                    String ns = e.getValue().substring(1, e.getValue().length() - 1);
                    if (item.value.equals(os)) { replacement = ns; break; }
                    if (item.value.equals(os.replace('/', '.'))) { replacement = ns.replace('/', '.'); break; }
                }
            }
            if (replacement == null) continue;
            byte[] oldBytes = item.value.getBytes("UTF-8");
            byte[] newBytes = replacement.getBytes("UTF-8");
            if (oldBytes.length != newBytes.length || item.utf16Length != replacement.length()) continue;
            System.arraycopy(newBytes, 0, out, item.dataOffset, newBytes.length);
        }
        updateDexHashes(out);
        return out;
    }

    private static LinkedHashSet<String> readClassDescriptors(byte[] dex) {
        LinkedHashSet<String> out = new LinkedHashSet<String>();
        if (!looksDex(dex) || dex.length < 112) return out;
        try {
            int stringCount = u32(dex, 0x38), stringOff = u32(dex, 0x3c);
            int typeCount = u32(dex, 0x40), typeOff = u32(dex, 0x44);
            int classCount = u32(dex, 0x60), classOff = u32(dex, 0x64);
            String[] strings = new String[stringCount];
            for (int i = 0; i < stringCount; i++) {
                int off = u32(dex, stringOff + i * 4);
                StringItem item = readStringItem(dex, off);
                strings[i] = item == null ? null : item.value;
            }
            int[] types = new int[typeCount];
            for (int i = 0; i < typeCount; i++) types[i] = u32(dex, typeOff + i * 4);
            for (int i = 0; i < classCount; i++) {
                int classIdx = u32(dex, classOff + i * 32);
                if (classIdx < 0 || classIdx >= types.length) continue;
                int sidx = types[classIdx];
                if (sidx >= 0 && sidx < strings.length) {
                    String d = strings[sidx];
                    if (d != null && d.startsWith("L") && d.endsWith(";")) out.add(d);
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    private static final class StringItem {
        final String value; final int utf16Length; final int dataOffset;
        StringItem(String value, int utf16Length, int dataOffset) {
            this.value = value; this.utf16Length = utf16Length; this.dataOffset = dataOffset;
        }
    }

    private static StringItem readStringItem(byte[] data, int off) throws Exception {
        if (off < 0 || off >= data.length) return null;
        int[] r = readUleb(data, off);
        int len = r[0], p = r[1], end = p;
        while (end < data.length && data[end] != 0) end++;
        if (end >= data.length) return null;
        String s = new String(data, p, end - p, "UTF-8");
        return new StringItem(s, len, p);
    }

    private static int[] readUleb(byte[] data, int off) throws IOException {
        int result = 0, shift = 0, p = off;
        for (int i = 0; i < 5; i++) {
            if (p >= data.length) throw new EOFException();
            int b = data[p++] & 0xff;
            result |= (b & 0x7f) << shift;
            if ((b & 0x80) == 0) return new int[]{result, p};
            shift += 7;
        }
        throw new IOException("bad uleb128");
    }

    private static void updateDexHashes(byte[] dex) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(dex, 32, dex.length - 32);
        byte[] sig = sha1.digest();
        System.arraycopy(sig, 0, dex, 12, 20);
        Adler32 adler = new Adler32();
        adler.update(dex, 12, dex.length - 12);
        long v = adler.getValue();
        dex[8] = (byte)(v & 0xff);
        dex[9] = (byte)((v >>> 8) & 0xff);
        dex[10] = (byte)((v >>> 16) & 0xff);
        dex[11] = (byte)((v >>> 24) & 0xff);
    }

    private static int u32(byte[] b, int off) {
        if (off < 0 || off + 4 > b.length) return -1;
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8) |
                ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static boolean looksDex(byte[] b) {
        return b != null && b.length >= 8 && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n';
    }

    private static boolean looksZip(byte[] b) {
        return b != null && b.length >= 4 && b[0] == 'P' && b[1] == 'K';
    }

    private static String descriptorToDot(String d) {
        if (d == null || d.length() < 2) return String.valueOf(d);
        String s = d;
        if (s.startsWith("L")) s = s.substring(1);
        if (s.endsWith(";")) s = s.substring(0, s.length() - 1);
        return s.replace('/', '.');
    }

    private static byte[] readAll(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int)Math.min(Integer.MAX_VALUE, Math.max(4096L, f.length())));
            byte[] buf = new byte[1024 * 1024];
            int n;
            while ((n = in.read(buf)) >= 0) { if (n > 0) out.write(buf, 0, n); }
            return out.toByteArray();
        } finally { try { in.close(); } catch (Exception ignored) {} }
    }

    private static byte[] readEntry(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[256 * 1024];
        int n;
        while ((n = in.read(buf)) >= 0) { if (n > 0) out.write(buf, 0, n); }
        return out.toByteArray();
    }

    private static void writeFileEntry(ZipOutputStream zos, String name, byte[] data) throws IOException {
        String safe = name.replace('\\', '/');
        while (safe.startsWith("/")) safe = safe.substring(1);
        if (safe.length() == 0 || safe.contains("../")) return;
        ZipEntry e = new ZipEntry(safe);
        zos.putNextEntry(e);
        zos.write(data);
        zos.closeEntry();
    }
}
