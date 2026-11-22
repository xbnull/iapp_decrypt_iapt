package com.iapt.client.hook;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;

public class IaptHookProvider extends ContentProvider {
    public static final String AUTH = "com.iapt.client.hook";
    static final String SP = "iapt_client";
    static final String CONFIG_SP = "iapt_hook_config";
    static final int MAX_EVENTS = 160;
    static final int MAX_CACHE_CHARS = 262144;
    static final int MAX_LINE_CHARS = 8192;

    public boolean onCreate() { return true; }

    public Uri insert(Uri uri, ContentValues values) {
        try {
            Context c = getContext();
            if (c == null || values == null) return null;
            String pkg = values.getAsString("package_name");
            if (pkg == null || pkg.length() == 0) return null;

            if (!callerMatches(c, pkg)) return null;

            String path = uri == null ? "" : String.valueOf(uri.getPath());
            if ((path != null && path.indexOf("dump") >= 0) || values.containsKey("dump_text")) {
                return writeDump(c, pkg, values);
            }

            if (!shouldStoreEvent(str(values, "method_name"), str(values, "stage"),
                    str(values, "result_text"))) return null;

            SharedPreferences sp = c.getSharedPreferences(SP, 0);
            JSONObject o = new JSONObject();
            o.put("package_name", pkg);
            o.put("method_name", str(values, "method_name"));
            o.put("stage", str(values, "stage"));
            o.put("args_json", str(values, "args_json"));
            o.put("result_text", str(values, "result_text"));
            o.put("result_b64", str(values, "result_b64"));
            o.put("created_at", System.currentTimeMillis());
            appendEvent(sp, o.toString());
            return Uri.parse("content://" + AUTH + "/events/" + System.currentTimeMillis());
        } catch (Throwable e) { return null; }
    }

    static boolean callerMatches(Context c, String reportedPkg) {
        try {
            int uid = Binder.getCallingUid();
            String[] pkgs = c.getPackageManager().getPackagesForUid(uid);
            if (pkgs != null) {
                for (int i=0;i<pkgs.length;i++) {
                    if (reportedPkg.equals(pkgs[i])) return true;
                }
            }
            SharedPreferences sp = c.getSharedPreferences(SP, 0);
            Set<String> allow = sp.getStringSet("hook_scope_pkgs", null);
            return allow == null || allow.size() == 0 || allow.contains(reportedPkg);
        } catch(Throwable e) {
            return true;
        }
    }

    static String str(ContentValues v, String k) { Object o = v.get(k); return o == null ? "" : String.valueOf(o); }

    static boolean shouldStoreEvent(String method, String stage, String result) {
        if (method == null) method = "";
        if (stage == null) stage = "";
        if (result == null) result = "";
        if (method.startsWith("IAPT-XP-")) return false;
        if ("iAPT-LSP".equals(method) && "status".equals(stage)) {
            return "动态解密".equals(result);
        }
        return true;
    }

    static void appendEvent(SharedPreferences sp, String line) {
        line = safeEventLine(line);
        String old = sp.getString("hook_events_jsonl", "");
        if (old != null && old.length() > MAX_CACHE_CHARS) {
            old = old.substring(old.length() - MAX_CACHE_CHARS);
            int n = old.indexOf('\n');
            if (n >= 0 && n + 1 < old.length()) old = old.substring(n + 1);
        }
        String all = old.length() == 0 ? line : old + "\n" + line;
        String[] lines = all.split("\\n");
        if (lines.length > MAX_EVENTS) {
            StringBuilder sb = new StringBuilder();
            for (int i = lines.length - MAX_EVENTS; i < lines.length; i++) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(lines[i]);
            }
            all = sb.toString();
        }
        sp.edit().putString("hook_events_jsonl", all).commit();
    }

    static String safeEventLine(String line) {
        try {
            if (line == null) return "";
            String x = line.replace('\r', ' ').replace('\n', ' ');
            if (x.length() > MAX_LINE_CHARS) x = x.substring(0, MAX_LINE_CHARS);
            return x;
        } catch(Throwable e) {
            return "";
        }
    }

    static Uri writeDump(Context c, String pkg, ContentValues values) {
        SharedPreferences sp = c.getSharedPreferences(SP, 0);
        String rel = normalizeDumpRelPath(str(values, "dump_rel"));
        String text = removeBadUnicodeControls(str(values, "dump_text"));
        boolean append = "1".equals(str(values, "dump_append"));
        if (isIyuFile(rel) && text != null && text.indexOf("<View") >= 0) {
            text = buildLooseIyuDump(text);
            // 兜底修复后的 .iyu 已经是完整文件，不能再按原始半成品追加。
            append = false;
        }
        String path = "";
        try {
            if (rel == null || rel.length() == 0) rel = "mian.iyu";
            File base = new File("/sdcard/iApt/dump/" + safePathPart(pkg));
            File out = safeOutFile(base, rel);
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileOutputStream fos = new FileOutputStream(out, append);
            fos.write(text.getBytes("UTF-8"));
            fos.close();
            path = out.getAbsolutePath();
            return Uri.parse("content://" + AUTH + "/dump/ok");
        } catch(Throwable e) {
            try {
                JSONObject o = new JSONObject();
                o.put("package_name", pkg);
                o.put("method_name", "iAPT-DUMP");
                o.put("stage", "dynamic");
                o.put("args_json", "write_failed rel=" + rel);
                o.put("result_text", "write_failed:" + e.getClass().getName() + "\n输出：" + rel + "\n" + e.getMessage());
                o.put("result_b64", "");
                o.put("created_at", System.currentTimeMillis());
                appendEvent(sp, o.toString());
            } catch(Throwable ignored) {}
            return Uri.parse("content://" + AUTH + "/dump/fail");
        }
    }

    static File safeOutFile(File base, String rel) {
        try {
            if (base != null && !base.exists()) base.mkdirs();
            String r = normalizeDumpRelPath(rel);
            File out = new File(base, r);
            String bp = base.getCanonicalPath();
            String op = out.getCanonicalPath();
            if (!op.startsWith(bp + File.separator) && !op.equals(bp)) {
                out = new File(base, safePathPart(new File(r).getName()));
            }
            return out;
        } catch(Throwable e) {
            return new File(base, safePathPart(rel == null ? "mian.iyu" : rel));
        }
    }

    static String normalizeRelPath(String s) {
        if (s == null || s.length() == 0) return "mian.iyu";
        String x = s.trim().replace('\\', '/');
        while (x.startsWith("/")) x = x.substring(1);
        String[] parts = x.split("/");
        StringBuilder sb = new StringBuilder();
        for (int i=0;i<parts.length;i++) {
            String p = parts[i];
            if (p == null || p.length() == 0 || ".".equals(p) || "..".equals(p)) continue;
            p = safePathPart(p);
            if (p.length() == 0) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(p);
        }
        if (sb.length() == 0) sb.append("mian.iyu");
        return sb.toString();
    }

    static String normalizeDumpRelPath(String s) {
        // Keep the original dynamic dump layout.
        // Do not force iApp source files into a src/ subdirectory; some workflows
        // expect the decrypted files exactly where the client used to write them.
        return normalizeRelPath(s);
    }

    static String safePathPart(String s) {
        if (s == null) return "x";
        StringBuilder sb = new StringBuilder();
        for (int i=0;i<s.length();i++) {
            char c = s.charAt(i);
            if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c < 32) sb.append('_');
            else sb.append(c);
        }
        String x = sb.toString().trim();
        while (x.startsWith(".")) x = x.substring(1);
        if (x.length() == 0) x = "x";
        return x;
    }


    static class ViewNode {
        String id;
        String did;
        String block;
        int order;
        ViewNode(String i, String d, String b, int o) { id = i; did = d; block = b; order = o; }
    }

    static boolean isIyuFile(String f) {
        if (f == null) return true;
        return f.toLowerCase(Locale.US).endsWith(".iyu") || f.indexOf('.') < 0;
    }

    static String buildLooseIyuDump(String s) {
        if (s == null) return "";
        String x = stripXmlDecl(removeBadUnicodeControls(s)).trim();
        x = removeSimpleWrapperTags(x);
        x = repairViewClosures(x).trim();
        if (x.length() == 0) return "";
        if (x.indexOf("<View") >= 0 || x.indexOf("<view") >= 0) return x.endsWith("\n") ? x : x + "\n";
        x = stripUIEventsetTagsLoose(x).trim();
        return "<UIEventset>\n" + (x.length() > 0 ? x + "\n" : "") + "</UIEventset>\n";
    }

    static String repairViewClosures(String s) {
        if (s == null || s.length() == 0) return "";
        String x = stripUIEventsetTagsLoose(stripXmlDecl(s)).trim();
        if (x.indexOf("<View") < 0 && x.indexOf("<view") < 0) return x;
        ArrayList views = new ArrayList();
        StringBuilder loose = new StringBuilder();
        int pos = 0;
        while (true) {
            int st = indexOfIgnoreCase(x, "<View", pos);
            if (st < 0) {
                appendLooseIyuTail(loose, x.substring(pos));
                break;
            }
            appendLooseIyuTail(loose, x.substring(pos, st));
            int evEnd = indexOfIgnoreCase(x, "</event>", st);
            int nextView = indexOfIgnoreCase(x, "<View", st + 5);
            int end;
            if (evEnd >= 0 && (nextView < 0 || evEnd < nextView)) end = evEnd + "</event>".length();
            else if (nextView >= 0) end = nextView;
            else end = x.length();
            String block = stripViewCloseTags(x.substring(st, end)).trim();
            if (block.length() > 0) views.add(block);
            pos = end;
        }
        if (views.size() == 0) return x;
        StringBuilder out = new StringBuilder();
        for (int i=0;i<views.size();i++) {
            String block = String.valueOf(views.get(i)).trim();
            if (block.length() == 0) continue;
            out.append(block).append('\n');
            out.append("</View>\n");
        }
        String tail = loose.toString().trim();
        if (tail.length() > 0) {
            out.append("<UIEventset>\n");
            out.append(tail);
            if (out.charAt(out.length() - 1) != '\n') out.append('\n');
            out.append("</UIEventset>\n");
        }
        return out.toString().trim();
    }

    static String removeBadUnicodeControls(String s) {
        if (s == null || s.length() == 0) return s == null ? "" : s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i=0;i<s.length();i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') { sb.append(c); continue; }
            if (c == 160) { sb.append(' '); continue; }
            int tp = Character.getType(c);
            if (tp == Character.CONTROL || tp == Character.FORMAT) continue;
            sb.append(c);
        }
        return sb.toString();
    }

    static String stripXmlDecl(String s) {
        if (s == null) return "";
        String x = s.trim();
        if (x.startsWith("<?xml")) {
            int p = x.indexOf("?>");
            if (p >= 0) x = x.substring(p + 2).trim();
        }
        return x;
    }

    static String removeSimpleWrapperTags(String s) {
        if (s == null) return "";
        String x = s;
        x = x.replaceAll("(?s)<xxbj\\b[^>]*>", "");
        x = x.replace("</xxbj>", "");
        x = x.replaceAll("(?s)<_Yu5Src\\b[^>]*>", "");
        x = x.replace("</_Yu5Src>", "");
        return x.trim();
    }

    static String stripUIEventsetTagsLoose(String s) {
        if (s == null) return "";
        String x = s.replace("\r\n", "\n").replace('\r', '\n');
        x = x.replaceAll("(?i)<UIEventset\\b[^>]*>", "");
        x = x.replaceAll("(?i)</UIEventset>", "");
        return x.trim();
    }

    static String stripViewCloseTags(String s) {
        if (s == null) return "";
        return s.replaceAll("(?i)</View>", "").trim();
    }

    static void appendLooseIyuTail(StringBuilder sb, String text) {
        if (sb == null || text == null) return;
        String t = stripUIEventsetTagsLoose(stripViewCloseTags(text)).trim();
        if (t.length() == 0) return;
        if (t.indexOf("<eventItme") >= 0 || t.indexOf("<eventitme") >= 0) {
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
            sb.append(t).append('\n');
        }
    }

    static int indexOfIgnoreCase(String s, String needle, int from) {
        if (s == null || needle == null) return -1;
        return s.toLowerCase(Locale.US).indexOf(needle.toLowerCase(Locale.US), from < 0 ? 0 : from);
    }

    static String firstTag(String s) {
        if (s == null) return "";
        int a = s.indexOf('<');
        int b = s.indexOf('>', a + 1);
        if (a < 0 || b < 0) return "";
        return s.substring(a, b + 1);
    }

    static String attrValue(String tag, String name) {
        try {
            if (tag == null || name == null) return "";
            String p = name + "=\"";
            int a = tag.indexOf(p);
            if (a >= 0) { a += p.length(); int b = tag.indexOf('"', a); return b >= 0 ? tag.substring(a, b) : tag.substring(a); }
            p = name + "='";
            a = tag.indexOf(p);
            if (a >= 0) { a += p.length(); int b = tag.indexOf('\'', a); return b >= 0 ? tag.substring(a, b) : tag.substring(a); }
        } catch(Throwable ignored) {}
        return "";
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        try {
            String path = uri == null ? "" : String.valueOf(uri.getPath());
            if (path != null && path.indexOf("config") >= 0) return queryConfig();
        } catch(Throwable ignored) {}

        MatrixCursor mc = new MatrixCursor(new String[]{"id","json"});
        try {
            Context c = getContext(); if (c == null) return mc;
            String all = c.getSharedPreferences(SP,0).getString("hook_events_jsonl", "");
            if (all.length() == 0) return mc;
            String[] lines = all.split("\\n");
            for(int i=0;i<lines.length;i++) mc.addRow(new Object[]{i+1, lines[i]});
        } catch(Throwable e) {}
        return mc;
    }

    Cursor queryConfig() {
        MatrixCursor mc = new MatrixCursor(new String[]{"key","value"});
        try {
            Context c = getContext(); if (c == null) return mc;
            SharedPreferences sp = c.getSharedPreferences(CONFIG_SP, 0);
            boolean fbAllowed = sp.getBoolean("hook_fb_allowed", false);
            boolean dynAllowed = sp.getBoolean("hook_dynamic_allowed", false);
            boolean funcAllowed = sp.getBoolean("hook_func_allowed", false);
            boolean fbEnabled = sp.getBoolean("hook_fb_enabled", false) && fbAllowed;
            boolean dynEnabled = sp.getBoolean("hook_dynamic_enabled", false) && dynAllowed;
            boolean funcEnabled = sp.getBoolean("hook_func_enabled", false) && funcAllowed;
            mc.addRow(new Object[]{"hook_fb_enabled", fbEnabled ? "1" : "0"});
            mc.addRow(new Object[]{"hook_dynamic_enabled", dynEnabled ? "1" : "0"});
            mc.addRow(new Object[]{"hook_func_enabled", funcEnabled ? "1" : "0"});
            mc.addRow(new Object[]{"hook_fb_allowed", fbAllowed ? "1" : "0"});
            mc.addRow(new Object[]{"hook_dynamic_allowed", dynAllowed ? "1" : "0"});
            mc.addRow(new Object[]{"hook_func_allowed", funcAllowed ? "1" : "0"});
            mc.addRow(new Object[]{"hook_func_rules", sp.getString("hook_func_rules", "")});
        } catch(Throwable e) {}
        return mc;
    }
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
    public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    public String getType(Uri uri) { return "vnd.android.cursor.item/iapt-hook-event"; }
}
