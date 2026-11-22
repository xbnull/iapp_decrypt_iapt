package com.iapt.client.hook;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import org.json.JSONObject;

public class IaptHookReceiver extends BroadcastReceiver {
    static final String SP = "iapt_client";
    static final int MAX_EVENTS = 500;

    public void onReceive(Context context, Intent intent) {
        try {
            if (context == null || intent == null) return;
            String action = intent.getAction();
            if (!"com.iapt.client.hook.EVENT".equals(action)) return;
            String pkg = intent.getStringExtra("package_name");
            if (pkg == null || pkg.length() == 0) return;
            String method = s(intent, "method_name");
            String stage = s(intent, "stage");
            String result = s(intent, "result_text");
            if (!shouldStoreEvent(method, stage, result)) return;

            JSONObject o = new JSONObject();
            o.put("package_name", pkg);
            o.put("method_name", method);
            o.put("stage", stage);
            o.put("args_json", s(intent, "args_json"));
            o.put("result_text", result);
            o.put("result_b64", s(intent, "result_b64"));
            o.put("created_at", System.currentTimeMillis());
            appendEvent(context.getSharedPreferences(SP, 0), o.toString());
        } catch(Throwable ignored) {}
    }

    static String s(Intent i, String k) {
        String v = i.getStringExtra(k);
        return v == null ? "" : v;
    }

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
        String old = sp.getString("hook_events_jsonl", "");
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
}
