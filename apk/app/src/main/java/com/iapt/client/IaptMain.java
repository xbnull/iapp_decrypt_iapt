package com.iapt.client;
import android.Manifest;
import android.app.*;
import android.os.*;
import android.view.*;
import android.view.inputmethod.InputMethodManager;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.widget.*;
import android.database.DataSetObserver;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import java.util.concurrent.*;

public class IaptMain {
    // IAPT_CLIENT_ANCIENT_LABEL_SCAN_CACHE_V2
    // IAPT_CLIENT_V81_OLD_NEW_ROUTE_FIX
    // IAPT_CLIENT_V137_OUTPUT_COUNT_FIX
    // IAPT_CLIENT_V152_TASK_HISTORY_AND_DETAIL_SCOPE_FIX
    // IAPT_CLIENT_UI_TASK_CARD_USE_FEATURE_ANIM_V13
    // IAPT_CLIENT_V32_UI_MOTION
    public static void start(android.app.Activity activity) {
        new IaptApp(activity).start();
    }

    static class IaptApp {
        static final String API_BASE = "https://iapp.xbnull.top/api";
        static final String PREF_API_BASE = "custom_api_base_v188";
        static final String APP_ID = "iapt-android";
        static final String APP_SECRET = "iapt_7b4d3f2af9d8b68c95d11f02fb07de024e6f77ea951e0f0d011cb2303afb0cfa";
        static final int APP_VERSION_CODE = 23;
        static final String IAPT_TRANSPORT_VERSION = "V191-internal-subscription-guard";
        static final String APP_VERSION_NAME = "2.3";
        static final int FEATURE_SERVER_SOKEY = 15; // 服务器获取sokey；使用功能15，功能0包含。
        static final int FEATURE_JOINT_KEY_ENUM = 14; // 联合枚举必须显式订阅，功能0不包含。
        static final int FEATURE_DYNAMIC_KEY_POOL = 15; // 使用服务器密钥池中的单个动态Key；功能0包含。
        static final int FEATURE_DYNAMIC_KEY_POOL_ENUM = 16; // 枚举服务器动态Key池；功能0包含。
        static final int FEATURE_ANTI_QIUSHUI = 17; // 反加密样本；必须显式订阅，功能0不包含。
        static final int FEATURE_ANTI_IAPEC = 17; // 反iAPEC加密：只还原“代码高效加密”字符串层。
        static final int FEATURE_ANTI_IAPEC_SELF_DESTRUCT = 17; // 反iAPEC自毁：还原被销毁/哈希化的控件类型。
        static final int FEATURE_NATIVE_COMPILE_RESTORE = 5; // 原生编译修复与动态修复共用功能5。
        static final String PREF_DEXKEY_ACQUIRE_MODE = "dexkey_acquire_mode_v185";
        static final int DEXKEY_MODE_STATIC = 1;
        static final int DEXKEY_MODE_DYNAMIC = 2;
        // MD3 规范调色板（紫）：来自用户最新 UI 代码，保留旧常量别名以兼容业务页面。
        static final int MD3_PRIMARY = Color.parseColor("#6750A4");
        static final int MD3_ON_PRIMARY = Color.parseColor("#FFFFFF");
        static final int MD3_PRIMARY_CONTAINER = Color.parseColor("#EADDFF");
        static final int MD3_ON_PRIMARY_CONTAINER = Color.parseColor("#21005D");
        static final int MD3_SURFACE = Color.parseColor("#FEF7FF");
        static final int MD3_SURFACE_CONTAINER_LOW = Color.parseColor("#F3EDF7");
        static final int MD3_SURFACE_CONTAINER = Color.parseColor("#F3EDF7");
        static final int MD3_SURFACE_CONTAINER_HIGH = Color.parseColor("#ECE6F0");
        static final int TEXT_MAIN = Color.parseColor("#1D1B20");
        static final int TEXT_SUB = Color.parseColor("#49454F");

        static final int BLUE = MD3_PRIMARY;
        static final int BLUE_DARK = MD3_ON_PRIMARY_CONTAINER;
        static final int BLACK = TEXT_MAIN;
        static final int GRAY = TEXT_SUB;
        static final int BG = MD3_SURFACE;
        static final int CARD = Color.parseColor("#FFFFFF");
        static final int DIVIDER = MD3_SURFACE_CONTAINER_HIGH;
        static final int PRIMARY = MD3_PRIMARY;
        static final int PRIMARY_LIGHT = Color.parseColor("#7F67BE");
        static final int BG_COLOR = MD3_SURFACE;
        static final int CARD_BG = CARD;


        Activity a;
        SharedPreferences sp;
        SharedPreferences hookSp;
        Api api;
        RelativeLayout rootLayout;
        SwipeFrameLayout content;
        LinearLayout root;
        LinearLayout bottomNav;
        TextView fabButton;
        LinearLayout[] navTabs = new LinearLayout[3];
        int currentMainTab = 0;
        boolean topLevelPage = true;
        int nextPageTransitionDirection = 0;
        Button tabTasks, tabFuncs, tabMine;
        ArrayList<JSONObject> tasks = new ArrayList<JSONObject>();
        ArrayList<JSONObject> pendingTasks = new ArrayList<JSONObject>();
        ArrayList<JSONObject> subs = new ArrayList<JSONObject>();
        JSONObject me;
        boolean isAdmin = false;
        boolean isSuperAdmin = false;
        JSONObject adminUsersData = null;
        JSONObject adminTasksData = null;
        JSONObject adminCardsData = null;
        JSONObject adminAppSettingsData = null;
        JSONObject adminWhitelistData = null;
        JSONObject adminSubscriptionsData = null;
        JSONObject adminKeyPoolData = null;
        String adminTasksLastKeyword = "";
        String adminTasksLastStatus = "";
        int adminTasksLastUserId = 0;
        // 管理后台刷新时保留当前位置，避免每次操作后跳回顶部。
        ScrollView adminScrollView = null;
        int adminScrollRestoreY = 0;
        boolean adminScrollRestorePending = false;
        JSONObject appConfig = null;
        boolean announcementShownThisSession = false;
        boolean announcementConfigFetching = false;
        boolean updateSkipThisSession = false;
        HashMap<Integer, Bitmap> taskIconCache = new HashMap<Integer, Bitmap>();
        TextView homeTaskCountChip = null;
        int serverTaskTotalCount = -1;
        int serverTaskReturnedCount = -1;
        // 用户界面只显示最终可下载输出数量，不使用列表接口里会随扫描阶段跳变的 file_count。
        final Map<String, Integer> taskOutputCountCache = Collections.synchronizedMap(new HashMap<String, Integer>());
        // 防止同一个已完成任务被重复请求详情；详情请求只在后台执行，不阻塞列表。
        final Set<String> taskOutputCountHydrating = Collections.synchronizedSet(new HashSet<String>());
        // Keep the task family stable even if a stale server worker temporarily writes V6/V3.
        // Only identifiers are persisted; no decryption implementation or mapping table is stored client-side.
        HashSet<String> knownAncientTaskIds = new HashSet<String>();
        HashSet<String> knownAncientTaskNos = new HashSet<String>();
        // V151: prevent repeated refresh/detail requests from stacking up and making the UI/server appear frozen.
        boolean tasksFastLoading = false;
        long lastTasksFastStartMs = 0L;
        // Persist the last successful server task list per account.  This keeps
        // history visible immediately after reopening the client or during a
        // temporary network failure; the server remains authoritative on refresh.
        int taskHistoryLoadedUserId = Integer.MIN_VALUE;
        // API 地址入口只在用户主动点击“退出登录”后临时开放。
        // 直接启动到登录页、登录失效返回登录页时均不开放。
        boolean loginApiTapEnabled = false;
        int loginApiTapCount = 0;
        long loginApiLastTapMs = 0L;

        IaptApp(Activity activity) {
            a = activity;
            sp = a.getSharedPreferences("iapt_client", Context.MODE_PRIVATE);
            try {
                // Only Hook switches/rules are shared with hooked processes. Login
                // tokens and normal client data remain in the private preference file.
                hookSp = a.getSharedPreferences("iapt_hook_config", Context.MODE_WORLD_READABLE);
            } catch (Throwable ignored) {
                hookSp = a.getSharedPreferences("iapt_hook_config", Context.MODE_PRIVATE);
            }
            migrateLegacyHookConfig();
            try {
                Set<String> ids = sp.getStringSet("known_ancient_task_ids", Collections.<String>emptySet());
                Set<String> nos = sp.getStringSet("known_ancient_task_nos", Collections.<String>emptySet());
                if (ids != null) knownAncientTaskIds.addAll(ids);
                if (nos != null) knownAncientTaskNos.addAll(nos);
            } catch(Exception ignored) {}
            api = new Api(effectiveApiBase(), APP_ID, APP_SECRET, sp);
        }


        String effectiveApiBase() {
            String custom = sp.getString(PREF_API_BASE, "");
            custom = custom == null ? "" : custom.trim();
            return custom.length() == 0 ? API_BASE : Api.trimSlash(custom);
        }

        void rebuildApiClient() {
            api = new Api(effectiveApiBase(), APP_ID, APP_SECRET, sp);
        }

        String validateCustomApiBase(String raw) throws Exception {
            String value = raw == null ? "" : raw.trim();
            if (value.length() == 0) return "";
            value = Api.trimSlash(value);
            String lower = value.toLowerCase(Locale.US);
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
                throw new Exception("API 地址必须以 http:// 或 https:// 开头");
            }
            Uri uri = Uri.parse(value);
            if (uri.getHost() == null || uri.getHost().trim().length() == 0) {
                throw new Exception("API 地址格式无效");
            }
            if (uri.getQuery() != null || uri.getFragment() != null) {
                throw new Exception("API 地址不能包含查询参数或锚点");
            }
            return value;
        }

        void clearClientSessionPreservingDeviceSettings() {
            String customApi = sp.getString(PREF_API_BASE, "");
            int dexMode = dexkeyAcquireMode();
            SharedPreferences.Editor ed = sp.edit().clear();
            if (customApi != null && customApi.trim().length() > 0) {
                ed.putString(PREF_API_BASE, customApi.trim());
            }
            ed.putInt(PREF_DEXKEY_ACQUIRE_MODE, dexMode);
            ed.apply();
            me = null;
            isAdmin = false;
            isSuperAdmin = false;
            tasks.clear();
            pendingTasks.clear();
            subs.clear();
            taskOutputCountCache.clear();
            taskOutputCountHydrating.clear();
            appConfig = null;
        }

        void logoutToLogin() {
            clearClientSessionPreservingDeviceSettings();
            loginApiTapEnabled = true;
            loginApiTapCount = 0;
            loginApiLastTapMs = 0L;
            showLogin();
        }

        void showApiBaseDialog() {
            LinearLayout box = vbox();
            box.setPadding(dp(2), dp(2), dp(2), dp(2));

            final EditText input = edit("https://服务器地址/api");
            input.setSingleLine(true);
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
            input.setText(sp.getString(PREF_API_BASE, ""));
            input.setSelection(input.getText().length());
            input.setBackground(strokeBg(MD3_SURFACE, 14, MD3_PRIMARY));

            TextView note = tv("请输入完整 API 地址，不会自动补全 /api。留空保存使用默认地址。", 12, TEXT_SUB, 0);
            note.setLineSpacing(dp(2), 1.0f);
            addM(box, input, -1, dp(54), 0, 0, 0, 10);
            addM(box, note, -1, -2, 2, 0, 2, 0);

            final AlertDialog dialog = mdDialog("设置 API 地址", box)
                    .setNegativeButton("取消", null)
                    .setPositiveButton("保存", null)
                    .create();
            dialog.setOnShowListener(new DialogInterface.OnShowListener() {
                public void onShow(DialogInterface di) {
                    dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(TEXT_SUB);
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(MD3_PRIMARY);
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                        public void onClick(View v) {
                            try {
                                String value = validateCustomApiBase(input.getText().toString());
                                SharedPreferences.Editor ed = sp.edit();
                                if (value.length() == 0) ed.remove(PREF_API_BASE);
                                else ed.putString(PREF_API_BASE, value);
                                ed.apply();
                                rebuildApiClient();
                                appConfig = null;
                                dialog.dismiss();
                                toast(value.length() == 0 ? "已恢复默认 API 地址" : "API 地址已保存");
                            } catch (Exception e) {
                                input.setError(e.getMessage());
                                input.requestFocus();
                            }
                        }
                    });
                }
            });
            dialog.show();
            if (dialog.getWindow() != null) {
                dialog.getWindow().setBackgroundDrawable(bg(Color.WHITE, 22));
            }
        }

        void onLoginIntroTapped() {
            if (!loginApiTapEnabled) return;
            long now = System.currentTimeMillis();
            if (loginApiLastTapMs == 0L || now - loginApiLastTapMs > 1400L) {
                loginApiTapCount = 0;
            }
            loginApiLastTapMs = now;
            loginApiTapCount++;
            if (loginApiTapCount >= 15) {
                loginApiTapCount = 0;
                loginApiLastTapMs = 0L;
                showApiBaseDialog();
            }
        }

        int dexkeyAcquireMode() {
            int mode = sp.getInt(PREF_DEXKEY_ACQUIRE_MODE, DEXKEY_MODE_STATIC);
            return mode == DEXKEY_MODE_DYNAMIC ? DEXKEY_MODE_DYNAMIC : DEXKEY_MODE_STATIC;
        }

        boolean useDynamicDexkeyMode() {
            return dexkeyAcquireMode() == DEXKEY_MODE_DYNAMIC;
        }

        String dexkeyAcquireModeLabel() {
            return useDynamicDexkeyMode()
                    ? "方案2(有安全风险)"
                    : "方案1";
        }

        void migrateLegacyHookConfig() {
            try {
                String[] boolKeys = new String[]{
                        "hook_fb_allowed", "hook_dynamic_allowed", "hook_func_allowed",
                        "hook_safe_default_migrated_v209", "hook_fb_enabled",
                        "hook_dynamic_enabled", "hook_func_enabled"
                };
                SharedPreferences.Editor ed = hookSp.edit();
                boolean changed = false;
                for (int i = 0; i < boolKeys.length; i++) {
                    String k = boolKeys[i];
                    if (!hookSp.contains(k) && sp.contains(k)) {
                        ed.putBoolean(k, sp.getBoolean(k, false));
                        changed = true;
                    }
                }
                if (!hookSp.contains("hook_func_rules") && sp.contains("hook_func_rules")) {
                    ed.putString("hook_func_rules", sp.getString("hook_func_rules", ""));
                    changed = true;
                }
                if (changed) ed.commit();
            } catch (Throwable ignored) {}
        }

        interface SwipeCallback {
            void onSwipe(int direction);
        }

        class SwipeFrameLayout extends FrameLayout {
            float downX;
            float downY;
            boolean intercepting;
            SwipeCallback callback;

            SwipeFrameLayout(Context context) {
                super(context);
                setClickable(true);
            }

            void setSwipeCallback(SwipeCallback cb) {
                callback = cb;
            }

            @Override
            public boolean onInterceptTouchEvent(android.view.MotionEvent event) {
                if (!topLevelPage) return super.onInterceptTouchEvent(event);
                int action = event.getActionMasked();
                if (action == android.view.MotionEvent.ACTION_DOWN) {
                    downX = event.getX();
                    downY = event.getY();
                    intercepting = false;
                    return false;
                }
                if (action == android.view.MotionEvent.ACTION_MOVE) {
                    float dx = event.getX() - downX;
                    float dy = event.getY() - downY;
                    if (Math.abs(dx) > dp(22) && Math.abs(dx) > Math.abs(dy) * 1.35f) {
                        intercepting = true;
                        return true;
                    }
                }
                return intercepting;
            }

            @Override
            public boolean onTouchEvent(android.view.MotionEvent event) {
                int action = event.getActionMasked();
                if (action == android.view.MotionEvent.ACTION_DOWN) {
                    downX = event.getX();
                    downY = event.getY();
                    intercepting = false;
                    return true;
                }
                if (action == android.view.MotionEvent.ACTION_UP ||
                        action == android.view.MotionEvent.ACTION_CANCEL) {
                    float dx = event.getX() - downX;
                    float dy = event.getY() - downY;
                    if (topLevelPage && Math.abs(dx) > dp(64) && Math.abs(dx) > Math.abs(dy) * 1.25f) {
                        if (callback != null) callback.onSwipe(dx < 0 ? 1 : -1);
                    }
                    intercepting = false;
                    return true;
                }
                return true;
            }
        }

        class LoadingGlyphView extends View {
            final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            final RectF arc = new RectF();
            long born = System.currentTimeMillis();
            boolean running;
            final Runnable ticker = new Runnable() {
                public void run() {
                    if (!running) return;
                    invalidate();
                    postDelayed(this, 16);
                }
            };

            LoadingGlyphView(Context context) {
                super(context);
                setLayerType(View.LAYER_TYPE_SOFTWARE, null);
            }

            @Override
            protected void onAttachedToWindow() {
                super.onAttachedToWindow();
                running = true;
                born = System.currentTimeMillis();
                removeCallbacks(ticker);
                post(ticker);
            }

            @Override
            protected void onDetachedFromWindow() {
                running = false;
                removeCallbacks(ticker);
                super.onDetachedFromWindow();
            }

            @Override
            protected void onDraw(Canvas canvas) {
                super.onDraw(canvas);
                float w = getWidth();
                float h = getHeight();
                float cx = w / 2f;
                float cy = h / 2f;
                float t = ((System.currentTimeMillis() - born) % 1800L) / 1800f;
                float pulse = 0.72f + 0.28f * (float)Math.sin(t * Math.PI * 2.0);

                paint.setStyle(Paint.Style.STROKE);
                paint.setStrokeCap(Paint.Cap.ROUND);
                paint.setStrokeWidth(dp(3));
                paint.setColor(MD3_PRIMARY);
                arc.set(cx - dp(21), cy - dp(21), cx + dp(21), cy + dp(21));
                canvas.save();
                canvas.rotate(t * 360f, cx, cy);
                canvas.drawArc(arc, 18f, 112f, false, paint);
                paint.setColor(Color.parseColor("#B69DF8"));
                canvas.drawArc(arc, 176f, 78f, false, paint);
                canvas.restore();

                paint.setStyle(Paint.Style.FILL);
                for (int i = 0; i < 3; i++) {
                    double angle = t * Math.PI * 2.0 + i * Math.PI * 2.0 / 3.0;
                    float r = dp(12);
                    float x = cx + (float)Math.cos(angle) * r;
                    float y = cy + (float)Math.sin(angle) * r;
                    paint.setColor(i == 0 ? MD3_PRIMARY : (i == 1 ? Color.parseColor("#7D5260") : Color.parseColor("#006A6A")));
                    canvas.drawCircle(x, y, dp(3.2f) * pulse, paint);
                }

                paint.setColor(MD3_PRIMARY_CONTAINER);
                canvas.drawCircle(cx, cy, dp(5.5f) * pulse, paint);
                paint.setColor(MD3_PRIMARY);
                canvas.drawCircle(cx, cy, dp(2.4f), paint);
            }
        }

        void start() {
            // 启动阶段不自动申请任何存储权限，也不叠加系统权限框和 AlertDialog。
            // 需要访问文件的具体功能会通过 ensureStorageReady() 按需申请。
            checkServerGateAndStart();
        }

        void checkServerGateAndStart() {
            LinearLayout page = vbox();
            page.setGravity(Gravity.CENTER);
            page.setPadding(dp(24), dp(24), dp(24), dp(24));
            page.setBackgroundColor(BG);
            LoadingGlyphView pb = new LoadingGlyphView(a);
            TextView t = tv("正在连接服务器并检查软件状态...", 15, GRAY, Typeface.BOLD);
            t.setGravity(Gravity.CENTER);
            addM(page, pb, dp(72), dp(72), 0, 0, 0, 18);
            page.addView(t, new LinearLayout.LayoutParams(-1, -2));
            setRoot(page);
            new Thread(new Runnable(){ public void run(){
                try {
                    final JSONObject r = api.getPublic("/app/config");
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try {
                            appConfig = extractAppConfig(r);
                            if(appConfig == null) appConfig = new JSONObject();
                            if(!appConfig.optBoolean("app_enabled", true)) { showAppClosed(appConfig.optString("app_closed_message", "软件维护中")); return; }
                            boolean forceUpdate = isForceUpdateConfig(appConfig);
                            if(isCloudVersionNewer(appConfig) && (forceUpdate || !updateSkipThisSession)) { showUpdatePage(appConfig, forceUpdate); return; }
                            continueAfterGate();
                        } catch (Throwable uiError) {
                            showStartupFailure(uiError);
                        }
                    }});
                } catch(final Throwable e) {
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try {
                            showAppClosed("无法连接服务器或软件未开启：" + (e.getMessage()==null?String.valueOf(e):e.getMessage()));
                        } catch (Throwable uiError) {
                            showStartupFailure(uiError);
                        }
                    }});
                }
            }}).start();
        }

        void continueAfterGate() {
            if (getToken().length() == 0) showLogin(); else validateTokenAndEnter();
        }

        void showStartupFailure(Throwable error) {
            try {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                if (error != null) error.printStackTrace(pw);
                pw.flush();
                TextView text = tv("iAPT 初始化失败\n\n" + sw.toString(), 12, TEXT_MAIN, 0);
                text.setTextIsSelectable(true);
                text.setPadding(dp(20), dp(20), dp(20), dp(20));
                ScrollView scroll = new ScrollView(a);
                scroll.addView(text, new ScrollView.LayoutParams(-1, -2));
                setRoot(scroll);
            } catch (Throwable ignored) {
            }
        }

        void showAppClosed(String msg) {
            LinearLayout page = vbox(); page.setGravity(Gravity.CENTER); page.setPadding(dp(28), dp(24), dp(28), dp(24)); page.setBackgroundColor(BG);
            TextView title = tv("软件暂不可用", 24, Color.parseColor("#EF4444"), Typeface.BOLD); title.setGravity(Gravity.CENTER);
            TextView m = tv(msg, 14, GRAY, 0); m.setGravity(Gravity.CENTER);
            Button retry = btn("重新检查", BLUE, Color.WHITE);
            addM(page,title,-1,dp(52),0,0,0,12); addM(page,m,-1,-2,0,0,0,22); addM(page,retry,-1,dp(48),0,0,0,0);
            retry.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ checkServerGateAndStart(); }});
            setRoot(page);
        }

        void showForceUpdate(final JSONObject up) {
            showUpdatePage(up, true);
        }

        void openUrl(String url) { try { if(url != null && url.trim().length()>0) a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url.trim()))); else toast("未设置更新链接"); } catch(Exception e){ toast("打开链接失败："+e.getMessage()); } }


        int localVersionNumber() {
            int n = parseVersionNumber(APP_VERSION_NAME);
            if (APP_VERSION_CODE > n) n = APP_VERSION_CODE;
            return n;
        }

        int parseVersionNumber(String s) {
            try {
                if (s == null) return 0;
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < s.length(); i++) {
                    char c = s.charAt(i);
                    if (c >= '0' && c <= '9') sb.append(c);
                }
                if (sb.length() == 0) return 0;
                String x = sb.toString();
                if (x.length() > 8) x = x.substring(0, 8);
                return Integer.parseInt(x);
            } catch(Exception e) { return 0; }
        }

        int cloudVersionNumber(JSONObject cfg) {
            try {
                if (cfg == null) return 0;
                cfg = extractAppConfig(cfg);
                int best = 0;
                JSONObject up = cfg.optJSONObject("update");
                if (up != null) {
                    int c = up.optInt("version_code", 0); if (c > best) best = c;
                    c = up.optInt("code", 0); if (c > best) best = c;
                    c = parseVersionNumber(up.optString("version_name", "")); if (c > best) best = c;
                    c = parseVersionNumber(up.optString("version", "")); if (c > best) best = c;
                }
                int c = cfg.optInt("update_version_code", 0); if (c > best) best = c;
                c = cfg.optInt("version_code", 0); if (c > best) best = c;
                c = parseVersionNumber(cfg.optString("update_version_name", "")); if (c > best) best = c;
                c = parseVersionNumber(cfg.optString("version_name", "")); if (c > best) best = c;
                c = parseVersionNumber(cfg.optString("version", "")); if (c > best) best = c;
                return best;
            } catch(Exception e) { return 0; }
        }

        boolean isCloudVersionNewer(JSONObject cfg) {
            int cloud = cloudVersionNumber(cfg);
            int local = localVersionNumber();
            return cloud > 0 && local > 0 && cloud > local;
        }

        boolean boolConfig(JSONObject o, String key, boolean def) {
            try {
                if (o == null || !o.has(key)) return def;
                Object v = o.opt(key);
                if (v instanceof Boolean) return ((Boolean)v).booleanValue();
                if (v instanceof Number) return ((Number)v).intValue() != 0;
                String s = o.optString(key, "").trim();
                if ("1".equals(s) || "true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s) || "on".equalsIgnoreCase(s)) return true;
                if ("0".equals(s) || "false".equalsIgnoreCase(s) || "no".equalsIgnoreCase(s) || "off".equalsIgnoreCase(s)) return false;
                return def;
            } catch(Exception e) { return def; }
        }

        boolean isForceUpdateConfig(JSONObject cfg) {
            try {
                if (cfg == null) return false;
                cfg = extractAppConfig(cfg);
                JSONObject up = cfg.optJSONObject("update");
                boolean f = false;
                if (up != null) f = boolConfig(up, "force", boolConfig(up, "force_update", false));
                f = boolConfig(cfg, "force_update", f);
                f = boolConfig(cfg, "update_force", f);
                return f;
            } catch(Exception e) { return false; }
        }

        String updateField(JSONObject cfg, String key1, String key2, String def) {
            try {
                if (cfg == null) return def;
                cfg = extractAppConfig(cfg);
                JSONObject up = cfg.optJSONObject("update");
                String v = "";
                if (up != null) v = up.optString(key1, up.optString(key2, ""));
                if (v == null || v.trim().length() == 0) v = cfg.optString("update_" + key1, cfg.optString(key1, ""));
                if (v == null || v.trim().length() == 0) v = cfg.optString("update_" + key2, cfg.optString(key2, ""));
                if (v == null || v.trim().length() == 0) v = def;
                return v == null ? "" : v.trim();
            } catch(Exception e) { return def; }
        }

        String cloudVersionName(JSONObject cfg) {
            try {
                cfg = extractAppConfig(cfg);
                JSONObject up = cfg.optJSONObject("update");
                String v = "";
                if (up != null) v = up.optString("version_name", up.optString("version", ""));
                if (v.length() == 0) v = cfg.optString("update_version_name", cfg.optString("version_name", cfg.optString("version", "")));
                if (v.length() == 0) v = String.valueOf(cloudVersionNumber(cfg));
                return v;
            } catch(Exception e) { return ""; }
        }

        String announcementTitle(JSONObject cfg) {
            try {
                cfg = extractAppConfig(cfg);
                JSONObject ann = cfg.optJSONObject("announcement");
                String t = cfg.optString("announcement_title", cfg.optString("notice_title", "公告"));
                if (ann != null) {
                    String x = ann.optString("title", ann.optString("name", ""));
                    if (x.trim().length() > 0) t = x;
                }
                if (t == null || t.trim().length() == 0) t = "公告";
                return t.trim();
            } catch(Exception e) { return "公告"; }
        }

        String announcementText(JSONObject cfg) {
            try {
                cfg = extractAppConfig(cfg);
                JSONObject ann = cfg.optJSONObject("announcement");
                String t = cfg.optString("announcement_text",
                    cfg.optString("announcement_content",
                    cfg.optString("announcement",
                    cfg.optString("notice_text",
                    cfg.optString("notice_content", "")))));
                if (ann != null) {
                    String x = ann.optString("text", ann.optString("content", ann.optString("message", ann.optString("body", ""))));
                    if (x.trim().length() > 0) t = x;
                }
                return t == null ? "" : t.trim();
            } catch(Exception e) { return ""; }
        }

        boolean announcementEnabled(JSONObject cfg) {
            try {
                cfg = extractAppConfig(cfg);
                JSONObject ann = cfg.optJSONObject("announcement");
                boolean en = boolConfig(cfg, "announcement_enabled", boolConfig(cfg, "show_announcement", boolConfig(cfg, "notice_enabled", false)));
                if (ann != null) en = boolConfig(ann, "enabled", boolConfig(ann, "show", en));
                return en && announcementText(cfg).length() > 0;
            } catch(Exception e) { return false; }
        }

        void showUpdatePage(final JSONObject cfg, final boolean force) {
            LinearLayout page = vbox();
            page.setGravity(Gravity.CENTER);
            page.setPadding(dp(24), dp(24), dp(24), dp(24));
            page.setBackgroundColor(BG);

            LinearLayout card = vbox();
            card.setPadding(dp(22), dp(22), dp(22), dp(22));
            card.setBackground(bg(Color.WHITE, 24));
            softElev(card, 4);

            TextView badge = pill(force ? "强制更新" : "发现新版本", force ? Color.parseColor("#FCEBEC") : Color.parseColor("#E8EEFF"), force ? Color.parseColor("#C45454") : BLUE, 12);
            card.addView(badge, new LinearLayout.LayoutParams(-2, dp(36)));

            TextView title = tv("需要更新客户端", 24, BLACK, Typeface.BOLD);
            LinearLayout.LayoutParams titleLp = new LinearLayout.LayoutParams(-1, dp(36));
            titleLp.topMargin = dp(18);
            card.addView(title, titleLp);

            String ver = cloudVersionName(cfg);
            String log = updateField(cfg, "log", "content", "");
            if (log.length() == 0) log = updateField(cfg, "message", "text", "");
            String msg = "当前版本：" + APP_VERSION_NAME + "\n云端版本：" + ver;
            if (log.length() > 0) msg += "\n\n" + log;
            TextView info = tv(msg, 14, GRAY, 0);
            info.setGravity(Gravity.LEFT);
            info.setLineSpacing(dp(3), 1.0f);
            LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(-1, -2);
            infoLp.topMargin = dp(12);
            card.addView(info, infoLp);

            Button update = btn("立即更新", BLUE, Color.WHITE);
            LinearLayout.LayoutParams upLp = new LinearLayout.LayoutParams(-1, dp(50));
            upLp.topMargin = dp(22);
            card.addView(update, upLp);
            update.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ openUrl(updateField(cfg, "url", "download_url", "")); }});

            if (!force) {
                Button skip = btn("暂时不更新", Color.parseColor("#EEF2F7"), BLACK);
                LinearLayout.LayoutParams skipLp = new LinearLayout.LayoutParams(-1, dp(50));
                skipLp.topMargin = dp(10);
                card.addView(skip, skipLp);
                skip.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ updateSkipThisSession = true; continueAfterGate(); }});
            } else {
                Button retry = btn("重新检测", Color.parseColor("#EEF2F7"), BLACK);
                LinearLayout.LayoutParams retryLp = new LinearLayout.LayoutParams(-1, dp(50));
                retryLp.topMargin = dp(10);
                card.addView(retry, retryLp);
                retry.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ checkServerGateAndStart(); }});
            }

            page.addView(card, new LinearLayout.LayoutParams(-1, -2));
            setRoot(page);
        }

        JSONObject extractAppConfig(JSONObject r) {
            try {
                if(r == null) return new JSONObject();
                JSONObject cfg = r.optJSONObject("config");
                if(cfg != null) return cfg;
                cfg = r.optJSONObject("app_config");
                if(cfg != null) return cfg;
                JSONObject data = r.optJSONObject("data");
                if(data != null) {
                    cfg = data.optJSONObject("config");
                    if(cfg != null) return cfg;
                    cfg = data.optJSONObject("app_config");
                    if(cfg != null) return cfg;
                    // 有些服务端直接把 app_enabled / announcement_enabled 放在 data 里
                    if(data.has("announcement") || data.has("announcement_enabled") || data.has("app_enabled") || data.has("update")) return data;
                }
                // 有些服务端直接返回配置本体
                return r;
            } catch(Exception e) {
                return new JSONObject();
            }
        }

        void postAnnouncementCheck() {
            // v73：公告不再弹窗，改为首页卡片展示；更新也不再弹窗，启动检测时进入更新页。
        }

        void refreshConfigAndShowAnnouncement() {
            if(announcementConfigFetching) return;
            announcementConfigFetching = true;
            new Thread(new Runnable(){ public void run(){
                try {
                    final JSONObject r = api.getPublic("/app/config");
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try {
                            JSONObject cfg = extractAppConfig(r);
                            if(cfg != null) appConfig = cfg;
                        } catch(Exception e) {}
                        announcementConfigFetching = false;
                        maybeShowAnnouncementAndUpdate();
                    }});
                } catch(final Exception e) {
                    a.runOnUiThread(new Runnable(){ public void run(){
                        announcementConfigFetching = false;
                        maybeShowAnnouncementAndUpdate();
                    }});
                }
            }}).start();
        }

        void maybeShowAnnouncementAndUpdate() {
            // v73：禁用公告/更新弹窗。公告显示在首页卡片；更新在启动检测页处理。
        }


        void validateTokenAndEnter() {
            LinearLayout page = vbox();
            page.setGravity(Gravity.CENTER);
            page.setPadding(dp(24), dp(24), dp(24), dp(24));
            page.setBackgroundColor(BG);
            
            // 现代化加载等待 UI
            ProgressBar pb = new ProgressBar(a);
            TextView t = tv("正在验证登录状态...", 15, GRAY, Typeface.BOLD);
            t.setGravity(Gravity.CENTER);
            
            addM(page, pb, dp(48), dp(48), 0, 0, 0, 16);
            page.addView(t, new LinearLayout.LayoutParams(-1, -2));
            setRoot(page);
            
            new Thread(new Runnable(){ public void run(){
                try {
                    final JSONObject r = api.get("/me");
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try {
                            applyMeResponse(r);
                            cachePut("me", r);
                            showShell();
                            postAnnouncementCheck();
                        } catch (Throwable uiError) {
                            showStartupFailure(uiError);
                        }
                    }});
                } catch(final AuthException ae) {
                    clearClientSessionPreservingDeviceSettings();
                    loginApiTapEnabled = false;
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try { toast("登录已失效，请重新登录"); showLogin(); }
                        catch (Throwable uiError) { showStartupFailure(uiError); }
                    }});
                } catch(final Throwable e) {
                    a.runOnUiThread(new Runnable(){ public void run(){
                        try { toast(e.getMessage()==null?String.valueOf(e):e.getMessage()); showShell(); }
                        catch (Throwable uiError) { showStartupFailure(uiError); }
                    }});
                }
            }}).start();
        }

        void requestPerms() {
            // Android 6-12 使用传统读写权限；Android 13+ 使用媒体权限；Android 11+ 另外需要“所有文件访问权限”才能直接读取任意目录里的 APK。
            requestRuntimeStoragePerms();
            if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) showAllFilesAccessDialog(false);
        }

        void requestRuntimeStoragePerms() {
            if (Build.VERSION.SDK_INT >= 23) {
                ArrayList<String> ps = new ArrayList<String>();
                if (Build.VERSION.SDK_INT >= 33) {
                    addPermissionIfNeed(ps, "android.permission.READ_MEDIA_IMAGES");
                    addPermissionIfNeed(ps, "android.permission.READ_MEDIA_VIDEO");
                    addPermissionIfNeed(ps, "android.permission.READ_MEDIA_AUDIO");
                } else {
                    addPermissionIfNeed(ps, Manifest.permission.READ_EXTERNAL_STORAGE);
                    addPermissionIfNeed(ps, Manifest.permission.WRITE_EXTERNAL_STORAGE);
                }
                if (ps.size() > 0) a.requestPermissions(ps.toArray(new String[ps.size()]), 2001);
            }
        }

        void addPermissionIfNeed(ArrayList<String> ps, String perm) {
            try {
                if (Build.VERSION.SDK_INT >= 23 && a.checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED) ps.add(perm);
            } catch (Exception e) {}
        }

        boolean hasAllFilesAccess() {
            if (Build.VERSION.SDK_INT < 30) return true;
            try {
                Object r = Environment.class.getMethod("isExternalStorageManager").invoke(null);
                return Boolean.TRUE.equals(r);
            } catch (Exception e) {
                return false;
            }
        }

        boolean ensureStorageReady() {
            requestRuntimeStoragePerms();
            if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) {
                showAllFilesAccessDialog(true);
                return false;
            }
            return true;
        }

        String storagePermissionStatus() {
            if (Build.VERSION.SDK_INT >= 30) {
                return hasAllFilesAccess() ? "文件权限：已开启所有文件访问" : "文件权限：未开启所有文件访问，无法读取其它目录 APK";
            }
            if (Build.VERSION.SDK_INT >= 23) {
                boolean r = a.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
                boolean w = a.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
                return (r && w) ? "文件权限：已授权读写存储" : "文件权限：未授权读写存储";
            }
            return "文件权限：系统版本无需动态申请";
        }

        void showAllFilesAccessDialog(final boolean forceOpen) {
            a.runOnUiThread(new Runnable(){ public void run(){
                if (Build.VERSION.SDK_INT < 30 || hasAllFilesAccess()) return;
                new AlertDialog.Builder(a)
                    .setTitle("需要文件访问权限")
                    .setMessage("当前系统需要手动开启“所有文件访问权限”，否则软件只能访问少量公共目录，不能读取你在其它目录里的 APK，也可能无法保存 ZIP。")
                    .setPositiveButton("去开启", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){ openAllFilesAccessSettings(); }})
                    .setNegativeButton(forceOpen ? "稍后" : "取消", null)
                    .show();
            }});
        }

        void openAllFilesAccessSettings() {
            try {
                Intent it = new Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION");
                it.setData(Uri.parse("package:" + a.getPackageName()));
                a.startActivity(it);
            } catch (Exception e) {
                try { a.startActivity(new Intent("android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION")); }
                catch (Exception ex) { toast("请在系统设置里手动给本应用开启所有文件访问权限"); }
            }
        }

        String getToken() { return sp.getString("token", ""); }
        int dp(float v) { return (int)(v * a.getResources().getDisplayMetrics().density + 0.5f); }

        GradientDrawable bg(int color, float radius) {
            GradientDrawable g = new GradientDrawable();
            g.setColor(color);
            g.setCornerRadius(dp(radius));
            return g;
        }
        GradientDrawable strokeBg(int color, float radius, int sw, int sc) {
            GradientDrawable g = bg(color, radius);
            g.setStroke(dp(sw), sc);
            return g;
        }
        GradientDrawable strokeBg(int color, float radius, int strokeColor) {
            GradientDrawable g = bg(color, radius);
            g.setStroke(dp(1.5f), strokeColor);
            return g;
        }
        void softElev(View v, float elevDp) {
            if (v == null) return;
            if (Build.VERSION.SDK_INT >= 21) {
                v.setElevation(dp(elevDp));
            }
        }
        
        // 专门为导航栏打造的液态玻璃材质 Background
        GradientDrawable liquidGlassBg(float radius) {
            GradientDrawable g = new GradientDrawable();
            g.setOrientation(GradientDrawable.Orientation.TL_BR);
            // 采用高纯度半透明白色与极淡雅的莫兰迪蓝灰交织，形成晶莹剔透的液态反射层
            g.setColors(new int[]{
                Color.parseColor("#E6FFFFFF"), 
                Color.parseColor("#D9F1F5F9")
            });
            g.setCornerRadius(dp(radius));
            g.setStroke(dp(1), Color.parseColor("#40FFFFFF")); // 极其高光的玻璃外边缘描边
            return g;
        }

        TextView tv(String text, float spSize, int color, int style) {
            TextView t = new TextView(a);
            t.setText(text == null ? "" : text);
            t.setTextSize(spSize);
            t.setTextColor(color);
            t.setGravity(Gravity.CENTER_VERTICAL);
            t.setIncludeFontPadding(false); // 消除过时的字体边距，UI排版更紧凑精确
            if (style != 0) t.setTypeface(Typeface.create("sans-serif-medium", style));
            return t;
        }

        // 生成带透明度圆角背景的现代仿真图标
        // 【核心视觉】：文字徽标生成器（取代塑料感 Emoji）
        TextView textAvatar(String letter, int color, int size, float radius) {
            TextView t = new TextView(a);
            t.setText(letter == null ? "" : letter);
            t.setTextSize(size);
            t.setTextColor(color);
            t.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            t.setGravity(Gravity.CENTER);
            t.setIncludeFontPadding(false);
            int bgColor = Color.argb(35, Color.red(color), Color.green(color), Color.blue(color));
            t.setBackground(bg(bgColor, radius));
            return t;
        }

        // 保留旧方法名，兼容其它页面调用。
        TextView mdIcon(String symbol, int color, int size, float radius) {
            return textAvatar(symbol, color, size, radius);
        }



        TextView pill(String text, int bgColor, int textColor, float spSize) {
            TextView t = tv(text, spSize, textColor, Typeface.BOLD);
            t.setGravity(Gravity.CENTER);
            t.setSingleLine(true);
            t.setPadding(dp(14), 0, dp(14), 0);
            t.setBackground(bg(bgColor, 999));
            return t;
        }

        String homeQuotaText() {
            try {
                JSONObject q = null;
                if (me != null) {
                    q = me.optJSONObject("quota");
                    JSONObject u = me.optJSONObject("user");
                    if (q == null && u != null) q = u.optJSONObject("quota");
                }
                if (q != null) {
                    String v = quotaText(q, "total", "");
                    if (v.length() == 0 || "0".equals(v)) v = quotaText(q, "remain", "");
                    if (v.length() == 0) v = quotaText(q, "remaining", "");
                    if (v.length() == 0) v = quotaText(q, "left", "");
                    if (v.length() > 0) return v;
                }
            } catch(Exception e) {}
            return "0";
        }

        String statusText(String s) {
            s = safe(s).toLowerCase(Locale.US);
            if (s.indexOf("whitelist_protected") >= 0 || s.indexOf("白名单保护") >= 0) return "白名单保护";
            if (s.indexOf("done") >= 0 || s.indexOf("success") >= 0 || s.indexOf("完成") >= 0) return "完成";
            if (s.indexOf("cancel") >= 0 || s.indexOf("stop") >= 0 || s.indexOf("停止") >= 0 || s.indexOf("取消") >= 0) return "已停止";
            if (s.indexOf("fail") >= 0 || s.indexOf("error") >= 0 || s.indexOf("失败") >= 0) return "失败";
            if (s.indexOf("queue") >= 0 || s.indexOf("pending") >= 0 || s.indexOf("等待") >= 0 || s.indexOf("队列") >= 0) return "队列";
            if (s.indexOf("upload") >= 0 || s.indexOf("提交") >= 0 || s.indexOf("上传") >= 0) return "提交";
            return "执行中";
        }

        int statusBg(String s) {
            String t = statusText(s);
            if ("白名单保护".equals(t)) return Color.parseColor("#FFF4DD");
            if ("完成".equals(t)) return Color.parseColor("#E8F5EE");
            if ("失败".equals(t)) return Color.parseColor("#FCEBEC");
            if ("已停止".equals(t)) return Color.parseColor("#F1F5F9");
            if ("队列".equals(t)) return Color.parseColor("#FFF4DD");
            return Color.parseColor("#EBF3FF");
        }

        int statusColor(String s) {
            String t = statusText(s);
            if ("白名单保护".equals(t)) return Color.parseColor("#8A5A00");
            if ("完成".equals(t)) return Color.parseColor("#2F7D57");
            if ("失败".equals(t)) return Color.parseColor("#C45454");
            if ("已停止".equals(t)) return Color.parseColor("#64748B");
            if ("队列".equals(t)) return Color.parseColor("#B7791F");
            return Color.parseColor("#3568D4");
        }

        void addClickAnim(final View v) {
            if (v == null) return;
            if (Build.VERSION.SDK_INT >= 21) {
                v.setOnTouchListener(new View.OnTouchListener() {
                    public boolean onTouch(View view, android.view.MotionEvent event) {
                        if (event.getAction() == android.view.MotionEvent.ACTION_DOWN) {
                            view.animate().scaleX(0.95f).scaleY(0.95f).alpha(0.85f).setDuration(120)
                                    .setInterpolator(new android.view.animation.OvershootInterpolator()).start();
                        } else if (event.getAction() == android.view.MotionEvent.ACTION_UP ||
                                event.getAction() == android.view.MotionEvent.ACTION_CANCEL) {
                            view.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(120)
                                    .setInterpolator(new android.view.animation.OvershootInterpolator()).start();
                        }
                        return false;
                    }
                });
            }
        }

        void resetClickAnimTree(View view) {
            if (view == null) return;
            try {
                view.animate().cancel();
                view.setScaleX(1f);
                view.setScaleY(1f);
                view.setAlpha(1f);
                view.setPressed(false);
            } catch(Exception ignored) {}

            if (view instanceof ViewGroup) {
                ViewGroup group = (ViewGroup)view;
                for (int i = 0; i < group.getChildCount(); i++) {
                    resetClickAnimTree(group.getChildAt(i));
                }
            }
        }





        void applyPageTransition(View page) {
            if (page == null) return;
            int direction = nextPageTransitionDirection;
            nextPageTransitionDirection = 0;
            page.animate().cancel();
            page.setAlpha(0f);
            page.setScaleX(0.985f);
            page.setScaleY(0.985f);
            if (direction != 0) {
                page.setTranslationX(direction > 0 ? dp(56) : -dp(56));
                page.setTranslationY(0f);
            } else {
                page.setTranslationX(0f);
                page.setTranslationY(dp(18));
            }
            page.animate()
                    .alpha(1f)
                    .translationX(0f)
                    .translationY(0f)
                    .scaleX(1f)
                    .scaleY(1f)
                    .setDuration(390)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator(1.65f))
                    .start();
        }

        void animateDialogIn(final AlertDialog dialog, final boolean loading) {
            if (dialog == null || dialog.getWindow() == null) return;
            final View decor = dialog.getWindow().getDecorView();
            decor.animate().cancel();
            decor.setAlpha(0f);
            decor.setTranslationY(-dp(loading ? 22 : 38));
            decor.setScaleX(loading ? 0.90f : 0.96f);
            decor.setScaleY(loading ? 0.90f : 0.96f);
            decor.post(new Runnable() {
                public void run() {
                    decor.animate()
                            .alpha(1f)
                            .translationY(0f)
                            .scaleX(1f)
                            .scaleY(1f)
                            .setDuration(loading ? 520 : 430)
                            .setInterpolator(new android.view.animation.DecelerateInterpolator(1.7f))
                            .start();
                }
            });
        }

        Button btn(String text, int color, int textColor) {
            Button b = new Button(a);
            b.setText(text);
            b.setTextColor(textColor);
            b.setTextSize(15);
            b.setAllCaps(false);
            b.setSingleLine(true);
            b.setMaxLines(1);
            b.setGravity(Gravity.CENTER);
            b.setIncludeFontPadding(true);
            b.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            b.setBackground(bg(color, 16));
            // 固定高度按钮不能再叠加较大的上下内边距，否则部分系统字体会被裁切。
            b.setMinHeight(0);
            b.setMinimumHeight(0);
            b.setMinWidth(0);
            b.setMinimumWidth(0);
            b.setPadding(dp(16), 0, dp(16), 0);
            b.setStateListAnimator(null);
            addClickAnim(b);
            return b;
        }

        EditText edit(String hint) {
            EditText e = new EditText(a);
            e.setHint(hint);
            e.setTextSize(16);
            e.setSingleLine(false);
            e.setMinLines(1);
            e.setMinHeight(dp(56));
            e.setMinimumHeight(dp(56));
            e.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            e.setIncludeFontPadding(true);
            e.setTextColor(TEXT_MAIN);
            e.setHintTextColor(Color.parseColor("#79747E"));
            e.setPadding(dp(16), dp(12), dp(16), dp(12));
            e.setBackground(strokeBg(Color.TRANSPARENT, 12, Color.parseColor("#79747E")));
            // Rounded clipping can cut glyphs, cursor and selection handles on
            // vendor fonts. The drawable already supplies the rounded border.
            if (Build.VERSION.SDK_INT >= 21) e.setClipToOutline(false);
            return e;
        }

        Button btnPrimary(String text) {
            Button b = new Button(a);
            b.setText(text);
            b.setTextColor(MD3_ON_PRIMARY);
            b.setTextSize(15);
            b.setAllCaps(false);
            b.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            b.setBackground(bg(MD3_PRIMARY, 999));
            b.setPadding(dp(24), dp(12), dp(24), dp(12));
            b.setStateListAnimator(null);
            addClickAnim(b);
            return b;
        }

        Button btnOutline(String text) {
            Button b = new Button(a);
            b.setText(text);
            b.setTextColor(MD3_PRIMARY);
            b.setTextSize(15);
            b.setAllCaps(false);
            b.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            b.setBackground(strokeBg(Color.TRANSPARENT, 999, MD3_SURFACE_CONTAINER_HIGH));
            b.setPadding(dp(24), dp(12), dp(24), dp(12));
            b.setStateListAnimator(null);
            addClickAnim(b);
            return b;
        }

        AlertDialog showGoogleLoading(String text) {
            LinearLayout dView = vbox();
            dView.setGravity(Gravity.CENTER);
            dView.setPadding(dp(32), dp(36), dp(32), dp(36));
            dView.setBackground(bg(MD3_SURFACE, 24));

            LoadingGlyphView pb = new LoadingGlyphView(a);
            TextView msg = tv(text == null ? "正在处理..." : text, 15, TEXT_MAIN, Typeface.BOLD);
            msg.setGravity(Gravity.CENTER);

            dView.addView(pb, new LinearLayout.LayoutParams(dp(76), dp(76)));
            LinearLayout.LayoutParams tLp = new LinearLayout.LayoutParams(-1, -2);
            tLp.topMargin = dp(20);
            dView.addView(msg, tLp);

            AlertDialog dialog = new AlertDialog.Builder(a).create();
            dialog.setView(dView);
            dialog.setCancelable(false);
            dialog.show();
            animateDialogIn(dialog, true);
            try {
                if (dialog.getWindow() != null) {
                    dialog.getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
                }
            } catch(Exception ignored) {}
            return dialog;
        }

        void showScreenshotStyleDialog(final String title, String message) {
            final LinearLayout dView = vbox();
            dView.setPadding(dp(24), dp(24), dp(24), dp(24));
            dView.setBackground(bg(MD3_SURFACE, 28));

            TextView t = tv(title, 22, TEXT_MAIN, Typeface.BOLD);
            dView.addView(t, new LinearLayout.LayoutParams(-1, -2));

            TextView m = tv(message, 15, TEXT_SUB, 0);
            m.setGravity(Gravity.LEFT);
            m.setLineSpacing(dp(4), 1.0f);
            LinearLayout.LayoutParams mLp = new LinearLayout.LayoutParams(-1, -2);
            mLp.topMargin = dp(16);
            dView.addView(m, mLp);

            final EditText input = edit(title != null && title.indexOf("兑") >= 0 ? "请输入卡密" : "请输入相关信息");
            input.setSingleLine(true);
            LinearLayout.LayoutParams inputLp = new LinearLayout.LayoutParams(-1, dp(56));
            inputLp.topMargin = dp(20);
            dView.addView(input, inputLp);

            LinearLayout btnRow = hbox();
            btnRow.setGravity(Gravity.RIGHT);
            Button btnCancel = btnOutline("取消");
            Button btnConfirm = btnPrimary("确定");
            btnRow.addView(btnCancel, new LinearLayout.LayoutParams(-2, dp(48)));
            btnRow.addView(new Space(a), new LinearLayout.LayoutParams(dp(12), 1));
            btnRow.addView(btnConfirm, new LinearLayout.LayoutParams(-2, dp(48)));

            LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(-1, -2);
            btnLp.topMargin = dp(28);
            dView.addView(btnRow, btnLp);

            final AlertDialog dialog = new AlertDialog.Builder(a).create();
            dialog.setView(dView);
            dialog.show();
            try {
                if (dialog.getWindow() != null) {
                    dialog.getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
                }
            } catch(Exception ignored) {}

            btnCancel.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dialog.dismiss(); }});
            btnConfirm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dialog.dismiss(); toast("操作成功"); }});
        }


        LinearLayout vbox() {
            LinearLayout l = new LinearLayout(a);
            l.setOrientation(LinearLayout.VERTICAL);
            return l;
        }
        LinearLayout hbox() {
            LinearLayout l = new LinearLayout(a);
            l.setOrientation(LinearLayout.HORIZONTAL);
            l.setGravity(Gravity.CENTER_VERTICAL);
            return l;
        }
        void add(ViewGroup p, View v, int w, int h) { p.addView(v, new LinearLayout.LayoutParams(w, h)); }
        void addM(ViewGroup p, View v, int w, int h, int l, int t, int r, int b) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(w, h);
            lp.setMargins(dp(l), dp(t), dp(r), dp(b));
            p.addView(v, lp);
        }
        void addW(LinearLayout p, View v, int weight) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -1, weight);
            p.addView(v, lp);
        }

        void setRoot(View v) { a.setContentView(v); }
        void toast(final String s) { a.runOnUiThread(new Runnable(){ public void run(){ Toast.makeText(a, s, Toast.LENGTH_SHORT).show(); }}); }
        void showLoading(final String msg) {}

        String cacheScope() {
            String t = getToken();
            if (t == null || t.length() == 0) return "guest";
            return String.valueOf(t.hashCode());
        }
        String cacheKey(String name) { return "cache_" + cacheScope() + "_" + name; }
        JSONObject cacheGet(String name, long maxAgeMs) {
            try {
                String k = cacheKey(name);
                long ts = sp.getLong(k + "_ts", 0);
                String body = sp.getString(k + "_body", "");
                if (body.length() == 0) return null;
                if (maxAgeMs > 0 && System.currentTimeMillis() - ts > maxAgeMs) return null;
                return new JSONObject(body);
            } catch(Exception e) { return null; }
        }
        void cachePut(String name, JSONObject obj) {
            try {
                if (obj == null) return;
                String k = cacheKey(name);
                sp.edit().putString(k + "_body", obj.toString()).putLong(k + "_ts", System.currentTimeMillis()).apply();
            } catch(Exception e) {}
        }
        void cacheDrop(String name) {
            try {
                String k = cacheKey(name);
                sp.edit().remove(k + "_body").remove(k + "_ts").apply();
            } catch(Exception e) {}
        }
        void applyMeResponse(JSONObject r) {
            try {
                if (r == null) return;
                me = r.optJSONObject("user");
                if (me != null && me.optInt("id", 0) > 0) {
                    sp.edit().putInt("user_id", me.optInt("id", 0)).apply();
                }
                subs.clear();
                JSONArray sa = r.optJSONArray("subscriptions");
                if(sa != null) for(int i=0;i<sa.length();i++) subs.add(sa.optJSONObject(i));
                JSONObject admin = me == null ? null : me.optJSONObject("admin");
                isAdmin = admin != null && admin.optBoolean("is_admin", false);
                isSuperAdmin = admin != null && admin.optBoolean("is_super_admin", false);
            } catch(Exception e) {}
        }
        JSONObject taskNestedObject(JSONObject o, String key) {
            if (o == null || key == null) return null;
            JSONObject direct = o.optJSONObject(key);
            if (direct != null) return direct;
            String raw = safe(o.optString(key, "")).trim();
            if (!raw.startsWith("{")) return null;
            try { return new JSONObject(raw); } catch(Exception ignored) { return null; }
        }

        boolean taskBool(JSONObject o, String key) {
            if (o == null || key == null || !o.has(key)) return false;
            Object value = o.opt(key);
            if (value instanceof Boolean) return ((Boolean)value).booleanValue();
            if (value instanceof Number) return ((Number)value).intValue() != 0;
            String s = safe(o.optString(key, "")).trim().toLowerCase(Locale.US);
            return "1".equals(s) || "true".equals(s) || "yes".equals(s) || "on".equals(s);
        }

        boolean taskObjectSaysAncient(JSONObject o) {
            if (o == null) return false;
            String fam = safe(o.optString("task_family", "")).trim().toLowerCase(Locale.US);
            String pub = safe(o.optString("public_scheme", "")).trim().toLowerCase(Locale.US);
            String ver = safe(o.optString("decrypt_version", "")).trim().toLowerCase(Locale.US);
            String taskVer = safe(o.optString("task_version", "")).trim().toLowerCase(Locale.US);
            String scheme = safe(o.optString("decrypt_scheme", "")).trim().toLowerCase(Locale.US);
            String finalScheme = safe(o.optString("client_final_scheme", "")).trim().toLowerCase(Locale.US);
            String appName = safe(o.optString("app_name", ""));
            String runnerName = safe(o.optString("runner_name", ""));
            return "ancient".equals(ver) || "old".equals(ver) || "legacy".equals(ver)
                    || "old_iapp".equals(ver) || "iapp_old".equals(ver)
                    || "ancient".equals(taskVer) || "ancient".equals(scheme)
                    || "ancient".equals(pub) || "ancient".equals(fam) || "ancient".equals(finalScheme)
                    || taskBool(o, "legacy_iapp") || taskBool(o, "old_iapp")
                    || appName.contains("远古") || runnerName.contains("远古");
        }

        boolean nestedTaskSaysAncient(JSONObject o) {
            if (o == null) return false;
            String[] keys = new String[]{"options", "options_json", "project_meta", "project_meta_json", "payload", "request_options"};
            for (int i = 0; i < keys.length; i++) {
                JSONObject nested = taskNestedObject(o, keys[i]);
                if (nested != null && nested != o && taskObjectSaysAncient(nested)) return true;
            }
            return false;
        }

        String taskOutputCountCacheKey(JSONObject o) {
            if (o == null) return "";
            int id = o.optInt("id", 0);
            if (id > 0) return "id:" + id;
            String no = safe(o.optString("task_no", "")).trim();
            if (no.length() > 0 && !"local".equals(no)) return "no:" + no;
            String apk = safe(o.optString("apk_name", o.optString("app_name", ""))).trim();
            String created = safe(o.optString("created_at", "")).trim();
            if (apk.length() == 0 && created.length() == 0) return "";
            return "local:" + apk + ":" + created;
        }

        int countOutputArray(JSONArray arr) {
            if (arr == null) return 0;
            int count = 0;
            for (int i = 0; i < arr.length(); i++) {
                Object item = arr.opt(i);
                if (item == null || item == JSONObject.NULL) continue;
                if (item instanceof JSONObject) {
                    JSONObject f = (JSONObject)item;
                    boolean dir = f.optBoolean("is_dir", false) || f.optBoolean("directory", false);
                    String type = safe(f.optString("type", f.optString("kind", ""))).trim().toLowerCase(Locale.US);
                    String name = safe(f.optString("name", f.optString("path", f.optString("filename", "")))).trim();
                    if (dir || "dir".equals(type) || "directory".equals(type) || name.endsWith("/")) continue;
                }
                count++;
            }
            return count;
        }

        int jsonOutputCount(JSONObject o, String key) {
            if (o == null || key == null || !o.has(key) || o.isNull(key)) return 0;
            try {
                Object v = o.opt(key);
                if (v instanceof Number) return Math.max(0, ((Number)v).intValue());
                if (v instanceof JSONArray) return countOutputArray((JSONArray)v);
                String s = safe(o.optString(key, "")).trim();
                if (s.length() == 0 || "null".equalsIgnoreCase(s)) return 0;
                return Math.max(0, Integer.parseInt(s));
            } catch(Exception ignored) { return 0; }
        }

        boolean outputCountLooksPublic(JSONObject o, String key, int n) {
            if (n <= 0) return false;
            // V29: 防止把服务端内部扫描 file_count / 原始资源数量误当成“结果文件数”。
            if (o != null && (o.optBoolean("public_file_count_authoritative", false)
                    || o.optBoolean("downloadable_file_count_authoritative", false)
                    || o.optBoolean("client_output_file_count_authoritative", false))) return true;
            // client_output_file_count / result_file_count 等字段通常是最终结果数，可以接受。
            if ("client_output_file_count".equals(key) || "public_output_file_count".equals(key)
                    || "public_file_count".equals(key) || "result_file_count".equals(key)
                    || "decrypted_file_count".equals(key) || "output_file_count".equals(key)
                    || "download_file_count".equals(key) || "result_files_count".equals(key)
                    || "output_files_count".equals(key)) return true;
            // downloadable_file_count 在旧服务端可能被错误回填成 file_count；过大时先不显示。
            return n <= 500;
        }

        int authoritativeOutputCount(JSONObject o) {
            if (o == null) return 0;
            String[] numericKeys = new String[]{
                    "client_output_file_count", "public_output_file_count", "public_file_count",
                    "result_file_count", "decrypted_file_count", "output_file_count",
                    "download_file_count", "result_files_count", "output_files_count",
                    "downloadable_file_count", "downloadable_files"
            };
            for (int i = 0; i < numericKeys.length; i++) {
                int n = jsonOutputCount(o, numericKeys[i]);
                if (outputCountLooksPublic(o, numericKeys[i], n)) return n;
            }
            String[] arrayKeys = new String[]{"output_files", "result_files", "download_files"};
            for (int i = 0; i < arrayKeys.length; i++) {
                int n = countOutputArray(o.optJSONArray(arrayKeys[i]));
                if (n > 0) return n;
            }
            String[] nestedKeys = new String[]{"result", "decrypt_report", "ancient_report", "output", "data"};
            for (int i = 0; i < nestedKeys.length; i++) {
                JSONObject nested = taskNestedObject(o, nestedKeys[i]);
                if (nested == null || nested == o) continue;
                for (int j = 0; j < numericKeys.length; j++) {
                    int n = jsonOutputCount(nested, numericKeys[j]);
                    if (outputCountLooksPublic(nested, numericKeys[j], n)) return n;
                }
                for (int j = 0; j < arrayKeys.length; j++) {
                    int n = countOutputArray(nested.optJSONArray(arrayKeys[j]));
                    if (n > 0) return n;
                }
            }
            return 0;
        }

        int taskOutputFileCount(JSONObject task, JSONObject detail) {
            int count = authoritativeOutputCount(detail);
            if (count <= 0) count = authoritativeOutputCount(task);
            String key = taskOutputCountCacheKey(task != null ? task : detail);
            if (count > 0) {
                if (key.length() > 0) taskOutputCountCache.put(key, Integer.valueOf(count));
                return count;
            }
            if (key.length() > 0) {
                Integer cached = taskOutputCountCache.get(key);
                if (cached != null && cached.intValue() > 0) return cached.intValue();
            }
            return 0;
        }

        String taskOutputCountText(JSONObject task) {
            int count = taskOutputFileCount(task, null);
            if (count > 0) return count + " 文件";
            String status = safe(task == null ? "" : task.optString("status", "")).trim().toLowerCase(Locale.US);
            if ("queued".equals(status) || "running".equals(status)
                    || status.indexOf("upload") >= 0 || status.indexOf("提交") >= 0 || status.indexOf("上传") >= 0) {
                return "处理中";
            }
            // 已完成但列表接口没有携带最终数量时，后台会读取详情并回填。
            if ("done".equals(status) || status.indexOf("success") >= 0 || status.indexOf("完成") >= 0) {
                return "读取中";
            }
            return "0 文件";
        }

        void updateHomeTaskCountChip() {
            try {
                if (homeTaskCountChip != null) {
                    int local = tasks.size();
                    int total = serverTaskTotalCount >= 0 ? Math.max(serverTaskTotalCount, local) : local;
                    homeTaskCountChip.setText("任务  " + total);
                }
            } catch(Exception ignored) {}
        }

        int completedDetailFileCount(JSONObject detail) {
            if (detail == null) return 0;
            JSONObject t = taskFromDetail(detail);
            if (t == null) return 0;
            int count = taskOutputFileCount(t, detail);
            if (count > 0) return count;

            // 兼容旧服务端：详情接口的 file_count 在 done 状态下是最终输出数；
            // 仅允许详情接口使用该兜底，绝不使用 /tasks 列表里的 file_count。
            String status = safe(t.optString("status", "")).trim().toLowerCase(Locale.US);
            if ("done".equals(status) || status.indexOf("success") >= 0 || status.indexOf("完成") >= 0) {
                count = jsonOutputCount(t, "file_count");
                // 详情接口的 file_count 只作为旧服务端兜底；过大的值更可能是内部扫描数量，不显示给普通用户。
                if (count > 0 && count <= 500) {
                    String key = taskOutputCountCacheKey(t);
                    if (key.length() > 0) taskOutputCountCache.put(key, Integer.valueOf(count));
                } else {
                    count = 0;
                }
            }
            return count;
        }

        void hydrateCompletedTaskOutputCounts(final BaseAdapter ad) {
            final ArrayList<JSONObject> need = new ArrayList<JSONObject>();
            // 限制每轮数量，避免任务很多时突然并发大量详情请求。
            for (int i = 0; i < tasks.size() && need.size() < 8; i++) {
                JSONObject task = tasks.get(i);
                if (task == null || task.optInt("id", 0) <= 0) continue;
                String status = safe(task.optString("status", "")).trim().toLowerCase(Locale.US);
                boolean done = "done".equals(status) || status.indexOf("success") >= 0 || status.indexOf("完成") >= 0;
                if (!done || taskOutputFileCount(task, null) > 0) continue;
                String key = taskOutputCountCacheKey(task);
                if (key.length() == 0 || !taskOutputCountHydrating.add(key)) continue;
                need.add(task);
            }
            if (need.size() == 0) return;

            new Thread(new Runnable(){ public void run(){
                boolean changed = false;
                for (int i = 0; i < need.size(); i++) {
                    JSONObject listTask = need.get(i);
                    String key = taskOutputCountCacheKey(listTask);
                    try {
                        int id = listTask.optInt("id", 0);
                        if (id <= 0) continue;
                        JSONObject detail = api.getFast("/tasks/" + id);
                        JSONObject detailTask = taskFromDetail(detail);
                        if (detailTask != null) normalizeKnownAncientTask(detailTask);
                        int count = completedDetailFileCount(detail);
                        if (count > 0) {
                            // 写入客户端专用字段，后续重绘和本次会话刷新都能直接使用。
                            try { listTask.put("client_output_file_count", count); } catch(Exception ignored) {}
                            if (key.length() > 0) taskOutputCountCache.put(key, Integer.valueOf(count));
                            changed = true;
                        }
                    } catch(Exception ignored) {
                    } finally {
                        if (key.length() > 0) taskOutputCountHydrating.remove(key);
                    }
                }
                if (changed) {
                    a.runOnUiThread(new Runnable(){ public void run(){
                        persistTaskHistory();
                        if (ad != null) ad.notifyDataSetChanged();
                        updateHomeTaskCountChip();
                    }});
                }
            }}).start();
        }

        String taskHistoryPreferenceKey(int userId) {
            return "task_history_user_" + Math.max(0, userId);
        }

        void restorePersistedTaskHistory() {
            int userId = sp.getInt("user_id", 0);
            if (taskHistoryLoadedUserId == userId) return;
            taskHistoryLoadedUserId = userId;
            serverTaskTotalCount = -1;
            serverTaskReturnedCount = 0;
            tasks.clear();
            pendingTasks.clear();
            taskOutputCountCache.clear();
            taskOutputCountHydrating.clear();
            if (userId <= 0) return;
            try {
                String raw = sp.getString(taskHistoryPreferenceKey(userId), "");
                if (raw == null || raw.trim().length() == 0) return;
                JSONArray arr = new JSONArray(raw);
                int limit = Math.min(arr.length(), 500);
                for (int i = 0; i < limit; i++) {
                    JSONObject item = arr.optJSONObject(i);
                    if (item == null || item.optInt("id", 0) <= 0) continue;
                    normalizeKnownAncientTask(item);
                    taskOutputFileCount(item, null);
                    tasks.add(item);
                }
            } catch(Exception ignored) {}
        }

        void persistTaskHistory() {
            int userId = sp.getInt("user_id", 0);
            if (userId <= 0) return;
            try {
                JSONArray arr = new JSONArray();
                HashSet<Integer> seenIds = new HashSet<Integer>();
                HashSet<String> seenNos = new HashSet<String>();
                for (int i = 0; i < tasks.size() && arr.length() < 500; i++) {
                    JSONObject item = tasks.get(i);
                    if (item == null) continue;
                    int id = item.optInt("id", 0);
                    String no = safe(item.optString("task_no", "")).trim();
                    if (id <= 0 && (no.length() == 0 || "local".equals(no))) continue;
                    if (id > 0 && !seenIds.add(Integer.valueOf(id))) continue;
                    if (no.length() > 0 && !"local".equals(no) && !seenNos.add(no)) continue;
                    // JSONObject.toString() makes a snapshot, so later UI updates do not
                    // mutate the value being written by SharedPreferences.
                    arr.put(new JSONObject(item.toString()));
                }
                sp.edit().putString(taskHistoryPreferenceKey(userId), arr.toString()).apply();
            } catch(Exception ignored) {}
        }

        boolean isStandaloneUtilityTask(JSONObject o) {
            if (o == null) return false;
            String ver = safe(o.optString("decrypt_version", o.optString("task_version", ""))).trim().toLowerCase(Locale.US);
            String kind = safe(o.optString("task_kind", "")).trim().toLowerCase(Locale.US);
            String appName = safe(o.optString("app_name", "")).toLowerCase(Locale.US);
            String apkName = safe(o.optString("apk_name", "")).toLowerCase(Locale.US);
            JSONObject options = taskNestedObject(o, "options");
            if (options == null) options = taskNestedObject(o, "options_json");
            if (options != null) {
                String ov = safe(options.optString("decrypt_version", options.optString("task_version", ""))).trim().toLowerCase(Locale.US);
                String ok = safe(options.optString("task_kind", "")).trim().toLowerCase(Locale.US);
                if (ver.length() == 0) ver = ov;
                if (kind.length() == 0) kind = ok;
                if (taskBool(options, "dynamic_key_extract") || taskBool(options, "server_sokey_extract")
                        || taskBool(options, "source_restore") || taskBool(options, "numeric_source_restore")
                        || taskBool(options, "static_dex_restore") || taskBool(options, "iact_dynamic_decrypt")) return true;
            }
            HashSet<String> standaloneVersions = new HashSet<String>(Arrays.asList(
                    "v6", "6", "key", "dynkey", "dynamic_key", "dynamic_key_extract",
                    "sokey", "server_sokey", "server_sokey_extract",
                    "restore", "source_restore", "fn_restore", "numeric_restore", "numeric_source_restore",
                    "dex_restore", "static_dex_restore", "source_dex_restore", "iact", "iact_restore"));
            if (standaloneVersions.contains(ver)) return true;
            if (kind.contains("dynamic_key_extract") || kind.contains("server_sokey") || kind.contains("source_restore")
                    || kind.contains("dex_restore") || kind.contains("numeric") || kind.contains("iact") || kind.equals("v6")) return true;
            if (appName.contains("动态key提取") || appName.contains("服务器获取sokey") || appName.contains("so key 提取")
                    || appName.contains("源码还原") || appName.contains("dex还原") || appName.contains("iact")) return true;
            return apkName.endsWith("_sokey.zip") || apkName.endsWith("_iact.zip")
                    || apkName.endsWith("_numeric.zip") || apkName.endsWith("_dex_restore.zip")
                    || apkName.endsWith("_src.zip");
        }

        boolean whitelistProtectionText(String value) {
            String text = safe(value).trim().toLowerCase(Locale.US);
            if (text.length() == 0) return false;
            return text.indexOf("白名单保护") >= 0
                    || text.indexOf("白名单样本") >= 0
                    || text.indexOf("whitelist_protected") >= 0
                    || text.indexOf("iapt_whitelist_protected") >= 0
                    || text.indexOf("iapt_whitelist_package_signature_block") >= 0
                    || text.indexOf("iapt_wl_v168_package_signature_block") >= 0;
        }

        boolean whitelistProtectedObject(JSONObject value) {
            if (value == null) return false;
            try {
                if (value.optBoolean("whitelist_protected", false)
                        || value.optBoolean("is_whitelist_protected", false)
                        || value.optBoolean("protected_by_whitelist", false)) return true;

                String[] textKeys = new String[]{
                        "error_code", "error_text", "error", "message", "result_text",
                        "status_text", "decrypt_summary", "result", "detail"
                };
                for (int i = 0; i < textKeys.length; i++) {
                    if (whitelistProtectionText(value.optString(textKeys[i], ""))) return true;
                }

                String[] nestedKeys = new String[]{
                        "task", "data", "output", "decrypt_result", "result_object"
                };
                for (int i = 0; i < nestedKeys.length; i++) {
                    JSONObject nested = value.optJSONObject(nestedKeys[i]);
                    if (nested == null) continue;
                    if (nested.optBoolean("whitelist_protected", false)) return true;
                    for (int j = 0; j < textKeys.length; j++) {
                        if (whitelistProtectionText(nested.optString(textKeys[j], ""))) return true;
                    }
                }
            } catch(Exception ignored) {}
            return false;
        }

        boolean isWhitelistProtectedTask(JSONObject task, JSONObject detail) {
            return whitelistProtectedObject(task) || whitelistProtectedObject(detail);
        }

        boolean shouldShowV3DecryptDetails(JSONObject task, JSONObject detail) {
            if (isWhitelistProtectedTask(task, detail)) return false;
            JSONObject t = task != null ? task : taskFromDetail(detail);
            if (t == null || isStandaloneUtilityTask(t) || isStandaloneUtilityTask(detail)) return false;
            if (isKnownAncientTask(t) || isKnownAncientTask(detail)) return true;
            String runner = taskRunnerName(t);
            return "V3".equals(runner) || "远古".equals(runner);
        }

        boolean rawTaskSaysModern(JSONObject o) {
            if (o == null) return false;
            // 嵌套 options 明确为远古时，服务端顶层暂存的 V3/V6 字段不得覆盖它。
            if (taskObjectSaysAncient(o) || nestedTaskSaysAncient(o)) return false;
            String fam = safe(o.optString("task_family", "")).trim().toLowerCase(Locale.US);
            String pub = safe(o.optString("public_scheme", "")).trim().toLowerCase(Locale.US);
            String ver = safe(o.optString("decrypt_version", "")).trim().toLowerCase(Locale.US);
            String scheme = safe(o.optString("decrypt_scheme", "")).trim().toLowerCase(Locale.US);
            return "v3".equals(fam) || "v6".equals(fam) || "modern".equals(fam)
                    || "v3".equals(pub) || "v6".equals(pub) || "modern".equals(pub)
                    || "v3".equals(ver) || "v6".equals(ver)
                    || "v3".equals(scheme) || "v6".equals(scheme);
        }

        boolean rawTaskSaysAncient(JSONObject o) {
            if (o == null) return false;
            if (taskObjectSaysAncient(o) || nestedTaskSaysAncient(o)) return true;

            String fam = safe(o.optString("task_family", "")).trim().toLowerCase(Locale.US);
            String pub = safe(o.optString("public_scheme", "")).trim().toLowerCase(Locale.US);
            if ("v3".equals(fam) || "v6".equals(fam) || "modern".equals(fam)) return false;
            if ("v3".equals(pub) || "v6".equals(pub) || "modern".equals(pub)) return false;

            JSONObject rep = o.optJSONObject("decrypt_report");
            if (rep == null) rep = o.optJSONObject("ancient_report");
            if (rep != null) {
                String rscheme = safe(rep.optString("scheme", "")).trim().toLowerCase(Locale.US);
                String rfam = safe(rep.optString("family", "")).trim().toLowerCase(Locale.US);
                if ("ancient".equals(rscheme) || "old".equals(rscheme) || "ancient".equals(rfam) || rscheme.indexOf("old-iapp") >= 0) return true;
                if ("v3".equals(rscheme) || "v3".equals(rfam) || rscheme.indexOf("新版") >= 0) return false;
            }
            String summary = safe(o.optString("decrypt_summary", ""));
            if (summary.indexOf("方案：远古") >= 0 || summary.indexOf("old-iApp") >= 0) return true;
            if (summary.indexOf("方案：新版 V3") >= 0 || summary.indexOf("方案：V3") >= 0) return false;
            return false;
        }

        boolean isKnownAncientTask(JSONObject o) {
            if (o == null) return false;
            if (rawTaskSaysAncient(o)) return true;

            // 已由创建响应确认过的任务 ID/编号优先级高于后续列表中的旧 V3 字段。
            // 旧 worker 可能短暂回写 V3，但同一任务的方案不会在创建后改变。
            int id = o.optInt("id", 0);
            String no = safe(o.optString("task_no", "")).trim();
            if (id > 0 && knownAncientTaskIds.contains(String.valueOf(id))) return true;
            if (no.length() > 0 && knownAncientTaskNos.contains(no)) return true;

            if (rawTaskSaysModern(o)) return false;
            return false;
        }

        void rememberAncientTask(JSONObject o) {
            if (o == null || !rawTaskSaysAncient(o)) return;
            boolean changed = false;
            int id = o.optInt("id", 0);
            String no = safe(o.optString("task_no", "")).trim();
            if (id > 0) changed |= knownAncientTaskIds.add(String.valueOf(id));
            if (no.length() > 0 && !"local".equals(no)) changed |= knownAncientTaskNos.add(no);
            if (changed) {
                try {
                    sp.edit()
                            .putStringSet("known_ancient_task_ids", new HashSet<String>(knownAncientTaskIds))
                            .putStringSet("known_ancient_task_nos", new HashSet<String>(knownAncientTaskNos))
                            .apply();
                } catch(Exception ignored) {}
            }
        }

        void redactWhitelistProtectedTask(JSONObject o) {
            if (o == null) return;
            try {
                String[] sensitiveKeys = new String[]{
                        "sokey", "old_sokey", "selected_sokey", "client_sokey", "hidden",
                        "dexkey", "selected_dexkey", "client_dexkey", "fb", "f_b",
                        "selected_key", "dynamic_key", "dynamic_keys", "post_key", "xor_key", "aes_key",
                        "decrypt_summary", "decrypt_report", "decrypt_report_json",
                        "ancient_report", "ancient_report_json", "decrypt_info", "decrypt_info_json",
                        "decrypt_result", "decrypt_result_json", "result_json", "report_json",
                        "output_json", "analysis_json", "dynamic_restore", "dynamic_restore_json",
                        "project_meta", "project_meta_json", "project_file", "downloadable_files",
                        "files", "output_files", "result_files", "stdout", "stderr", "command", "cmdline",
                        "options", "request_options", "payload", "request_json", "params_json"
                };
                for (int i = 0; i < sensitiveKeys.length; i++) o.remove(sensitiveKeys[i]);

                JSONObject safeOptions = new JSONObject();
                safeOptions.put("whitelist_protected", true);
                safeOptions.put("error_code", "whitelist_protected");
                safeOptions.put("message", "白名单保护");
                o.put("options_json", safeOptions);
                o.put("whitelist_protected", true);
                o.put("client_whitelist_protected", true);
                o.put("error_code", "whitelist_protected");
                o.put("status", "failed");
                o.put("error_text", "白名单保护");
                o.put("message", "白名单保护");
                o.put("result_text", "白名单保护");
                o.put("file_count", 0);
                o.put("downloadable_file_count", 0);
                o.put("client_output_file_count", 0);
                o.put("output_file_count", 0);
                o.put("result_file_count", 0);
                o.put("decrypted_file_count", 0);
                o.put("total_bytes", 0);
            } catch(Exception ignored) {}
        }

        void normalizeKnownAncientTask(JSONObject o) {
            if (o == null) return;
            try {
                if (isWhitelistProtectedTask(o, null)) {
                    redactWhitelistProtectedTask(o);
                }
                if (rawTaskSaysAncient(o)) rememberAncientTask(o);
                boolean knownAncient = isKnownAncientTask(o);
                if (knownAncient) {
                    o.put("decrypt_scheme", "ancient");
                    o.put("decrypt_version", "ancient");
                    o.put("task_version", "ancient");
                    o.put("client_final_scheme", "ancient");
                    o.put("legacy_iapp", true);
                    o.put("old_iapp", true);
                }
                // V100: 服务端提交报告前可能短暂返回 failed，但只要已经有输出文件，
                // 客户端不展示终态失败；统一显示为解密中，等待下一轮状态变成 done。
                String st = safe(o.optString("status", "")).trim().toLowerCase(Locale.US);
                int outputCount = taskOutputFileCount(o, null);
                if ("failed".equals(st) && outputCount > 0) {
                    o.put("status", "running");
                    o.put("error_text", "");
                    if (knownAncient && !o.has("decrypt_summary")) {
                        o.put("decrypt_summary", "远古解密已写出文件，正在提交最终报告。");
                    }
                }
            } catch(Exception ignored) {}
        }

        void applyTasksResponse(JSONObject r, BaseAdapter ad) {
            try {
                JSONArray arr = r == null ? null : r.optJSONArray("items");
                // Malformed/partial responses must not erase the last good history.
                if (arr == null) {
                    if (ad != null) ad.notifyDataSetChanged();
                    updateHomeTaskCountChip();
                    return;
                }
                int totalFromServer = -1;
                if (r.has("total_count")) totalFromServer = r.optInt("total_count", -1);
                else if (r.has("server_task_count")) totalFromServer = r.optInt("server_task_count", -1);
                else if (r.has("count")) totalFromServer = r.optInt("count", -1);
                int returnedFromServer = r.has("returned_count") ? r.optInt("returned_count", arr.length()) : arr.length();
                if (totalFromServer < 0) totalFromServer = arr.length();
                serverTaskReturnedCount = Math.max(0, returnedFromServer);
                serverTaskTotalCount = Math.max(totalFromServer, arr.length());
                tasks.clear();
                // V117：上传成功后，本地占位任务已经拿到服务器 task_id。
                // 刷新列表时必须按 id/task_no 去重，否则同一个任务会同时显示为
                // “本地执行中”和“服务器执行中”两张卡片。
                HashSet<Integer> pendingIds = new HashSet<Integer>();
                HashSet<String> pendingNos = new HashSet<String>();
                for (int i=0;i<pendingTasks.size();i++) {
                    JSONObject p = pendingTasks.get(i);
                    if (p == null) continue;
                    tasks.add(p);
                    int pid = p.optInt("id", 0);
                    String pno = safe(p.optString("task_no", "")).trim();
                    if (pid > 0) pendingIds.add(Integer.valueOf(pid));
                    if (pno.length() > 0 && !"local".equals(pno)) pendingNos.add(pno);
                }
                for(int i=0;i<arr.length();i++) {
                    JSONObject item = arr.optJSONObject(i);
                    if (item == null) continue;
                    int sid = item.optInt("id", 0);
                    String sno = safe(item.optString("task_no", "")).trim();
                    if ((sid > 0 && pendingIds.contains(Integer.valueOf(sid)))
                            || (sno.length() > 0 && pendingNos.contains(sno))) {
                        continue;
                    }
                    normalizeKnownAncientTask(item);
                    taskOutputFileCount(item, null);
                    tasks.add(item);
                }
                persistTaskHistory();
                if (ad != null) ad.notifyDataSetChanged();
                updateHomeTaskCountChip();
            } catch(Exception e) {}
        }

        interface Job { Object run() throws Exception; }
        interface Done { void ok(Object o); }
        
        boolean shouldShowBlockingLoading(String title) {
            if (title == null) return true;
            // 查询类请求不再弹出阻塞窗口：优先显示缓存/当前页面，后台静默刷新。
            return !(title.indexOf("加载") >= 0 || title.indexOf("读取") >= 0 || title.indexOf("刷新") >= 0 || title.indexOf("验证码") >= 0 || title.indexOf("创建任务") >= 0 || title.indexOf("上传") >= 0);
        }
        
        // 查询/创建/上传静默处理，页面列表直接显示临时任务状态。
        void async(final String title, final Job job, final Done done) {
            final boolean showDialog = shouldShowBlockingLoading(title);
            final AlertDialog[] pdRef = new AlertDialog[1];
            if (showDialog) {
                pdRef[0] = showGoogleLoading(title == null ? "正在处理..." : title);
            }
            new Thread(new Runnable() { public void run() {
                try {
                    final Object r = job.run();
                    a.runOnUiThread(new Runnable(){ public void run(){ if(pdRef[0]!=null) pdRef[0].dismiss(); if(done!=null) done.ok(r); }});
                } catch (final AuthException e) {
                    clearClientSessionPreservingDeviceSettings();
                    loginApiTapEnabled = false;
                    a.runOnUiThread(new Runnable(){ public void run(){
                        if(pdRef[0]!=null) pdRef[0].dismiss();
                        Toast.makeText(a, "登录已失效，请重新登录", Toast.LENGTH_LONG).show();
                        showLogin();
                    }});
                } catch (final Exception e) {
                    final boolean quietTransient = !showDialog && isTransientNetworkError(e);
                    a.runOnUiThread(new Runnable(){ public void run(){
                        if(pdRef[0]!=null) pdRef[0].dismiss();
                        if (!quietTransient) Toast.makeText(a, e.getMessage()==null?String.valueOf(e):e.getMessage(), Toast.LENGTH_LONG).show();
                    }});
                }
            }}).start();
        }

        boolean isTransientNetworkError(Exception e) {
            try {
                String msg = e == null || e.getMessage() == null ? String.valueOf(e) : e.getMessage();
                msg = msg == null ? "" : msg.toLowerCase(Locale.US);
                return msg.indexOf("timeout") >= 0
                        || msg.indexOf("timed out") >= 0
                        || msg.indexOf("504") >= 0
                        || msg.indexOf("gateway") >= 0
                        || msg.indexOf("connection reset") >= 0
                        || msg.indexOf("connection abort") >= 0
                        || msg.indexOf("unexpected end") >= 0
                        || msg.indexOf("network") >= 0;
            } catch(Exception ignored) { return false; }
        }

        void showLogin() {
            LinearLayout outer = vbox();
            outer.setGravity(Gravity.CENTER);
            outer.setPadding(dp(24), dp(24), dp(24), dp(24));
            outer.setBackgroundColor(MD3_SURFACE);

            LinearLayout page = vbox();
            page.setPadding(dp(32), dp(40), dp(32), dp(40));

            TextView title = tv("iAPT", 30, TEXT_MAIN, Typeface.BOLD);
            TextView sub = tv("欢迎来到 iAPT 工作台", 15, TEXT_SUB, 0);
            title.setGravity(Gravity.CENTER);
            sub.setGravity(Gravity.CENTER);
            sub.setClickable(true);
            sub.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ onLoginIntroTapped(); }});

            final EditText user = edit("用户名");
            user.setSingleLine(true);
            final EditText pass = edit("密码");
            pass.setSingleLine(true);
            pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

            Button login = btnPrimary("登 录");
            Button reg = btnOutline("注册新账号");

            addM(page, title, -1, -2, 0, 0, 0, 8);
            addM(page, sub, -1, -2, 0, 0, 0, 40);
            addM(page, user, -1, dp(56), 0, 0, 0, 16);
            addM(page, pass, -1, dp(56), 0, 0, 0, 32);
            addM(page, login, -1, dp(54), 0, 0, 0, 16);
            if(appConfig != null && appConfig.optBoolean("register_enabled", false)) addM(page, reg, -1, dp(54), 0, 0, 0, 0);

            outer.addView(page, new LinearLayout.LayoutParams(-1, -2));

            reg.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showRegister(); }});
            login.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final String u = user.getText().toString().trim();
                final String p = pass.getText().toString();
                if (u.length()==0 || p.length()==0) { toast("请输入用户名和密码"); return; }
                async("正在登录...", new Job(){ public Object run() throws Exception {
                    JSONObject body = new JSONObject(); body.put("username", u); body.put("password", p);
                    JSONObject r = api.post("/login", body, "");
                    String token = r.optString("token", "");
                    if (token.length()==0) throw new Exception("登录返回 token 为空");
                    sp.edit().putString("token", token).putInt("user_id", r.optJSONObject("user") == null ? 0 : r.optJSONObject("user").optInt("id",0)).apply();
                    return r;
                }}, new Done(){ public void ok(Object o){ try { JSONObject rr=(JSONObject)o; JSONObject cfg=extractAppConfig(rr); if(cfg!=null) appConfig=cfg; } catch(Exception e) {} loginApiTapEnabled = false; loginApiTapCount = 0; loginApiLastTapMs = 0L; toast("登录成功"); showShell(); postAnnouncementCheck(); }});
            }});
            setRoot(outer);
        }


        String regCaptchaId = "";
        ImageView regCaptchaImg;

        void showRegister() {
            LinearLayout outer = vbox();
            outer.setGravity(Gravity.CENTER);
            outer.setPadding(dp(20), dp(24), dp(20), dp(24));
            outer.setBackgroundColor(MD3_SURFACE);

            LinearLayout page = vbox();
            page.setPadding(dp(24), dp(28), dp(24), dp(24));
            page.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 28));
            softElev(page, 4);

            TextView title = tv("注册账号", 27, TEXT_MAIN, Typeface.BOLD);
            title.setGravity(Gravity.CENTER);

            final EditText name = edit("昵称，可留空");
            name.setSingleLine(true);
            name.setBackground(strokeBg(MD3_SURFACE, 14, MD3_PRIMARY));

            final EditText user = edit("用户名，3-64位");
            user.setSingleLine(true);
            user.setBackground(strokeBg(MD3_SURFACE, 14, MD3_PRIMARY));

            final EditText pass = edit("密码，至少6位");
            pass.setSingleLine(true);
            pass.setInputType(
                    InputType.TYPE_CLASS_TEXT |
                    InputType.TYPE_TEXT_VARIATION_PASSWORD);
            pass.setBackground(strokeBg(MD3_SURFACE, 14, MD3_PRIMARY));

            regCaptchaImg = new ImageView(a);
            regCaptchaImg.setAdjustViewBounds(true);
            regCaptchaImg.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));
            regCaptchaImg.setPadding(dp(8), dp(8), dp(8), dp(8));

            final EditText cap = edit("输入图形验证码");
            cap.setSingleLine(true);
            cap.setBackground(strokeBg(MD3_SURFACE, 14, MD3_PRIMARY));

            Button refresh = btn(
                    "刷新验证码",
                    MD3_PRIMARY_CONTAINER,
                    MD3_ON_PRIMARY_CONTAINER);
            Button go = btnPrimary("提交注册");
            Button back = btn(
                    "返回登录",
                    MD3_PRIMARY_CONTAINER,
                    MD3_ON_PRIMARY_CONTAINER);

            addM(page, title, -1, dp(48), 0, 0, 0, 20);
            addM(page, name, -1, dp(54), 0, 0, 0, 12);
            addM(page, user, -1, dp(54), 0, 0, 0, 12);
            addM(page, pass, -1, dp(54), 0, 0, 0, 12);
            addM(page, regCaptchaImg, -1, dp(82), 0, 0, 0, 12);
            addM(page, cap, -1, dp(54), 0, 0, 0, 12);
            addM(page, refresh, -1, dp(48), 0, 0, 0, 12);
            addM(page, go, -1, dp(52), 0, 0, 0, 12);
            addM(page, back, -1, dp(50), 0, 0, 0, 0);

            outer.addView(page, new LinearLayout.LayoutParams(-1, -2));

            refresh.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    resetClickAnimTree(v);
                    loadRegisterCaptcha();
                }
            });

            back.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    resetClickAnimTree(v);
                    showLogin();
                }
            });

            go.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    resetClickAnimTree(v);
                    final String u = user.getText().toString().trim();
                    final String p = pass.getText().toString();
                    final String cc = cap.getText().toString().trim();
                    if (u.length() < 3 || p.length() < 6 ||
                            cc.length() == 0 || regCaptchaId.length() == 0) {
                        toast("请完整填写注册信息和验证码");
                        return;
                    }

                    async("正在注册...", new Job() {
                        public Object run() throws Exception {
                            JSONObject o = new JSONObject();
                            o.put("username", u);
                            o.put("password", p);
                            o.put("name", name.getText().toString().trim());
                            o.put("captcha_id", regCaptchaId);
                            o.put("captcha_code", cc);
                            return api.post("/register", o, "");
                        }
                    }, new Done() {
                        public void ok(Object o) {
                            JSONObject r = (JSONObject)o;
                            String token = r.optString("token", "");
                            if (token.length() > 0) {
                                sp.edit()
                                        .putString("token", token)
                                        .putInt(
                                                "user_id",
                                                r.optJSONObject("user") == null
                                                        ? 0
                                                        : r.optJSONObject("user")
                                                                .optInt("id", 0))
                                        .apply();
                            }
                            toast("注册成功");
                            validateTokenAndEnter();
                        }
                    });
                }
            });

            setRoot(outer);
            loadRegisterCaptcha();
        }


        void loadRegisterCaptcha() {
            async("正在加载验证码...", new Job(){ public Object run() throws Exception { return api.getPublic("/captcha"); }}, new Done(){ public void ok(Object o){ try{ JSONObject r=(JSONObject)o; regCaptchaId=r.optString("captcha_id",""); byte[] data=android.util.Base64.decode(r.optString("image_base64",""), android.util.Base64.NO_WRAP); Bitmap bm=BitmapFactory.decodeByteArray(data,0,data.length); if(regCaptchaImg!=null) regCaptchaImg.setImageBitmap(bm); }catch(Exception e){ toast("验证码显示失败："+e.getMessage()); } }});
        }

        // 手写 MD3 动画 Switch 开关，用于新版设置弹窗。
        View createMd3Switch(boolean initialState, final View.OnClickListener onToggle) {
            final FrameLayout track = new FrameLayout(a);
            track.setLayoutParams(new LinearLayout.LayoutParams(dp(52), dp(32)));

            final View thumb = new View(a);
            FrameLayout.LayoutParams thumbLp = new FrameLayout.LayoutParams(dp(24), dp(24));
            thumbLp.gravity = Gravity.CENTER_VERTICAL;
            thumbLp.leftMargin = dp(4);
            thumb.setLayoutParams(thumbLp);
            track.addView(thumb);

            final boolean[] isChecked = new boolean[]{initialState};

            if (isChecked[0]) {
                track.setBackground(bg(MD3_PRIMARY, 999));
                thumb.setBackground(bg(MD3_ON_PRIMARY, 999));
                thumb.setTranslationX(dp(20));
            } else {
                track.setBackground(strokeBg(MD3_SURFACE_CONTAINER_HIGH, 999, TEXT_SUB));
                thumb.setBackground(bg(TEXT_SUB, 999));
                thumb.setTranslationX(0);
            }

            track.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                isChecked[0] = !isChecked[0];
                if (isChecked[0]) {
                    track.setBackground(bg(MD3_PRIMARY, 999));
                    thumb.setBackground(bg(MD3_ON_PRIMARY, 999));
                } else {
                    track.setBackground(strokeBg(MD3_SURFACE_CONTAINER_HIGH, 999, TEXT_SUB));
                    thumb.setBackground(bg(TEXT_SUB, 999));
                }
                if (Build.VERSION.SDK_INT >= 11) {
                    android.animation.ObjectAnimator anim = android.animation.ObjectAnimator.ofFloat(thumb, "translationX", isChecked[0] ? dp(20) : 0);
                    anim.setDuration(430);
                    anim.start();
                } else {
                    thumb.setTranslationX(isChecked[0] ? dp(20) : 0);
                }
                if (onToggle != null) onToggle.onClick(v);
            }});

            addClickAnim(track);
            return track;
        }

        // 标准 MD3 风格弹窗。真实任务创建仍通过功能页入口发起，这里作为 FAB 的快速设置面板。
        void showMD3SettingsDialog() {
            final LinearLayout dView = vbox();
            dView.setPadding(dp(24), dp(24), dp(24), dp(16));
            dView.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 28));

            TextView title = tv("设置", 24, TEXT_MAIN, Typeface.NORMAL);
            dView.addView(title, new LinearLayout.LayoutParams(-1, -2));
            dView.addView(new Space(a), new LinearLayout.LayoutParams(-1, dp(14)));

            TextView section = tv("DexKey 获取方案", 17, TEXT_MAIN, Typeface.BOLD);
            dView.addView(section, new LinearLayout.LayoutParams(-1, -2));
            dView.addView(new Space(a), new LinearLayout.LayoutParams(-1, dp(8)));

            final RadioGroup modeGroup = new RadioGroup(a);
            modeGroup.setOrientation(RadioGroup.VERTICAL);
            modeGroup.setPadding(dp(2), 0, dp(2), 0);
            final RadioButton staticMode = roleRadio("方案1", dexkeyAcquireMode() == DEXKEY_MODE_STATIC);
            final RadioButton dynamicMode = roleRadio("方案2(有安全风险)", dexkeyAcquireMode() == DEXKEY_MODE_DYNAMIC);
            staticMode.setId(View.generateViewId());
            dynamicMode.setId(View.generateViewId());
            modeGroup.addView(staticMode, new RadioGroup.LayoutParams(-1, dp(46)));
            modeGroup.addView(dynamicMode, new RadioGroup.LayoutParams(-1, dp(46)));
            dView.addView(modeGroup, new LinearLayout.LayoutParams(-1, -2));

            final int[] pendingMode = new int[]{dexkeyAcquireMode()};
            modeGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener(){ public void onCheckedChanged(RadioGroup group, int checkedId){
                pendingMode[0] = checkedId == dynamicMode.getId() ? DEXKEY_MODE_DYNAMIC : DEXKEY_MODE_STATIC;
            }});

            dView.addView(new Space(a), new LinearLayout.LayoutParams(-1, dp(18)));

            LinearLayout btnRow = hbox();
            btnRow.setGravity(Gravity.RIGHT);
            TextView btnCancel = tv("取消", 14, MD3_PRIMARY, Typeface.BOLD);
            btnCancel.setPadding(dp(16), dp(10), dp(16), dp(10));
            addClickAnim(btnCancel);
            TextView btnConfirm = tv("保存", 14, MD3_ON_PRIMARY, Typeface.BOLD);
            btnConfirm.setPadding(dp(24), dp(10), dp(24), dp(10));
            btnConfirm.setBackground(bg(MD3_PRIMARY, 999));
            addClickAnim(btnConfirm);
            btnRow.addView(btnCancel);
            btnRow.addView(new Space(a), new LinearLayout.LayoutParams(dp(8), 1));
            btnRow.addView(btnConfirm);
            dView.addView(btnRow, new LinearLayout.LayoutParams(-1, -2));

            final AlertDialog dialog = new AlertDialog.Builder(a).create();
            dialog.setView(dView);
            dialog.show();
            animateDialogIn(dialog, false);
            try {
                if (dialog.getWindow() != null) {
                    dialog.getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
                }
            } catch(Exception ignored) {}
            btnCancel.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dialog.dismiss(); }});
            btnConfirm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                sp.edit().putInt(PREF_DEXKEY_ACQUIRE_MODE, pendingMode[0]).apply();
                toast("DexKey 获取方案已保存：" + dexkeyAcquireModeLabel());
                dialog.dismiss();
            }});
        }

        // 功能弹窗内容区域：内容少时按实际高度，内容多时限制高度并允许内部滚动。
        class Md3FeatureContentHost extends FrameLayout {
            final int maxHeightPx;

            Md3FeatureContentHost(int maxHeightPx) {
                super(a);
                this.maxHeightPx = maxHeightPx;
                setBackgroundColor(Color.TRANSPARENT);
                setPadding(dp(2), dp(2), dp(2), dp(2));
                setClipToPadding(false);
                setClipChildren(false);
            }

            @Override
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int mode = View.MeasureSpec.getMode(heightMeasureSpec);
                int size = View.MeasureSpec.getSize(heightMeasureSpec);
                int cap = maxHeightPx;
                if (mode != View.MeasureSpec.UNSPECIFIED) cap = Math.min(cap, size);
                int cappedHeight = View.MeasureSpec.makeMeasureSpec(
                        Math.max(0, cap), View.MeasureSpec.AT_MOST);
                super.onMeasure(widthMeasureSpec, cappedHeight);
            }
        }

        // 截图同款右侧 MD3 开关。继承 CheckBox，因此原业务的
        // isChecked / setChecked / OnCheckedChangeListener 全部保持可用。
        class Md3FeatureSwitch extends CheckBox {
            final android.graphics.Paint featurePaint =
                    new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
            final android.graphics.RectF featureRect =
                    new android.graphics.RectF();
            android.animation.ValueAnimator featureAnimator;
            float featureProgress = 0f;
            boolean featureAttached = false;

            Md3FeatureSwitch(String text) {
                super(a);
                setText(text == null ? "" : text);
                setTextSize(16);
                setTextColor(TEXT_MAIN);
                setGravity(Gravity.CENTER_VERTICAL);
                setIncludeFontPadding(false);
                setMinHeight(dp(48));
                setPadding(0, 0, dp(72), 0);
                setButtonDrawable(
                        new android.graphics.drawable.ColorDrawable(
                                Color.TRANSPARENT));
                setBackground(
                        new android.graphics.drawable.ColorDrawable(
                                Color.TRANSPARENT));
                if (Build.VERSION.SDK_INT >= 23) setForeground(null);
                if (Build.VERSION.SDK_INT >= 21) setStateListAnimator(null);
                setClickable(true);
                setFocusable(true);
                featureProgress = isChecked() ? 1f : 0f;
            }

            int featureAlphaColor(int color, float alpha) {
                return Color.argb(
                        Math.max(0, Math.min(255, (int)(255f * alpha))),
                        Color.red(color),
                        Color.green(color),
                        Color.blue(color));
            }

            int featureBlendColor(int from, int to, float fraction) {
                fraction = Math.max(0f, Math.min(1f, fraction));
                int a0 = Color.alpha(from);
                int r0 = Color.red(from);
                int g0 = Color.green(from);
                int b0 = Color.blue(from);
                return Color.argb(
                        (int)(a0 + (Color.alpha(to) - a0) * fraction),
                        (int)(r0 + (Color.red(to) - r0) * fraction),
                        (int)(g0 + (Color.green(to) - g0) * fraction),
                        (int)(b0 + (Color.blue(to) - b0) * fraction));
            }

            void animateFeatureProgress(float target) {
                if (featureAnimator != null) featureAnimator.cancel();

                final float start = featureProgress;
                if (!featureAttached || getWidth() <= 0 ||
                        Math.abs(start - target) < 0.001f) {
                    featureProgress = target;
                    invalidate();
                    return;
                }

                featureAnimator =
                        android.animation.ValueAnimator.ofFloat(start, target);
                featureAnimator.setDuration(430);
                featureAnimator.setInterpolator(
                        new android.view.animation.DecelerateInterpolator(1.6f));
                featureAnimator.addUpdateListener(
                        new android.animation.ValueAnimator
                                .AnimatorUpdateListener() {
                    public void onAnimationUpdate(
                            android.animation.ValueAnimator animator) {
                        featureProgress =
                                ((Float)animator.getAnimatedValue()).floatValue();
                        invalidate();
                    }
                });
                featureAnimator.start();
            }

            @Override
            public void setChecked(boolean checked) {
                boolean changed = checked != isChecked();
                super.setChecked(checked);
                if (changed) {
                    animateFeatureProgress(checked ? 1f : 0f);
                } else if (!featureAttached) {
                    featureProgress = checked ? 1f : 0f;
                    invalidate();
                }
            }

            @Override
            protected void onAttachedToWindow() {
                super.onAttachedToWindow();
                featureAttached = true;
                featureProgress = isChecked() ? 1f : 0f;
                invalidate();
            }

            @Override
            protected void onDetachedFromWindow() {
                featureAttached = false;
                if (featureAnimator != null) featureAnimator.cancel();
                super.onDetachedFromWindow();
            }

            @Override
            public void drawableHotspotChanged(float x, float y) {
                // 不调用 super，彻底屏蔽默认 CheckBox 点击波纹。
            }

            @Override
            protected void onDraw(android.graphics.Canvas canvas) {
                super.onDraw(canvas);

                float p = Math.max(0f, Math.min(1f, featureProgress));
                float enabledAlpha = isEnabled() ? 1f : 0.38f;
                float trackW = dp(52);
                float trackH = dp(32);

                // 整体左移 4dp，给右侧描边留出完整像素空间。
                float left = getWidth() - trackW - dp(4);
                float top = (getHeight() - trackH) / 2f;
                float right = left + trackW;
                float bottom = top + trackH;

                featureRect.set(left, top, right, bottom);
                featurePaint.setStrokeWidth(dp(2));

                int trackColor = featureBlendColor(
                        MD3_SURFACE_CONTAINER_HIGH,
                        MD3_PRIMARY,
                        p);

                featurePaint.setStyle(android.graphics.Paint.Style.FILL);
                featurePaint.setColor(
                        featureAlphaColor(trackColor, enabledAlpha));
                canvas.drawRoundRect(
                        featureRect,
                        trackH / 2f,
                        trackH / 2f,
                        featurePaint);

                if (p < 0.999f) {
                    featurePaint.setStyle(
                            android.graphics.Paint.Style.STROKE);
                    featurePaint.setColor(
                            featureAlphaColor(
                                    TEXT_SUB,
                                    enabledAlpha * (1f - p)));
                    canvas.drawRoundRect(
                            featureRect,
                            trackH / 2f,
                            trackH / 2f,
                            featurePaint);
                }

                float thumbRadius = dp(12);
                float offX = left + dp(4) + thumbRadius;
                float onX = right - dp(4) - thumbRadius;
                float thumbCenterX = offX + (onX - offX) * p;
                float thumbCenterY = top + trackH / 2f;

                int thumbColor = featureBlendColor(
                        TEXT_SUB,
                        MD3_ON_PRIMARY,
                        p);
                featurePaint.setStyle(android.graphics.Paint.Style.FILL);
                featurePaint.setColor(
                        featureAlphaColor(thumbColor, enabledAlpha));
                canvas.drawCircle(
                        thumbCenterX,
                        thumbCenterY,
                        thumbRadius,
                        featurePaint);
            }

            @Override
            protected void drawableStateChanged() {
                super.drawableStateChanged();
                invalidate();
            }
        }

        CheckBox md3FeatureSwitch(String text) {
            Md3FeatureSwitch featureSwitch = new Md3FeatureSwitch(text);
            featureSwitch.setBackground(
                    new android.graphics.drawable.ColorDrawable(
                            Color.TRANSPARENT));
            return featureSwitch;
        }

        // 所有云端功能弹窗的主标题固定为“任务选项设置”；
        // 具体功能名只显示为紫色副标题。

        void styleMd3FeatureContentButtons(View view) {
            if (view == null) return;

            // CheckBox / Switch / RadioButton 都继承 Button。
            // 必须先排除，否则会把整条开关选项刷成浅紫色背景。
            if (view instanceof CompoundButton) {
                return;
            }

            if (view instanceof Button) {
                Button button = (Button)view;
                button.setAllCaps(false);
                button.setTextColor(MD3_ON_PRIMARY_CONTAINER);
                button.setTypeface(
                        Typeface.create("sans-serif-medium", Typeface.BOLD));
                button.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));
                button.setStateListAnimator(null);
                if (Build.VERSION.SDK_INT >= 21) button.setElevation(0f);
                return;
            }

            if (view instanceof ViewGroup) {
                ViewGroup group = (ViewGroup)view;
                for (int i = 0; i < group.getChildCount(); i++) {
                    styleMd3FeatureContentButtons(group.getChildAt(i));
                }
            }
        }

        AlertDialog.Builder md3FeatureDialog(String featureName, View view) {
            LinearLayout container = vbox();
            container.setTag("iapt_md3_feature_container");
            container.setPadding(dp(24), dp(24), dp(24), dp(18));
            container.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 28));

            TextView head = tv("任务选项设置", 24, TEXT_MAIN, Typeface.BOLD);
            container.addView(head, new LinearLayout.LayoutParams(-1, -2));

            TextView feature = tv(featureName, 13, MD3_PRIMARY, Typeface.BOLD);
            LinearLayout.LayoutParams featureLp =
                    new LinearLayout.LayoutParams(-1, -2);
            featureLp.topMargin = dp(6);
            container.addView(feature, featureLp);

            int maxContentHeight =
                    (int)(a.getResources().getDisplayMetrics().heightPixels * 0.64f);
            Md3FeatureContentHost host =
                    new Md3FeatureContentHost(maxContentHeight);
            host.setTag("iapt_md3_feature_content_host");
            styleMd3FeatureContentButtons(view);
            FrameLayout.LayoutParams hostedContentLp =
                    new FrameLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT);
            hostedContentLp.setMargins(dp(1), dp(1), dp(1), dp(1));
            host.addView(view, hostedContentLp);

            LinearLayout.LayoutParams contentLp =
                    new LinearLayout.LayoutParams(-1, -2);
            contentLp.topMargin = dp(16);
            container.addView(host, contentLp);

            return new AlertDialog.Builder(a).setView(container);
        }

        void styleMd3FeatureActionButton(
                Button button, boolean primary, String text) {
            if (button == null) return;
            button.setText(text);
            button.setAllCaps(false);
            button.setTextSize(15);
            button.setGravity(Gravity.CENTER);
            button.setTypeface(
                    Typeface.create("sans-serif-medium", Typeface.BOLD));
            button.setMinHeight(dp(50));
            button.setStateListAnimator(null);

            if (primary) {
                button.setTextColor(MD3_ON_PRIMARY);
                button.setBackground(bg(MD3_PRIMARY, 999));
                button.setPadding(dp(24), dp(8), dp(24), dp(8));
                addClickAnim(button);
            } else {
                button.setTextColor(MD3_PRIMARY);
                button.setBackground(
                        new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
                button.setPadding(dp(16), dp(8), dp(16), dp(8));
            }
        }

        // 把系统默认按钮栏移入自定义淡紫面板，避免按钮跑到圆角弹窗外面。
        // 复用原 Button 对象，所以各功能原来的点击监听和校验逻辑不会丢失。
        void showMd3FeatureDialogWindow(final AlertDialog dialog) {
            dialog.show();
            animateDialogIn(dialog, false);

            try {
                final android.view.Window window = dialog.getWindow();
                if (window == null) return;

                window.setBackgroundDrawable(
                        bg(MD3_SURFACE_CONTAINER_HIGH, 28));
                window.addFlags(
                        android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND);

                android.view.WindowManager.LayoutParams attrs =
                        window.getAttributes();
                attrs.dimAmount = 0.58f;
                window.setAttributes(attrs);

                final int width =
                        (int)(a.getResources()
                                .getDisplayMetrics().widthPixels * 0.94f);
                window.setLayout(
                        width,
                        ViewGroup.LayoutParams.WRAP_CONTENT);

                final LinearLayout container =
                        (LinearLayout)window.getDecorView().findViewWithTag(
                                "iapt_md3_feature_container");

                final Button originalNegative =
                        dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
                final Button originalPositive =
                        dialog.getButton(AlertDialog.BUTTON_POSITIVE);

                String positiveText = originalPositive == null
                        ? ""
                        : String.valueOf(originalPositive.getText()).trim();
                if (positiveText.length() == 0) positiveText = "开始";

                ViewGroup oldButtonParent = null;
                if (originalPositive != null &&
                        originalPositive.getParent() instanceof ViewGroup) {
                    oldButtonParent =
                            (ViewGroup)originalPositive.getParent();
                } else if (originalNegative != null &&
                        originalNegative.getParent() instanceof ViewGroup) {
                    oldButtonParent =
                            (ViewGroup)originalNegative.getParent();
                }
                if (oldButtonParent != null) {
                    oldButtonParent.setVisibility(View.GONE);
                }

                if (container != null &&
                        container.findViewWithTag(
                                "iapt_md3_feature_action_row") == null) {
                    LinearLayout actionRow = hbox();
                    actionRow.setTag("iapt_md3_feature_action_row");
                    actionRow.setGravity(
                            Gravity.RIGHT | Gravity.CENTER_VERTICAL);
                    actionRow.setBackgroundColor(Color.TRANSPARENT);

                    Button cancelButton = new Button(a);
                    cancelButton.setText("取消");
                    cancelButton.setTextColor(MD3_PRIMARY);
                    cancelButton.setTextSize(15);
                    cancelButton.setAllCaps(false);
                    cancelButton.setGravity(Gravity.CENTER);
                    cancelButton.setTypeface(
                            Typeface.create(
                                    "sans-serif-medium",
                                    Typeface.BOLD));
                    cancelButton.setBackground(
                            new android.graphics.drawable.ColorDrawable(
                                    Color.TRANSPARENT));
                    cancelButton.setStateListAnimator(null);
                    cancelButton.setPadding(
                            dp(16), dp(8), dp(16), dp(8));
                    cancelButton.setOnClickListener(
                            new View.OnClickListener() {
                        public void onClick(View v) {
                            resetClickAnimTree(v);
                            if (originalNegative != null) {
                                originalNegative.performClick();
                            } else {
                                dialog.dismiss();
                            }
                        }
                    });

                    Button startButton = new Button(a);
                    startButton.setText(positiveText);
                    startButton.setTextColor(Color.WHITE);
                    startButton.setTextSize(15);
                    startButton.setAllCaps(false);
                    startButton.setGravity(Gravity.CENTER);
                    startButton.setTypeface(
                            Typeface.create(
                                    "sans-serif-medium",
                                    Typeface.BOLD));
                    startButton.setBackground(bg(MD3_PRIMARY, 999));
                    startButton.setStateListAnimator(null);
                    startButton.setPadding(
                            dp(24), dp(8), dp(24), dp(8));
                    addClickAnim(startButton);
                    startButton.setOnClickListener(
                            new View.OnClickListener() {
                        public void onClick(View v) {
                            resetClickAnimTree(v);
                            if (originalPositive != null) {
                                originalPositive.performClick();
                            }
                        }
                    });

                    actionRow.addView(
                            cancelButton,
                            new LinearLayout.LayoutParams(-2, dp(50)));

                    LinearLayout.LayoutParams startLp =
                            new LinearLayout.LayoutParams(dp(132), dp(50));
                    startLp.leftMargin = dp(12);
                    actionRow.addView(startButton, startLp);

                    LinearLayout.LayoutParams actionLp =
                            new LinearLayout.LayoutParams(-1, dp(50));
                    actionLp.topMargin = dp(20);
                    container.addView(actionRow, actionLp);
                }

                window.getDecorView().post(new Runnable() {
                    public void run() {
                        try {
                            int maxHeight =
                                    (int)(a.getResources()
                                            .getDisplayMetrics()
                                            .heightPixels * 0.90f);
                            int measured =
                                    window.getDecorView().getHeight();
                            window.setLayout(
                                    width,
                                    measured > maxHeight
                                            ? maxHeight
                                            : ViewGroup.LayoutParams
                                                    .WRAP_CONTENT);
                        } catch(Exception ignored) {}
                    }
                });
            } catch(Exception ignored) {}
        }



        void showShell() {
            restorePersistedTaskHistory();

            rootLayout = new RelativeLayout(a);
            rootLayout.setBackgroundColor(MD3_SURFACE);

            content = new SwipeFrameLayout(a);
            content.setSwipeCallback(new SwipeCallback() {
                public void onSwipe(int direction) {
                    if (!topLevelPage) return;
                    navigateMainTab(currentMainTab + direction, true);
                }
            });
            RelativeLayout.LayoutParams contentLp = new RelativeLayout.LayoutParams(-1, -1);
            contentLp.addRule(RelativeLayout.ABOVE, 1001);
            rootLayout.addView(content, contentLp);

            bottomNav = new LinearLayout(a);
            bottomNav.setId(1001);
            bottomNav.setOrientation(LinearLayout.HORIZONTAL);
            bottomNav.setBackgroundColor(MD3_SURFACE_CONTAINER);
            softElev(bottomNav, 12);

            RelativeLayout.LayoutParams navLp = new RelativeLayout.LayoutParams(-1, dp(84));
            navLp.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM);
            rootLayout.addView(bottomNav, navLp);

            navTabs[0] = createNavTab("任务", "ic_nav_tasks");
            navTabs[1] = createNavTab("功能", "ic_nav_functions");
            navTabs[2] = createNavTab("我的", "ic_nav_profile");

            bottomNav.addView(navTabs[0], new LinearLayout.LayoutParams(0, -1, 1));
            bottomNav.addView(navTabs[1], new LinearLayout.LayoutParams(0, -1, 1));
            bottomNav.addView(navTabs[2], new LinearLayout.LayoutParams(0, -1, 1));

            FrameLayout fabWrapper = new FrameLayout(a);
            fabWrapper.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));
            softElev(fabWrapper, 6);

            TextView fabIcon = tv("＋", 28, MD3_ON_PRIMARY_CONTAINER, 0);
            fabIcon.setGravity(Gravity.CENTER);
            fabWrapper.addView(fabIcon, new FrameLayout.LayoutParams(-1, -1));

            RelativeLayout.LayoutParams fabLp = new RelativeLayout.LayoutParams(dp(56), dp(56));
            fabLp.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM);
            fabLp.addRule(RelativeLayout.ALIGN_PARENT_RIGHT);
            fabLp.bottomMargin = dp(100);
            fabLp.rightMargin = dp(16);
            rootLayout.addView(fabWrapper, fabLp);

            addClickAnim(fabWrapper);
            fabWrapper.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showMD3SettingsDialog(); }});

            navTabs[0].setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ navigateMainTab(0, false); }});
            navTabs[1].setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ navigateMainTab(1, false); }});
            navTabs[2].setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ navigateMainTab(2, false); }});

            setRoot(rootLayout);
            currentMainTab = 0;
            showTasks();
        }

        void navigateMainTab(int target, boolean fromSwipe) {
            if (target < 0 || target > 2) return;
            if (target == currentMainTab && topLevelPage) {
                playNavWave(target);
                return;
            }
            nextPageTransitionDirection = target > currentMainTab ? 1 : -1;
            if (target == 0) showTasks();
            else if (target == 1) showFuncs();
            else showMine();
        }

        LinearLayout createNavTab(String title, String drawableName) {
            LinearLayout tab = vbox();
            tab.setGravity(Gravity.CENTER);
            tab.setContentDescription(title);

            FrameLayout stage = new FrameLayout(a);
            stage.setTag("pill");
            stage.setClipChildren(false);
            stage.setClipToPadding(false);
            stage.setBackground(bg(Color.TRANSPARENT, 999));

            View ripple = new View(a);
            ripple.setTag("ripple");
            ripple.setBackground(bg(MD3_PRIMARY, 999));
            ripple.setAlpha(0f);
            ripple.setScaleX(0.18f);
            ripple.setScaleY(0.18f);
            stage.addView(ripple, new FrameLayout.LayoutParams(dp(36), dp(36), Gravity.CENTER));

            ImageView icon = new ImageView(a);
            icon.setTag("icon");
            int drawableId = a.getResources().getIdentifier(drawableName, "drawable", a.getPackageName());
            if (drawableId != 0) icon.setImageResource(drawableId);
            icon.setColorFilter(TEXT_SUB);
            icon.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
            stage.addView(icon, new FrameLayout.LayoutParams(dp(24), dp(24), Gravity.CENTER));

            TextView text = tv(title, 12, TEXT_SUB, Typeface.BOLD);
            text.setTag("text");
            text.setGravity(Gravity.CENTER);

            tab.addView(stage, new LinearLayout.LayoutParams(dp(64), dp(38)));
            tab.addView(text, new LinearLayout.LayoutParams(-1, dp(22)));
            addClickAnim(tab);
            return tab;
        }

        void pulseNavTab(final int tabIndex, long delay, final boolean selected) {
            if (tabIndex < 0 || tabIndex >= navTabs.length || navTabs[tabIndex] == null) return;
            final FrameLayout stage = (FrameLayout)navTabs[tabIndex].findViewWithTag("pill");
            final View ripple = navTabs[tabIndex].findViewWithTag("ripple");
            final ImageView icon = (ImageView)navTabs[tabIndex].findViewWithTag("icon");
            if (stage == null || ripple == null || icon == null) return;
            stage.postDelayed(new Runnable() {
                public void run() {
                    ripple.animate().cancel();
                    icon.animate().cancel();
                    ripple.setAlpha(selected ? 0.25f : 0.16f);
                    ripple.setScaleX(0.18f);
                    ripple.setScaleY(0.18f);
                    ripple.animate()
                            .alpha(0f)
                            .scaleX(selected ? 2.05f : 1.72f)
                            .scaleY(selected ? 2.05f : 1.72f)
                            .setDuration(620)
                            .setInterpolator(new android.view.animation.DecelerateInterpolator(1.4f))
                            .start();
                    icon.setScaleX(0.76f);
                    icon.setScaleY(0.76f);
                    icon.animate()
                            .scaleX(selected ? 1.13f : 1.03f)
                            .scaleY(selected ? 1.13f : 1.03f)
                            .setDuration(260)
                            .setInterpolator(new android.view.animation.OvershootInterpolator(2.0f))
                            .withEndAction(new Runnable() {
                                public void run() {
                                    icon.animate().scaleX(1f).scaleY(1f).setDuration(220).start();
                                }
                            }).start();
                }
            }, delay);
        }

        void playNavWave(int selectedIndex) {
            // 仅播放当前选中项，未选中的导航图标保持静止。
            pulseNavTab(selectedIndex, 0, true);
        }

        void setTab(int index) {
            currentMainTab = index;
            for (int i = 0; i < 3; i++) {
                if (navTabs == null || navTabs[i] == null) continue;
                boolean active = (i == index);
                FrameLayout pill = (FrameLayout) navTabs[i].findViewWithTag("pill");
                TextView text = (TextView) navTabs[i].findViewWithTag("text");
                ImageView icon = (ImageView) navTabs[i].findViewWithTag("icon");
                if (pill != null) pill.setBackground(bg(active ? MD3_PRIMARY_CONTAINER : Color.TRANSPARENT, 999));
                if (text != null) text.setTextColor(active ? MD3_ON_PRIMARY_CONTAINER : TEXT_SUB);
                if (icon != null) icon.setColorFilter(active ? MD3_ON_PRIMARY_CONTAINER : TEXT_SUB);
            }
            playNavWave(index);
        }

        void setTab(boolean task) {
            setTab(task ? 0 : 2);
        }

        void clearContent() {
            if (content != null) content.removeAllViews();
        }

        void addGridLayout(LinearLayout parent, View[] views, int columns) {
            for (int i = 0; i < views.length; i += columns) {
                LinearLayout row = hbox();
                for (int j = 0; j < columns; j++) {
                    if (i + j < views.length) {
                        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1);
                        if (j > 0) lp.leftMargin = dp(14);
                        row.addView(views[i + j], lp);
                    } else {
                        row.addView(new Space(a), new LinearLayout.LayoutParams(0, -2, 1));
                    }
                }
                LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(-1, -2);
                if (i > 0) rowLp.topMargin = dp(14);
                parent.addView(row, rowLp);
            }
        }

        LinearLayout mdFeatureCard(String title, String desc, String letter, int color) {
            LinearLayout c = vbox();
            c.setBackground(bg(MD3_SURFACE_CONTAINER_LOW, 16));
            c.setPadding(dp(16), dp(18), dp(16), dp(16));
            softElev(c, 1);

            if (letter != null && letter.startsWith("@")) {
                FrameLayout iconBox = new FrameLayout(a);
                iconBox.setBackground(bg(color, 12));
                ImageView icon = new ImageView(a);
                int drawableId = a.getResources().getIdentifier(letter.substring(1), "drawable", a.getPackageName());
                if (drawableId != 0) icon.setImageResource(drawableId);
                icon.setColorFilter(Color.WHITE);
                icon.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
                FrameLayout.LayoutParams iconLp = new FrameLayout.LayoutParams(dp(22), dp(22), Gravity.CENTER);
                iconBox.addView(icon, iconLp);
                c.addView(iconBox, new LinearLayout.LayoutParams(dp(40), dp(40)));
            } else {
                TextView icon = textAvatar(letter, color, 18, 12);
                c.addView(icon, new LinearLayout.LayoutParams(dp(40), dp(40)));
            }

            TextView t = tv(title, 15, TEXT_MAIN, Typeface.BOLD);
            LinearLayout.LayoutParams tLp = new LinearLayout.LayoutParams(-1, -2);
            tLp.topMargin = dp(14);
            c.addView(t, tLp);

            TextView d = tv(desc, 12, TEXT_SUB, 0);
            d.setMaxLines(2);
            LinearLayout.LayoutParams dLp = new LinearLayout.LayoutParams(-1, -2);
            dLp.topMargin = dp(4);
            c.addView(d, dLp);

            addClickAnim(c);
            return c;
        }

        LinearLayout mdFunctionRow(String title) {
            LinearLayout card = hbox();
            card.setPadding(dp(16), dp(20), dp(16), dp(20));
            card.setBackground(bg(MD3_SURFACE_CONTAINER_LOW, 16));
            TextView t = tv(title, 16, TEXT_MAIN, Typeface.BOLD);
            card.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
            TextView arrow = tv("›", 22, TEXT_SUB, 0);
            arrow.setGravity(Gravity.CENTER);
            card.addView(arrow, new LinearLayout.LayoutParams(-2, -2));
            addClickAnim(card);
            return card;
        }

        void addFunctionRow(LinearLayout page, View row) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.bottomMargin = dp(12);
            page.addView(row, lp);
        }

        void showFuncs() {
            topLevelPage = true;
            currentMainTab = 1;
            setTab(1);
            clearContent();

            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout page = vbox();
            page.setPadding(dp(16), dp(16), dp(16), dp(40));
            sv.addView(page);
            content.addView(sv, new FrameLayout.LayoutParams(-1, -1));
            applyPageTransition(sv);

            page.addView(tv("解密功能", 16, TEXT_MAIN, Typeface.BOLD), new LinearLayout.LayoutParams(-1, dp(40)));

            LinearLayout v3 = mdFeatureCard("V3 静态解密", "静态解密", "@ic_feature_code", MD3_PRIMARY);
            LinearLayout dynKey = mdFeatureCard("提取动态 Key" + (hasFeature(4) ? "" : "  · 未开通"), "服务端提取", "@ic_feature_key", Color.parseColor("#F59E0B"));
            LinearLayout serverSo = mdFeatureCard("获取 sokey" + (hasFeature(FEATURE_SERVER_SOKEY) ? "" : "  · 未开通"), "服务器环境强制读取", "@ic_feature_server", Color.parseColor("#10B981"));
            LinearLayout v6 = mdFeatureCard("V6 反编译" + (hasFeature(6) ? "" : "  · 未开通"), "v6还原", "@ic_feature_decompile", Color.parseColor("#0EA5E9"));
            LinearLayout sourceRestore = mdFeatureCard("混淆还原" + (hasFeature(8) ? "" : "  · 未开通"), "混淆代码还原", "@ic_feature_restore", MD3_PRIMARY);
            LinearLayout dexRestoreOnly = mdFeatureCard("DEX 还原" + (hasFeature(8) ? "" : "  · 未开通"), "项目内 DEX 与源码同步还原", "@ic_feature_dex", Color.parseColor("#0369A1"));
            LinearLayout numericRestoreOnly = mdFeatureCard("动态修复" + (hasFeature(5) ? "" : "  · 未开通"), "修复数字函数表逻辑", "@ic_feature_repair", Color.parseColor("#E11D48"));
            LinearLayout nativeCompileOnly = mdFeatureCard("原生编译修复" + (hasFeature(FEATURE_NATIVE_COMPILE_RESTORE) ? "" : "  · 未开通"), "DEX 事件源码独立回填", "@ic_feature_dex", Color.parseColor("#7C3AED"));

            addGridLayout(page, new View[]{v3, dynKey, serverSo, v6, sourceRestore, dexRestoreOnly, numericRestoreOnly, nativeCompileOnly}, 2);

            v3.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showCreateTaskDialogBody(null); }});
            dynKey.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(4)) showDynamicKeyExtractDialog(null); else toast("未开通该功能"); }});
            serverSo.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(FEATURE_SERVER_SOKEY)) showServerSoKeyExtractDialog(null); else toast("未开通该功能"); }});
            v6.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(6)) showCreateTaskV6Dialog(null); else toast("未开通该功能"); }});
            sourceRestore.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(8)) showSourceRestoreDialog(null); else toast("未开通该功能"); }});
            dexRestoreOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(8)) showStaticDexSourceRestoreDialog(null); else toast("未开通该功能"); }});
            numericRestoreOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(5)) showNumericSourceRestoreDialog(null); else toast("未开通该功能"); }});
            nativeCompileOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)) showNativeCompileSourceRestoreDialog(null); else toast("未开通该功能"); }});

            page.addView(new Space(a), new LinearLayout.LayoutParams(-1, dp(24)));
            page.addView(tv("本地功能", 16, TEXT_MAIN, Typeface.BOLD), new LinearLayout.LayoutParams(-1, dp(40)));

            syncHookFeatureFlags();
            LinearLayout hookDex = mdFeatureCard("动态提取 Dexkey" + (hasFbHookFeature() ? "" : "  · 未开通"), "本机环境内存抓取", "@ic_feature_dex", MD3_PRIMARY);
            LinearLayout dynTile = mdFeatureCard("动态解密" + (hasDynamicHookFeature() ? "" : "  · 未开通"), "运行实时解密", "@ic_feature_runtime", Color.parseColor("#10B981"));
            LinearLayout funcHook = mdFeatureCard("函数控制" + (hasFunctionControlFeature() ? "" : "  · 未开通"), "代码函数控制", "@ic_feature_hook", Color.parseColor("#E11D48"));
            LinearLayout jumpTile = mdFeatureCard("界面跳转", "目标 Activity 唤起", "@ic_feature_jump", Color.parseColor("#F59E0B"));

            addGridLayout(page, new View[]{hookDex, dynTile, funcHook, jumpTile}, 2);

            hookDex.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFbHookFeature()) showFbHookPage(); else toast("未开通该功能"); }});
            dynTile.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasDynamicHookFeature()) showDynamicHookPage(); else toast("未开通该功能"); }});
            funcHook.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(hasFunctionControlFeature()) showFunctionControlPage(); else toast("未开通该功能"); }});
            jumpTile.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showIappJumpPage(); }});

        }

        void showTasks() {
            topLevelPage = true;
            currentMainTab = 0;
            setTab(0);
            clearContent();

            LinearLayout page = vbox();
            page.setPadding(dp(16), dp(16), dp(16), dp(24));
            page.setBackgroundColor(MD3_SURFACE);

            LinearLayout header = vbox();
            header.setPadding(dp(16), dp(16), dp(16), dp(16));
            header.setBackground(bg(MD3_SURFACE, 0));

            TextView qLabel = tv("额度", 14, TEXT_SUB, 0);
            header.addView(qLabel, new LinearLayout.LayoutParams(-1, dp(22)));
            TextView quota = tv(homeQuotaText(), 36, MD3_PRIMARY, Typeface.BOLD);
            quota.setGravity(Gravity.LEFT | Gravity.CENTER_VERTICAL);
            header.addView(quota, new LinearLayout.LayoutParams(-1, dp(44)));

            LinearLayout.LayoutParams hLp = new LinearLayout.LayoutParams(-1, -2);
            hLp.bottomMargin = dp(8);
            page.addView(header, hLp);

            addHomeAnnouncementCard(page);

            LinearLayout titleRow = hbox();
            TextView title = tv("最近任务记录", 18, TEXT_MAIN, Typeface.BOLD);
            TextView refresh = tv("刷新", 14, PRIMARY, Typeface.BOLD);
            refresh.setGravity(Gravity.CENTER);
            refresh.setPadding(dp(16), 0, dp(16), 0);
            refresh.setBackground(bg(MD3_PRIMARY_CONTAINER, 20));
            addClickAnim(refresh);
            titleRow.addView(title, new LinearLayout.LayoutParams(0, dp(40), 1));
            titleRow.addView(refresh, new LinearLayout.LayoutParams(dp(78), dp(38)));
            page.addView(titleRow, new LinearLayout.LayoutParams(-1, dp(44)));

            final TextView pullHint = tv("下拉刷新", 12, TEXT_SUB, 0);
            pullHint.setGravity(Gravity.CENTER);
            pullHint.setVisibility(View.GONE);
            pullHint.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));
            addM(page, pullHint, -1, dp(30), 0, 0, 0, 8);

            final ListView list = new ListView(a);
            list.setDivider(null);
            list.setDividerHeight(0);
            list.setItemsCanFocus(true);
            list.setCacheColorHint(Color.TRANSPARENT);
            list.setSelector(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
            list.setPadding(0, dp(2), 0, dp(20));
            list.setClipToPadding(false);
            list.setBackgroundColor(Color.TRANSPARENT);
            list.setScrollBarStyle(View.SCROLLBARS_INSIDE_INSET);
            page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));

            content.addView(page, new FrameLayout.LayoutParams(-1, -1));
            applyPageTransition(page);

            final TaskAdapter ad = new TaskAdapter();
            list.setAdapter(ad);
            setupPullToRefresh(list, pullHint, ad);
            list.setOnItemClickListener(null);
            refresh.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadTasksFast(ad, null); }});
            loadTasks(ad);
        }

        void addHomeAnnouncementCard(LinearLayout page) {
            try {
                if (!announcementEnabled(appConfig)) return;
                LinearLayout ann = vbox();
                ann.setPadding(dp(16), dp(12), dp(16), dp(12));
                ann.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));

                TextView title = tv(announcementTitle(appConfig), 15, MD3_ON_PRIMARY_CONTAINER, Typeface.BOLD);
                ann.addView(title, new LinearLayout.LayoutParams(-1, -2));

                TextView body = tv(announcementText(appConfig), 13, MD3_ON_PRIMARY_CONTAINER, 0);
                body.setGravity(Gravity.LEFT);
                body.setLineSpacing(dp(2), 1.0f);
                body.setMaxLines(4);
                LinearLayout.LayoutParams bodyLp = new LinearLayout.LayoutParams(-1, -2);
                bodyLp.topMargin = dp(4);
                ann.addView(body, bodyLp);

                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
                lp.topMargin = dp(16);
                lp.bottomMargin = dp(18);
                page.addView(ann, lp);
            } catch(Exception e) {}
        }

        void addElasticTaskMotion(final View card) {
            final float[] down = new float[]{0f, 0f};
            card.setOnTouchListener(new View.OnTouchListener() {
                public boolean onTouch(View view, android.view.MotionEvent event) {
                    int action = event.getActionMasked();
                    if (action == android.view.MotionEvent.ACTION_DOWN) {
                        down[0] = event.getRawX();
                        down[1] = event.getRawY();
                        view.animate().cancel();
                        view.setPivotX(view.getWidth() / 2f);
                        view.setPivotY(view.getHeight() / 2f);
                        view.animate().scaleX(0.985f).scaleY(0.985f).setDuration(110).start();
                    } else if (action == android.view.MotionEvent.ACTION_MOVE) {
                        float dy = event.getRawY() - down[1];
                        float stretch = 1f + Math.min(0.065f, Math.abs(dy) / Math.max(1f, dp(360)));
                        view.setScaleY(stretch);
                        view.setScaleX(1f - (stretch - 1f) * 0.28f);
                        view.setTranslationY(Math.max(-dp(8), Math.min(dp(8), dy * 0.055f)));
                    } else if (action == android.view.MotionEvent.ACTION_UP || action == android.view.MotionEvent.ACTION_CANCEL) {
                        view.animate().cancel();
                        view.animate().scaleX(1f).scaleY(1f).translationY(0f).setDuration(460)
                                .setInterpolator(new android.view.animation.OvershootInterpolator(1.8f)).start();
                    }
                    return false;
                }
            });
            card.setOnLongClickListener(new View.OnLongClickListener() {
                public boolean onLongClick(View view) {
                    view.animate().rotation(-1.4f).scaleX(1.025f).scaleY(1.055f).setDuration(180)
                            .withEndAction(new Runnable() {
                                public void run() {
                                    card.animate().rotation(0f).scaleX(1f).scaleY(1f).setDuration(380)
                                            .setInterpolator(new android.view.animation.OvershootInterpolator(2f)).start();
                                }
                            }).start();
                    return true;
                }
            });
        }

        class TaskAdapter extends BaseAdapter {
            public int getCount(){ return tasks.size(); }
            public Object getItem(int p){ return tasks.get(p); }
            public long getItemId(int p){ return p; }

            public View getView(int p, View cv, ViewGroup parent){
                JSONObject o = tasks.get(p);

                LinearLayout wrapper = vbox();
                wrapper.setPadding(dp(16), dp(5), dp(16), dp(5));

                LinearLayout card = hbox();
                card.setGravity(Gravity.CENTER_VERTICAL);
                card.setPadding(dp(16), dp(16), dp(16), dp(16));
                card.setTag("iapt_task_card_view");
                card.setBackground(bg(MD3_SURFACE_CONTAINER_LOW, 18));
                if (Build.VERSION.SDK_INT >= 21) {
                    card.setElevation(0f);
                    card.setStateListAnimator(null);
                }

                String status = opt(o, "status");
                int accentColor = statusColor(status);

                View accent = new View(a);
                accent.setBackground(bg(accentColor, 999));
                LinearLayout.LayoutParams accentLp =
                        new LinearLayout.LayoutParams(dp(4), dp(46));
                accentLp.rightMargin = dp(14);
                card.addView(accent, accentLp);

                LinearLayout mid = vbox();

                String name = opt(o, "apk_name");
                if (name.length() == 0 || "null".equals(name)) {
                    name = opt(o, "app_name");
                }
                if (name.length() == 0) name = "未命名任务";

                TextView title = tv(name, 16, TEXT_MAIN, Typeface.BOLD);
                title.setSingleLine(true);
                title.setEllipsize(
                        android.text.TextUtils.TruncateAt.END);
                mid.addView(
                        title,
                        new LinearLayout.LayoutParams(-1, -2));

                String info = taskOutputCountText(o) +
                        "  ·  " +
                        relativeTime(opt(o, "created_at"));
                TextView meta = tv(info, 13, TEXT_SUB, 0);
                meta.setSingleLine(true);
                LinearLayout.LayoutParams metaLp =
                        new LinearLayout.LayoutParams(-1, -2);
                metaLp.topMargin = dp(5);
                mid.addView(meta, metaLp);

                final boolean whitelistProtectedTask = isWhitelistProtectedTask(o, null);
                String projectMetaLine = whitelistProtectedTask ? "" : formatProjectMetaOneLine(o);
                if (projectMetaLine.length() > 0) {
                    TextView project = tv(
                            projectMetaLine,
                            11,
                            Color.parseColor("#79747E"),
                            0);
                    project.setSingleLine(true);
                    project.setEllipsize(
                            android.text.TextUtils.TruncateAt.END);
                    LinearLayout.LayoutParams projectLp =
                            new LinearLayout.LayoutParams(-1, -2);
                    projectLp.topMargin = dp(3);
                    mid.addView(project, projectLp);
                }

                card.addView(
                        mid,
                        new LinearLayout.LayoutParams(0, -2, 1));

                LinearLayout right = vbox();
                right.setGravity(Gravity.RIGHT);

                TextView statusTextView = tv(
                        whitelistProtectedTask ? "白名单保护" : statusText(status),
                        12,
                        accentColor,
                        Typeface.BOLD);
                statusTextView.setGravity(Gravity.RIGHT);
                statusTextView.setSingleLine(true);
                right.addView(
                        statusTextView,
                        new LinearLayout.LayoutParams(-2, -2));

                TextView arrow = tv(
                        "›",
                        21,
                        Color.parseColor("#79747E"),
                        0);
                arrow.setGravity(Gravity.RIGHT);
                LinearLayout.LayoutParams arrowLp =
                        new LinearLayout.LayoutParams(-2, -2);
                arrowLp.topMargin = dp(4);
                right.addView(arrow, arrowLp);

                LinearLayout.LayoutParams rightLp =
                        new LinearLayout.LayoutParams(-2, -2);
                rightLp.leftMargin = dp(12);
                card.addView(right, rightLp);

                addElasticTaskMotion(card);
                final JSONObject taskForClick = o;
                card.setClickable(true);
                card.setFocusable(false);
                card.setOnClickListener(new View.OnClickListener() {
                    public void onClick(final View view) {
                        view.postDelayed(new Runnable() {
                            public void run() {
                                resetClickAnimTree(view);
                                openTaskDetail(taskForClick);
                            }
                        }, 135);
                    }
                });

                wrapper.addView(
                        card,
                        new LinearLayout.LayoutParams(-1, -2));
                wrapper.setLayoutParams(
                        new AbsListView.LayoutParams(-1, -2));
                return wrapper;
            }
        }

        boolean isListAtTop(ListView list) {
            if (list == null || list.getChildCount() == 0) return true;
            return list.getFirstVisiblePosition() == 0 && list.getChildAt(0).getTop() >= list.getPaddingTop();
        }

        void setupPullToRefresh(final ListView list, final TextView hint, final BaseAdapter ad) {
            final float[] downY = new float[]{0};
            final boolean[] canPull = new boolean[]{false};
            list.setOnTouchListener(new View.OnTouchListener(){ public boolean onTouch(View v, android.view.MotionEvent ev){
                int action = ev.getAction();
                if (action == android.view.MotionEvent.ACTION_DOWN) {
                    downY[0] = ev.getRawY();
                    canPull[0] = isListAtTop(list);
                } else if (action == android.view.MotionEvent.ACTION_MOVE) {
                    float dy = ev.getRawY() - downY[0];
                    if (canPull[0] && dy > dp(24)) {
                        hint.setVisibility(View.VISIBLE);
                        hint.setText(dy > dp(90) ? "松开刷新" : "下拉刷新");
                    }
                } else if (action == android.view.MotionEvent.ACTION_UP || action == android.view.MotionEvent.ACTION_CANCEL) {
                    float dy = ev.getRawY() - downY[0];
                    if (canPull[0] && dy > dp(90)) {
                        hint.setVisibility(View.VISIBLE);
                        hint.setText("正在刷新...");
                        // 手势反馈立即结束，网络刷新在后台静默执行；避免弱网时卡在“正在刷新”。
                        hint.postDelayed(new Runnable(){ public void run(){ hint.setVisibility(View.GONE); }}, 250);
                        loadTasksFast(ad, null);
                    } else {
                        hint.setVisibility(View.GONE);
                    }
                    canPull[0] = false;
                }
                return false;
            }});
        }

        JSONObject addLocalTask(String fileName, int featureId, String status, BaseAdapter ad) {
            JSONObject o = new JSONObject();
            try {
                o.put("id", -System.currentTimeMillis());
                o.put("task_no", "local");
                o.put("apk_name", fileName == null ? "" : fileName);
                o.put("app_name", fileName == null ? "" : fileName);
                o.put("status", status == null ? "上传文件中" : status);
                o.put("feature_id", featureId);
                o.put("file_count", 0);
                o.put("created_at", String.valueOf(System.currentTimeMillis()));
                pendingTasks.add(0, o);
                tasks.add(0, o);
                if (ad != null) ad.notifyDataSetChanged();
                updateHomeTaskCountChip();
                a.runOnUiThread(new Runnable() {
                    public void run() {
                        nextPageTransitionDirection = -1;
                        showTasks();
                    }
                });
            } catch(Exception e) {}
            return o;
        }
        void setLocalTaskStatus(JSONObject o, String status, BaseAdapter ad) {
            try { if (o != null) o.put("status", status); if (ad != null) ad.notifyDataSetChanged(); } catch(Exception e) {}
        }
        void removeLocalTask(JSONObject o, BaseAdapter ad) {
            try {
                if (o != null) pendingTasks.remove(o);
                tasks.remove(o);
                persistTaskHistory();
                if (ad != null) ad.notifyDataSetChanged();
                updateHomeTaskCountChip();
            } catch(Exception e) {}
        }

        void loadTaskIcon(final JSONObject o, final ImageView view) {
            if (o == null || view == null) return;
            final int id = o.optInt("id", 0);
            if (id <= 0) return;
            Bitmap cached = taskIconCache.get(Integer.valueOf(id));
            if (cached != null) { view.setImageBitmap(cached); view.setVisibility(View.VISIBLE); return; }
            new Thread(new Runnable(){ public void run(){
                try {
                    final byte[] data = api.downloadBytes("/tasks/" + id + "/icon");
                    if (data == null || data.length == 0) return;
                    final Bitmap bm = BitmapFactory.decodeByteArray(data, 0, data.length);
                    if (bm == null) return;
                    taskIconCache.put(Integer.valueOf(id), bm);
                    a.runOnUiThread(new Runnable(){ public void run(){ try { view.setImageBitmap(bm); view.setVisibility(View.VISIBLE); } catch(Exception e){} }});
                } catch(Exception e) {}
            }}).start();
        }

        JSONObject taskFromDetail(JSONObject detail) {
            if (detail == null) return null;
            JSONObject t = detail.optJSONObject("task");
            return t == null ? detail : t;
        }

        void updateLocalTaskFromServer(final JSONObject localTask, final JSONObject serverTask, final BaseAdapter ad) {
            if (localTask == null || serverTask == null) return;
            a.runOnUiThread(new Runnable(){ public void run(){
                try {
                    String[] keys = new String[]{"id","task_no","apk_name","app_name","package_name","version_name","version_code","status","file_count","downloadable_file_count","downloadable_files","output_file_count","result_file_count","decrypted_file_count","total_bytes","total_ms","decrypt_version","feature_id","error_text","created_at","updated_at","decrypt_summary"};
                    boolean localAncient = isKnownAncientTask(localTask) || rawTaskSaysAncient(localTask);
                    if (localAncient) rememberAncientTask(localTask);
                    for (int i=0;i<keys.length;i++) {
                        String key = keys[i];
                        if (!serverTask.has(key) || serverTask.isNull(key)) continue;
                        if (localAncient && "decrypt_version".equals(key)) continue;
                        localTask.put(key, serverTask.get(key));
                    }
                    if (localAncient) {
                        localTask.put("decrypt_scheme", "ancient");
                        localTask.put("decrypt_version", "ancient");
                        localTask.put("task_version", "ancient");
                        localTask.put("client_final_scheme", "ancient");
                        localTask.put("legacy_iapp", true);
                        localTask.put("old_iapp", true);
                        rememberAncientTask(localTask);
                    }
                    // 服务端白名单终态必须覆盖并清理本地占位任务中的旧 key/options 缓存。
                    normalizeKnownAncientTask(localTask);
                    taskOutputFileCount(localTask, serverTask);
                    persistTaskHistory();
                    if (ad != null) ad.notifyDataSetChanged();
                } catch(Exception e) {}
            }});
        }

        JSONObject findNewestSubmittedTask(String apkName, long notBeforeMs) throws Exception {
            JSONObject list = api.getFast("/tasks");
            JSONArray arr = list == null ? null : list.optJSONArray("items");
            JSONObject best = null; int bestId = 0;
            if (arr != null) for (int i=0;i<arr.length();i++) {
                JSONObject t = arr.optJSONObject(i);
                if (t == null) continue;
                String name = safe(t.optString("apk_name", ""));
                if (!name.equals(apkName)) continue;
                long serverCreated = parseTime(safe(t.optString("created_at", "")));
                if (notBeforeMs > 0 && serverCreated > 0 && serverCreated + 120000L < notBeforeMs) continue;
                int id = t.optInt("id", 0);
                if (id > bestId) { bestId = id; best = t; }
            }
            return best;
        }

        void finishLocalTask(final JSONObject localTask, final BaseAdapter ad, final String toastText) {
            a.runOnUiThread(new Runnable(){ public void run(){
                if (toastText != null && toastText.length() > 0) toast(toastText);
                removeLocalTask(localTask, ad);
                loadTasks(ad);
            }});
        }

        void pollSubmittedTask(final JSONObject localTask, final BaseAdapter ad, int taskId) throws Exception {
            int failedStreak = 0, networkErrors = 0;
            long deadline = System.currentTimeMillis() + 10L * 60L * 1000L;
            while (System.currentTimeMillis() < deadline) {
                try {
                    JSONObject detail = api.getFast("/tasks/" + taskId);
                    JSONObject t = taskFromDetail(detail);
                    if (t == null) throw new Exception("任务详情为空");
                    updateLocalTaskFromServer(localTask, t, ad);
                    String status = safe(t.optString("status", "")).trim().toLowerCase(Locale.US);
                    if ("done".equals(status)) { finishLocalTask(localTask, ad, "解密完成"); return; }
                    if ("cancelled".equals(status)) { finishLocalTask(localTask, ad, "任务已停止"); return; }
                    if ("failed".equals(status)) {
                        boolean ancientTask = "远古".equals(taskRunnerName(localTask));
                        int outputCount = taskOutputFileCount(t, detail);
                        if (ancientTask && outputCount > 0) {
                            failedStreak = 0;
                            try { localTask.put("status", "running"); localTask.put("error_text", ""); } catch(Exception ignored) {}
                        } else {
                            failedStreak++;
                            int requiredSamples = ancientTask ? 12 : 3;
                            if (failedStreak >= requiredSamples) { finishLocalTask(localTask, ad, "解密失败"); return; }
                        }
                    } else failedStreak = 0;
                    networkErrors = 0;
                } catch (AuthException e) { throw e;
                } catch (Exception e) {
                    networkErrors++;
                    if (networkErrors >= 8) break;
                }
                try { Thread.sleep(900); } catch(InterruptedException e) { Thread.currentThread().interrupt(); break; }
            }
            finishLocalTask(localTask, ad, "任务已在后台继续执行");
        }

        void submitTaskInBackground(final JSONObject localTask, final BaseAdapter ad, final Job job) {
            new Thread(new Runnable(){ public void run(){
                try {
                    Object result = job.run();
                    JSONObject response = result instanceof JSONObject ? (JSONObject)result : null;
                    int taskId = response == null ? 0 : response.optInt("task_id", 0);
                    if (taskId > 0) {
                        boolean submittedAncient = isKnownAncientTask(localTask) || rawTaskSaysAncient(localTask);
                        try {
                            localTask.put("id", taskId);
                            localTask.put("task_no", response.optString("task_no", ""));
                            localTask.put("status", response.optString("status", "queued"));
                            if (!submittedAncient && response.has("decrypt_version")) localTask.put("decrypt_version", response.optString("decrypt_version", ""));
                            if (submittedAncient) {
                                localTask.put("decrypt_scheme", "ancient");
                                localTask.put("decrypt_version", "ancient");
                                localTask.put("task_version", "ancient");
                                localTask.put("client_final_scheme", "ancient");
                                localTask.put("legacy_iapp", true);
                                localTask.put("old_iapp", true);
                            }
                            rememberAncientTask(localTask);
                        } catch(Exception e) {}
                        a.runOnUiThread(new Runnable(){ public void run(){ persistTaskHistory(); if (ad != null) ad.notifyDataSetChanged(); toast("任务已提交"); }});
                        pollSubmittedTask(localTask, ad, taskId);
                    } else {
                        finishLocalTask(localTask, ad, "任务已提交");
                    }
                } catch (final AuthException e) {
                    clearClientSessionPreservingDeviceSettings();
                    loginApiTapEnabled = false;
                    a.runOnUiThread(new Runnable(){ public void run(){ setLocalTaskStatus(localTask, "提交失败", ad); Toast.makeText(a, "登录已失效，请重新登录", Toast.LENGTH_LONG).show(); showLogin(); }});
                } catch (final Exception originalError) {
                    // A mobile connection may time out after the server has already created
                    // the task. Recover the newest task with the same APK name before
                    // declaring submission failure; retrying the upload would create duplicates.
                    try {
                        JSONObject recovered = null;
                        String apkName = safe(localTask.optString("apk_name", ""));
                        long localStarted = parseTime(safe(localTask.optString("created_at", "")));
                        for (int i=0;i<4 && recovered==null;i++) {
                            try { Thread.sleep(750); } catch(InterruptedException e) { Thread.currentThread().interrupt(); break; }
                            try { recovered = findNewestSubmittedTask(apkName, localStarted); } catch(Exception ignored) {}
                        }
                        if (recovered != null && recovered.optInt("id", 0) > 0) {
                            final JSONObject rr = recovered;
                            updateLocalTaskFromServer(localTask, rr, ad);
                            a.runOnUiThread(new Runnable(){ public void run(){ toast("服务器已接收任务，继续跟踪状态"); }});
                            pollSubmittedTask(localTask, ad, recovered.optInt("id", 0));
                            return;
                        }
                    } catch(Exception ignored) {}
                    a.runOnUiThread(new Runnable(){ public void run(){ setLocalTaskStatus(localTask, "提交失败", ad); Toast.makeText(a, originalError.getMessage()==null?String.valueOf(originalError):originalError.getMessage(), Toast.LENGTH_LONG).show(); }});
                }
            }}).start();
        }

        void loadTasks(final BaseAdapter ad) {
            loadTasks(ad, null);
        }

        void loadTasks(final BaseAdapter ad, final Runnable after) {
            // V149：任务列表刷新全部走静默短请求；失败保留当前列表，不再弹 timeout/504。
            loadTasksInternal(ad, after, true);
        }

        void loadTasksFast(final BaseAdapter ad, final Runnable after) {
            loadTasksInternal(ad, after, true);
        }

        void loadTasksInternal(final BaseAdapter ad, final Runnable after, final boolean fastRefresh) {
            // 列表本身只请求一次 /tasks；详情文件数在后台独立补全，不阻塞刷新完成。
            // 快速刷新不能走 async 的统一错误提示，否则网络波动会弹 timeout，并且 after 不执行会让“正在刷新”一直停留。
            if (fastRefresh) {
                final long now = System.currentTimeMillis();
                if (tasksFastLoading && now - lastTasksFastStartMs < 9000L) {
                    if (after != null) after.run();
                    return;
                }
                tasksFastLoading = true;
                lastTasksFastStartMs = now;
                new Thread(new Runnable(){ public void run(){
                    JSONObject r = null;
                    boolean ok = false;
                    try {
                        r = api.getFast("/tasks");
                        ok = true;
                    } catch(Exception ignored) {
                        // 下拉刷新/按钮刷新失败时静默保留当前列表；不弹 timeout/504。
                    }
                    final JSONObject rr = r;
                    final boolean success = ok;
                    a.runOnUiThread(new Runnable(){ public void run(){
                        tasksFastLoading = false;
                        if (success && rr != null) applyTasksResponse(rr, ad);
                        if (after != null) after.run();
                        if (success) hydrateCompletedTaskOutputCounts(ad);
                    }});
                }}).start();
                return;
            }
            cacheDrop("tasks");
            async("后台刷新任务...", new Job(){ public Object run() throws Exception {
                return api.get("/tasks");
            }}, new Done(){ public void ok(Object o){
                JSONObject r = (JSONObject)o;
                applyTasksResponse(r, ad);
                if (after != null) after.run();
                hydrateCompletedTaskOutputCounts(ad);
            }});
        }

        String safe(String s){ return (s==null || "null".equals(s)) ? "" : s; }
        String opt(JSONObject o, String k){ return safe(o.optString(k, "")); }
        String taskRunnerName(JSONObject o){
            if (isKnownAncientTask(o)) return "远古";
            int fid = o == null ? 1 : o.optInt("feature_id", 1);
            String ver = o == null ? "" : opt(o, "decrypt_version").toLowerCase(Locale.US);
            String appName = o == null ? "" : opt(o, "app_name");
            String apkName = o == null ? "" : opt(o, "apk_name").toLowerCase(Locale.US);
            JSONObject options = o == null ? null : taskNestedObject(o, "options_json");
            String kind = options == null ? "" : safe(options.optString("task_kind", "")).toLowerCase(Locale.US);
            if (kind.contains("server_sokey") || apkName.endsWith("_sokey.zip")) return "SOKEY";
            if (kind.contains("dynamic_key_extract")) return "KEY";
            if (kind.contains("iact") || apkName.endsWith("_iact.zip")) return "iACT";
            if (kind.contains("native_compile") || apkName.endsWith("_native_compile.zip")) return "原生";
            if (kind.contains("numeric") || apkName.endsWith("_numeric.zip")) return "修复";
            if (kind.contains("dex_restore") || apkName.endsWith("_dex_restore.zip")) return "DEX";
            if (kind.contains("source_restore") || apkName.endsWith("_src.zip")) return "还原";
            if ("key".equals(ver) || "dynkey".equals(ver) || "dynamic_key".equals(ver) || "dynamic_key_extract".equals(ver) || appName.contains("动态Key提取")) return "KEY";
            if ("sokey".equals(ver) || "server_sokey".equals(ver) || "server_sokey_extract".equals(ver) || appName.contains("SO Key 提取") || appName.contains("服务器获取sokey")) return "SOKEY";
            if ("dex_restore".equals(ver) || "static_dex_restore".equals(ver) || "source_dex_restore".equals(ver)) return "DEX";
            if ("iact".equals(ver) || "iact_restore".equals(ver)) return "iACT";
            if ("native_compile_restore".equals(ver) || "native_compile_source_restore".equals(ver)) return "原生";
            if ("fn_restore".equals(ver) || "numeric_restore".equals(ver) || "numeric_source_restore".equals(ver)) return "修复";
            if ("restore".equals(ver) || "source_restore".equals(ver)) return "还原";
            if ("ancient".equals(ver) || "old".equals(ver) || "legacy".equals(ver) || "old_iapp".equals(ver) || "iapp_old".equals(ver)) return "远古";
            if (fid == FEATURE_ANTI_QIUSHUI) return "反加密";
            if (fid == 6) return "V6";
            if (fid == 8) return "还原";
            return "V3";
        }

        void showCreateTaskDialog(final BaseAdapter ad) {
            JSONObject cached = cacheGet("me", 15 * 60 * 1000);
            if (cached != null) {
                applyMeResponse(cached);
                showCreateTaskTypeDialog(ad);
                async("后台刷新功能权限...", new Job(){ public Object run() throws Exception { return api.get("/me"); }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; cachePut("me", r); applyMeResponse(r); }});
                return;
            }
            async("正在读取功能权限...", new Job(){ public Object run() throws Exception { return api.get("/me"); }}, new Done(){ public void ok(Object o){
                JSONObject r = (JSONObject)o;
                cachePut("me", r);
                applyMeResponse(r);
                showCreateTaskTypeDialog(ad);
            }});
        }

        void showCreateTaskTypeDialog(final BaseAdapter ad) {
            LinearLayout box = vbox();
            box.setPadding(dp(4), dp(4), dp(4), dp(4));
            Button v3 = btn("V3 静态解密", BLUE, Color.WHITE);
            Button dynamicKeyExtract = btn("提取动态 Key", hasFeature(4) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(4) ? Color.WHITE : GRAY);
            Button serverSoKeyExtract = btn("sokey（服务器获取）", hasFeature(FEATURE_SERVER_SOKEY) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(FEATURE_SERVER_SOKEY) ? Color.WHITE : GRAY);
            Button v6 = btn("V6 反编译", hasFeature(6) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(6) ? Color.WHITE : GRAY);
            Button sourceRestore = btn("混淆还原", hasFeature(8) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(8) ? Color.WHITE : GRAY);
            Button dexRestoreOnly = btn("DEX 还原", hasFeature(8) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(8) ? Color.WHITE : GRAY);
            Button numericRestoreOnly = btn("动态修复", hasFeature(5) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(5) ? Color.WHITE : GRAY);
            Button nativeCompileOnly = btn("原生编译修复", hasFeature(FEATURE_NATIVE_COMPILE_RESTORE) ? BLUE : Color.parseColor("#E2E8F0"), hasFeature(FEATURE_NATIVE_COMPILE_RESTORE) ? Color.WHITE : GRAY);
            addM(box, v3, -1, dp(50), 0, 0, 0, 10);
            addM(box, dynamicKeyExtract, -1, dp(50), 0, 0, 0, 10);
            addM(box, serverSoKeyExtract, -1, dp(50), 0, 0, 0, 10);
            addM(box, v6, -1, dp(50), 0, 0, 0, 10);
            addM(box, sourceRestore, -1, dp(50), 0, 0, 0, 10);
            addM(box, dexRestoreOnly, -1, dp(50), 0, 0, 0, 10);
            addM(box, numericRestoreOnly, -1, dp(50), 0, 0, 0, 10);
            addM(box, nativeCompileOnly, -1, dp(50), 0, 0, 0, 0);
            if (!hasFeature(4)) dynamicKeyExtract.setEnabled(false);
            if (!hasFeature(FEATURE_SERVER_SOKEY)) serverSoKeyExtract.setEnabled(false);
            if (!hasFeature(6)) v6.setEnabled(false);
            if (!hasFeature(8)) sourceRestore.setEnabled(false);
            if (!hasFeature(8)) dexRestoreOnly.setEnabled(false);
            if (!hasFeature(5)) numericRestoreOnly.setEnabled(false);
            if (!hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)) nativeCompileOnly.setEnabled(false);
            final AlertDialog dlg = md3FeatureDialog("选择解密版本", box).setNegativeButton("取消", null).create();
            v3.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showCreateTaskDialogBody(ad); }});
            dynamicKeyExtract.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showDynamicKeyExtractDialog(ad); }});
            serverSoKeyExtract.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showServerSoKeyExtractDialog(ad); }});
            v6.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showCreateTaskV6Dialog(ad); }});
            sourceRestore.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showSourceRestoreDialog(ad); }});
            dexRestoreOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showStaticDexSourceRestoreDialog(ad); }});
            numericRestoreOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showNumericSourceRestoreDialog(ad); }});
            nativeCompileOnly.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dlg.dismiss(); showNativeCompileSourceRestoreDialog(ad); }});
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        boolean hasFeature(int fid) {
            for(int i=0;i<subs.size();i++) {
                JSONObject sub = subs.get(i);
                if (sub == null) continue;
                Object raw = sub.opt("features_json");
                if (featureJsonHas(raw, fid)) return true;
            }
            return fid == 1;
        }

        boolean featureJsonHas(Object raw, int fid) {
            try {
                if (raw == null || raw == JSONObject.NULL) return false;
                JSONArray arr;
                if (raw instanceof JSONArray) arr = (JSONArray)raw;
                else {
                    String text = String.valueOf(raw).trim();
                    if (text.length() == 0 || "null".equals(text)) return false;
                    arr = new JSONArray(text);
                }
                for(int i=0;i<arr.length();i++) {
                    int v = arr.optInt(i, -999);
                    // 999 是真全功能；0 保持普通通配语义。
                    if (v == 999 || v == 0 || v == fid) return true;
                }
            } catch(Exception e) {}
            return false;
        }


        boolean hasExactFeature(int fid) {
            for(int i=0;i<subs.size();i++) {
                JSONObject sub = subs.get(i);
                if (sub == null) continue;
                if (featureJsonHasExact(sub.opt("features_json"), fid)) return true;
            }
            return false;
        }

        boolean featureJsonHasExact(Object raw, int fid) {
            try {
                if (raw == null || raw == JSONObject.NULL) return false;
                JSONArray arr;
                if (raw instanceof JSONArray) arr = (JSONArray)raw;
                else {
                    String text = String.valueOf(raw).trim();
                    if (text.length() == 0 || "null".equals(text)) return false;
                    arr = new JSONArray(text);
                }
                for(int i=0;i<arr.length();i++) {
                    int v = arr.optInt(i, -999);
                    // 显式特殊功能（7/14/17 等）可由真全功能 999 授权，
                    // 但不能由普通通配 0 授权。
                    if (v == 999 || v == fid) return true;
                }
            } catch(Exception e) {}
            return false;
        }

        boolean hasFbHookFeature() { return hasFeature(12) || hasFeature(0); }
        boolean hasDynamicHookFeature() { return hasFeature(4) || hasFeature(0); }
        boolean hasFunctionControlFeature() { return hasFeature(13) || hasFeature(0); }
        boolean hasHookFeature() { return hasFbHookFeature(); }

        void syncHookFeatureFlags() {
            try {
                boolean fbOk = hasFbHookFeature();
                boolean dynOk = hasDynamicHookFeature();
                boolean funcOk = hasFunctionControlFeature();
                SharedPreferences.Editor ed = hookSp.edit();
                ed.putBoolean("hook_fb_allowed", fbOk);
                ed.putBoolean("hook_dynamic_allowed", dynOk);
                ed.putBoolean("hook_func_allowed", funcOk);
                // v209：老版本动态获取 dex密钥 默认开启，容易导致只开作用域就崩。
                // 升级后统一迁移为默认关闭，需要用户在页面里手动开启具体功能。
                if (!hookSp.getBoolean("hook_safe_default_migrated_v209", false)) {
                    ed.putBoolean("hook_fb_enabled", false);
                    ed.putBoolean("hook_dynamic_enabled", false);
                    ed.putBoolean("hook_func_enabled", false);
                    ed.putBoolean("hook_safe_default_migrated_v209", true);
                }
                if (!fbOk) ed.putBoolean("hook_fb_enabled", false);
                if (!dynOk) ed.putBoolean("hook_dynamic_enabled", false);
                if (!funcOk) ed.putBoolean("hook_func_enabled", false);
                ed.commit();
            } catch(Exception e) {}
        }

        boolean hookFbEnabled() {
            syncHookFeatureFlags();
            return hookSp.getBoolean("hook_fb_enabled", false) && hasFbHookFeature();
        }

        boolean hookDynamicEnabled() {
            syncHookFeatureFlags();
            return hookSp.getBoolean("hook_dynamic_enabled", false) && hasDynamicHookFeature();
        }

        boolean hookFuncEnabled() {
            syncHookFeatureFlags();
            return hookSp.getBoolean("hook_func_enabled", false) && hasFunctionControlFeature();
        }

        String hookSwitchText() {
            return "动态获取dex密钥：" + (hookFbEnabled() ? "开启" : "关闭") + "\n动态解密：" + (hookDynamicEnabled() ? "开启" : "关闭") + "\n函数控制：" + (hookFuncEnabled() ? "开启" : "关闭");
        }

        void gateFeature(CheckBox c, int fid, String name) {
            boolean ok = hasFeature(fid);
            c.setEnabled(ok);
            if (!ok) {
                c.setChecked(false);
                c.setText(name);
                c.setTextColor(GRAY);
            } else {
                c.setText(name);
                c.setTextColor(BLACK);
            }
        }

        // 精细包装 MD 风格配置弹窗构造器
        AlertDialog.Builder mdDialog(String title, View view) {
            LinearLayout container = vbox();
            container.setPadding(dp(20), dp(20), dp(20), dp(10));
            container.setBackgroundColor(Color.WHITE);
            TextView head = tv(title, 18, BLACK, Typeface.BOLD);
            container.addView(head, new LinearLayout.LayoutParams(-1, dp(36)));
            
            LinearLayout.LayoutParams vlp = new LinearLayout.LayoutParams(-1, -2);
            vlp.topMargin = dp(10);
            container.addView(view, vlp);
            
            AlertDialog.Builder b = new AlertDialog.Builder(a);
            b.setView(container);
            return b;
        }

        void showCreateTaskDialogBody(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final EditText apk = edit("APK 路径"); apk.setSingleLine(true);
            box.addView(label("APK 路径（必填）")); addM(box, apk, -1, dp(50), 0, 4,0,8);
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button pickApk = btn("浏览选择 APK", Color.parseColor("#E2E8F0"), BLACK);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            LinearLayout fileBtns = hbox();
            addM(fileBtns, pickApk, 0, dp(46), 0, 0, 4, 0); ((LinearLayout.LayoutParams)pickApk.getLayoutParams()).weight = 1;
            addM(fileBtns, openPerm, 0, dp(46), 4, 0, 0, 0); ((LinearLayout.LayoutParams)openPerm.getLayoutParams()).weight = 1;
            addM(box, fileBtns, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 6);
            pickApk.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(apk); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});

            final CheckBox legacyIapp = md3FeatureSwitch("远古方案");
            final CheckBox fb = md3FeatureSwitch("dex密钥"); final EditText fbv = edit("dex密钥值"); fbv.setSingleLine(true); fbv.setVisibility(View.GONE);
            final CheckBox hidden = md3FeatureSwitch("so密钥"); final EditText hiddenv = edit("so密钥值"); hiddenv.setSingleLine(true); hiddenv.setVisibility(View.GONE);
            final CheckBox serverSokey = md3FeatureSwitch("sokey（服务器获取）");
            final String[] autoHiddenSokey = new String[]{""}; // 客户端文本搜索到的sokey，静默提交，不展开UI。
            final String[] autoDexkeyValue = new String[]{""}; // 客户端解析到的dexkey，静默提交，不展开UI。
            final String[] dynamicDexkeyReadyPath = new String[]{""};
            final String[] dynamicDexkeyReadyValue = new String[]{""};
            final String[] dynamicDexkeyFailedPath = new String[]{""};
            final boolean[] dynamicDexkeyResolving = new boolean[]{false};
            final CheckBox sokeyEnum = md3FeatureSwitch("sokey枚举");
            final CheckBox dexkeyEnum = md3FeatureSwitch("dexkey枚举");
            final CheckBox fast = md3FeatureSwitch("快速模式"); fast.setChecked(true);
            final CheckBox userPassword = md3FeatureSwitch("用户加密密码");
            final EditText userPasswordValue = edit("加密密码"); userPasswordValue.setSingleLine(true); userPasswordValue.setVisibility(View.GONE);
            userPasswordValue.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final CheckBox signatureVerify = md3FeatureSwitch("签名效验（服务器获取）");
            final boolean antiQiushuiEntitled = hasExactFeature(FEATURE_ANTI_QIUSHUI);
            final CheckBox antiQiushui = md3FeatureSwitch("反加密样本");
            antiQiushui.setVisibility(antiQiushuiEntitled ? View.VISIBLE : View.GONE);
            antiQiushui.setEnabled(antiQiushuiEntitled);
            final CheckBox antiIapec = md3FeatureSwitch("反iAPEC加密");
            antiIapec.setVisibility(antiQiushuiEntitled ? View.VISIBLE : View.GONE);
            antiIapec.setEnabled(antiQiushuiEntitled);
            final CheckBox antiIapecSelfDestruct = md3FeatureSwitch("反iAPEC自毁");
            antiIapecSelfDestruct.setVisibility(antiQiushuiEntitled ? View.VISIBLE : View.GONE);
            antiIapecSelfDestruct.setEnabled(antiQiushuiEntitled);
            // V116：只有开启反加密样本时才显示。默认不解密/不上传 assets/res 资源，
            // 只上传本地恢复后的必要容器文件，从而显著缩短提交时间。
            final CheckBox skipAntiResources = md3FeatureSwitch("不解密资源文件");
            skipAntiResources.setChecked(true);
            skipAntiResources.setVisibility(View.GONE);
            final CheckBox numericRestore = md3FeatureSwitch("动态修复");
            final CheckBox nativeCompileRestore = md3FeatureSwitch("原生编译修复");
            final CheckBox dynamicKey = md3FeatureSwitch("动态 key（服务器获取）");
            final CheckBox customDynamicKey = md3FeatureSwitch("自定义动态 key");
            final EditText customPostKey = edit("post_key 值，32位十六进制"); customPostKey.setSingleLine(true); customPostKey.setVisibility(View.GONE);
            final EditText customKeyXor = edit("xor_key 值，32位十六进制"); customKeyXor.setSingleLine(true); customKeyXor.setVisibility(View.GONE);
            final ArrayList<String> dynamicPoolLabels = new ArrayList<String>();
            final ArrayList<String> dynamicPoolRefs = new ArrayList<String>();
            final ArrayList<JSONObject> dynamicPoolFeatures = new ArrayList<JSONObject>();
            final boolean[] dynamicPoolLoaded = new boolean[]{false};
            dynamicPoolLabels.add("不开启");
            dynamicPoolRefs.add("");
            dynamicPoolFeatures.add(new JSONObject());
            dynamicPoolLabels.add("枚举");
            dynamicPoolRefs.add("");
            dynamicPoolFeatures.add(new JSONObject());
            final Spinner dynamicPool = new Spinner(a);
            final ArrayAdapter<String> dynamicPoolAdapter = new ArrayAdapter<String>(a, android.R.layout.simple_spinner_item, dynamicPoolLabels);
            dynamicPoolAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            dynamicPool.setAdapter(dynamicPoolAdapter);
            final boolean dynamicPoolEntitled = hasFeature(FEATURE_DYNAMIC_KEY_POOL) || hasFeature(FEATURE_DYNAMIC_KEY_POOL_ENUM);
            dynamicPool.setEnabled(dynamicPoolEntitled);
            final CheckBox maxFiles = md3FeatureSwitch("限制输出文件数量"); final EditText maxFilesv = edit("max_output_files 数量"); maxFilesv.setInputType(InputType.TYPE_CLASS_NUMBER); maxFilesv.setVisibility(View.GONE);
            final CheckBox customMainFile = md3FeatureSwitch("自定义主文件");
            final EditText mainFileValue = edit("主文件"); mainFileValue.setSingleLine(true); mainFileValue.setVisibility(View.GONE);

            gateFeature(dynamicKey, 4, "动态 key（服务器获取）");
            gateFeature(serverSokey, FEATURE_SERVER_SOKEY, "sokey（服务器获取）");
            gateFeature(numericRestore, 5, "动态修复");
            gateFeature(nativeCompileRestore, FEATURE_NATIVE_COMPILE_RESTORE, "原生编译修复");
            gateFeature(sokeyEnum, 2, "sokey枚举");

            // 动态修复自动判定：程序设置和用户手动设置分开记录。
            final boolean[] numericRestoreProgrammatic = new boolean[]{false};
            final boolean[] numericRestoreAuto = new boolean[]{false};
            final boolean[] numericRestoreUserOverride = new boolean[]{false};
            numericRestore.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (!numericRestoreProgrammatic[0]) {
                    numericRestoreUserOverride[0] = true;
                    numericRestoreAuto[0] = false;
                }
            }});
            // 原生编译修复也区分自动识别与用户手动覆盖；无功能5时自动分析静默跳过。
            final boolean[] nativeCompileProgrammatic = new boolean[]{false};
            final boolean[] nativeCompileAuto = new boolean[]{false};
            final boolean[] nativeCompileUserOverride = new boolean[]{false};
            nativeCompileRestore.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (!nativeCompileProgrammatic[0]) {
                    nativeCompileUserOverride[0] = true;
                    nativeCompileAuto[0] = false;
                }
            }});
            // iAPEC/外层容器也区分自动识别与手动覆盖。自动分析只在账号
            // 具备对应功能时静默勾选，用户仍可手动强制开关。
            final boolean[] antiQiushuiProgrammatic = new boolean[]{false};
            final boolean[] antiQiushuiAuto = new boolean[]{false};
            final boolean[] antiQiushuiUserOverride = new boolean[]{false};
            antiQiushui.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (!antiQiushuiProgrammatic[0]) {
                    antiQiushuiUserOverride[0] = true;
                    antiQiushuiAuto[0] = false;
                }
            }});
            final boolean[] antiIapecProgrammatic = new boolean[]{false};
            final boolean[] antiIapecAuto = new boolean[]{false};
            final boolean[] antiIapecUserOverride = new boolean[]{false};
            antiIapec.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (!antiIapecProgrammatic[0]) {
                    antiIapecUserOverride[0] = true;
                    antiIapecAuto[0] = false;
                }
            }});
            final boolean[] antiIapecSelfDestructProgrammatic = new boolean[]{false};
            final boolean[] antiIapecSelfDestructAuto = new boolean[]{false};
            final boolean[] antiIapecSelfDestructUserOverride = new boolean[]{false};
            antiIapecSelfDestruct.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (!antiIapecSelfDestructProgrammatic[0]) {
                    antiIapecSelfDestructUserOverride[0] = true;
                    antiIapecSelfDestructAuto[0] = false;
                }
            }});
            gateFeature(dexkeyEnum, 2, "dexkey枚举");
            // “反加密样本”是特殊功能：只有显式订阅功能17才展示该参数。
            // 未订阅时仍可正常使用其它解密参数，客户端不会把隐藏参数提交给服务端。

            box.addView(legacyIapp, new LinearLayout.LayoutParams(-1, dp(40)));
            addSwitch(box,fb,fbv);
            fbv.setHint("dex密钥值");
            addSwitch(box,hidden,hiddenv);
            box.addView(serverSokey, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(sokeyEnum, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(dexkeyEnum, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(fast, new LinearLayout.LayoutParams(-1, dp(40)));
            addSwitch(box, userPassword, userPasswordValue);
            box.addView(signatureVerify, new LinearLayout.LayoutParams(-1, dp(40)));
            if (antiQiushuiEntitled) {
                box.addView(antiQiushui, new LinearLayout.LayoutParams(-1, dp(40)));
                box.addView(skipAntiResources, new LinearLayout.LayoutParams(-1, dp(40)));
                box.addView(antiIapec, new LinearLayout.LayoutParams(-1, dp(40)));
                box.addView(antiIapecSelfDestruct, new LinearLayout.LayoutParams(-1, dp(40)));
            }
            box.addView(numericRestore, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(nativeCompileRestore, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(dynamicKey, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(customDynamicKey, new LinearLayout.LayoutParams(-1, dp(40)));
            addM(box, customPostKey, -1, dp(50), 0, 4,0,6);
            addM(box, customKeyXor, -1, dp(50), 0, 4,0,6);
            final TextView dynamicPoolLabel = label("服务器动态 Key 池");
            box.addView(dynamicPoolLabel);
            addM(box, dynamicPool, -1, dp(50), 0, 0, 0, 8);
            
            final Runnable applyLegacyIappMode = new Runnable(){ public void run(){
                boolean oldMode = legacyIapp.isChecked();
                legacyIapp.setText("远古方案");
                hidden.setText(oldMode ? "sokey参数" : "so密钥");
                fb.setText(oldMode ? "dexkey参数" : "dex密钥");
                fbv.setHint("dex密钥值");
                signatureVerify.setText("签名效验（服务器获取）");

                int newVisibility = oldMode ? View.GONE : View.VISIBLE;
                fast.setVisibility(newVisibility);
                serverSokey.setVisibility(newVisibility);
                if (oldMode) serverSokey.setChecked(false);
                // 远古方案普通解密只上传 resources.arsc + assets/lib.so；sokey/dexkey/签名均由客户端从原 APK 自动提取后作为参数提交。
                // 只有开启“动态修复”或“原生编译修复”时才额外上传必要 DEX；源码替换全部在服务端执行。
                numericRestore.setVisibility(View.VISIBLE);
                nativeCompileRestore.setVisibility(View.VISIBLE);
                dynamicKey.setVisibility(newVisibility);
                customDynamicKey.setVisibility(newVisibility);
                customPostKey.setVisibility(oldMode ? View.GONE : (customDynamicKey.isChecked() ? View.VISIBLE : View.GONE));
                customKeyXor.setVisibility(oldMode ? View.GONE : (customDynamicKey.isChecked() ? View.VISIBLE : View.GONE));
                dynamicPoolLabel.setVisibility(newVisibility);
                dynamicPool.setVisibility(newVisibility);
                maxFiles.setVisibility(newVisibility);
                maxFilesv.setVisibility(!oldMode && maxFiles.isChecked() ? View.VISIBLE : View.GONE);
                customMainFile.setVisibility(View.VISIBLE);
                mainFileValue.setVisibility(customMainFile.isChecked() ? View.VISIBLE : View.GONE);
                antiQiushui.setVisibility(!oldMode && antiQiushuiEntitled ? View.VISIBLE : View.GONE);
                antiIapec.setVisibility(antiQiushuiEntitled ? View.VISIBLE : View.GONE);
                antiIapecSelfDestruct.setVisibility(antiQiushuiEntitled ? View.VISIBLE : View.GONE);
                skipAntiResources.setVisibility(!oldMode && antiQiushuiEntitled && antiQiushui.isChecked() ? View.VISIBLE : View.GONE);

                if (oldMode) {
                    antiQiushui.setChecked(false);
                    skipAntiResources.setChecked(true);
                    skipAntiResources.setVisibility(View.GONE);
                    dynamicKey.setChecked(false);
                    customDynamicKey.setChecked(false);
                    dynamicPool.setSelection(0);
                    maxFiles.setChecked(false);
                }
            }};
            legacyIapp.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){ applyLegacyIappMode.run(); }});
            antiQiushui.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                boolean show = checked && antiQiushuiEntitled && !legacyIapp.isChecked();
                skipAntiResources.setVisibility(show ? View.VISIBLE : View.GONE);
                if (!checked) skipAntiResources.setChecked(true);
            }});
            applyLegacyIappMode.run();

            final boolean[] enumGuard = new boolean[]{false};
            CompoundButton.OnCheckedChangeListener enumListener = new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (enumGuard[0]) return;
                if (checked && dynamicPool.isEnabled() && dynamicPool.getSelectedItemPosition() == 1) {
                    enumGuard[0] = true;
                    b.setChecked(false);
                    enumGuard[0] = false;
                    toast("不能同时开启");
                    return;
                }
                if (checked && sokeyEnum.isChecked() && dexkeyEnum.isChecked() && !hasExactFeature(FEATURE_JOINT_KEY_ENUM)) {
                    enumGuard[0] = true;
                    b.setChecked(false);
                    enumGuard[0] = false;
                    toast("功能不可用");
                }
                if (sokeyEnum.isChecked() && hidden.isChecked()) hidden.setChecked(false);
                if (sokeyEnum.isChecked() && serverSokey.isChecked()) serverSokey.setChecked(false);
                if (dexkeyEnum.isChecked() && fb.isChecked()) fb.setChecked(false);
                hidden.setEnabled(!sokeyEnum.isChecked() && !serverSokey.isChecked());
                serverSokey.setEnabled(hasFeature(FEATURE_SERVER_SOKEY) && !sokeyEnum.isChecked());
                fb.setEnabled(!dexkeyEnum.isChecked());
            }};
            sokeyEnum.setOnCheckedChangeListener(enumListener);
            dexkeyEnum.setOnCheckedChangeListener(enumListener);

            serverSokey.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (checked) {
                    hidden.setChecked(false);
                    hidden.setEnabled(false);
                    if (sokeyEnum.isChecked()) sokeyEnum.setChecked(false);
                } else {
                    hidden.setEnabled(!sokeyEnum.isChecked());
                }
                serverSokey.setEnabled(hasFeature(FEATURE_SERVER_SOKEY) && !sokeyEnum.isChecked());
            }});
            hidden.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                hiddenv.setVisibility(checked?View.VISIBLE:View.GONE);
                if (checked && serverSokey.isChecked()) serverSokey.setChecked(false);
            }});

            customDynamicKey.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                customPostKey.setVisibility(checked?View.VISIBLE:View.GONE);
                customKeyXor.setVisibility(checked?View.VISIBLE:View.GONE);
                if (checked && dynamicKey.isChecked()) dynamicKey.setChecked(false);
                if (checked) dynamicPool.setSelection(0);
                dynamicPool.setEnabled(dynamicPoolEntitled && !checked && !dynamicKey.isChecked());
            }});
            dynamicKey.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (checked && customDynamicKey.isChecked()) customDynamicKey.setChecked(false);
                if (checked) dynamicPool.setSelection(0);
                dynamicPool.setEnabled(dynamicPoolEntitled && !checked && !customDynamicKey.isChecked());
            }});
            dynamicPool.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
                public void onNothingSelected(AdapterView<?> parent) {}
                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                    if (position == 1 && dynamicPool.isEnabled() && (sokeyEnum.isChecked() || dexkeyEnum.isChecked())) {
                        enumGuard[0] = true;
                        sokeyEnum.setChecked(false);
                        dexkeyEnum.setChecked(false);
                        enumGuard[0] = false;
                        hidden.setEnabled(true);
                        fb.setEnabled(true);
                        toast("不能同时开启");
                    }
                }
            });
            // Dynamic-library recognition runs as soon as an APK is selected.  It is
            // intentionally limited to normalized SHA-256 matching: the client never
            // contains post/xor extraction code.
            final Api.DynamicSoFingerprintInfo[] detectedDynamicSo = new Api.DynamicSoFingerprintInfo[]{null};
            final Api.DynamicRestoreProbe[] detectedDynamicRestore = new Api.DynamicRestoreProbe[]{null};
            final Api.IapecProtectionProbe[] detectedIapecProtection = new Api.IapecProtectionProbe[]{null};
            final Api.NativeCompileProbe[] detectedNativeCompile = new Api.NativeCompileProbe[]{null};
            final String[] detectedDynamicPath = new String[]{""};
            final String[] dynamicRestoreNoticePath = new String[]{""};
            final int[] dynamicAutoNotice = new int[]{Integer.MIN_VALUE};
            final int[] dynamicAutoSelection = new int[]{0}; // 0=none, 1=pool, 2=server extract
            final Runnable applyDynamicAutoSelection = new Runnable(){ public void run(){
                Api.DynamicSoFingerprintInfo info = detectedDynamicSo[0];
                String currentPath = apk.getText().toString().trim();
                if (info == null || !info.hasLibraries() || !currentPath.equals(detectedDynamicPath[0])) return;

                if (info.defaultScheme && hasFeature(4)) {
                    // 默认指纹只表示 native 构建属于已知系列，并不表示容器可以
                    // 关闭动态 key。轻鸽等样本仍需从 SO 还原 post/xor。
                    dynamicPool.setSelection(0);
                    dynamicKey.setChecked(true);
                    dynamicAutoSelection[0] = 2;
                    dynamicAutoNotice[0] = 2;
                    return;
                }

                // Never overwrite an explicit custom-key choice.
                if (customDynamicKey.isChecked()) return;

                if (hasFeature(FEATURE_DYNAMIC_KEY_POOL)) {
                    if (!dynamicPoolLoaded[0]) {
                        // 密钥池仍在加载属于正常中间状态，不弹提示。
                        dynamicAutoNotice[0] = 1;
                        return;
                    }
                    int matched = Api.findFirstPoolFeatureMatch(info, dynamicPoolFeatures);
                    if (matched >= 2 && matched < dynamicPoolLabels.size()) {
                        dynamicKey.setChecked(false);
                        dynamicPool.setEnabled(true);
                        dynamicPool.setSelection(matched);
                        dynamicAutoSelection[0] = 1;
                        int notice = 1000 + matched;
                        // 自动命中密钥池方案时静默选择。
                        dynamicAutoNotice[0] = notice;
                        return;
                    }
                }

                if (hasFeature(4)) {
                    dynamicPool.setSelection(0);
                    dynamicKey.setChecked(true);
                    dynamicAutoSelection[0] = 2;
                    // 有服务器获取订阅时静默开启参数。
                    dynamicAutoNotice[0] = 2;
                } else if (hasFeature(FEATURE_DYNAMIC_KEY_POOL)) {
                    if (dynamicAutoSelection[0] == 2) dynamicKey.setChecked(false);
                    dynamicPool.setSelection(0);
                    dynamicAutoSelection[0] = 0;
                    customDynamicKey.setChecked(true);
                    dynamicAutoNotice[0] = 3;
                } else {
                    if (dynamicAutoSelection[0] == 1) dynamicPool.setSelection(0);
                    if (dynamicAutoSelection[0] == 2) dynamicKey.setChecked(false);
                    dynamicAutoSelection[0] = 0;
                    customDynamicKey.setChecked(true);
                    dynamicAutoNotice[0] = 4;
                }
            }};

            if (dynamicPoolEntitled) {
                async("加载动态密钥池...", new Job(){ public Object run() throws Exception { return api.get("/dynamic-keys/pool?light=1&limit=200"); }}, new Done(){ public void ok(Object o){
                    JSONObject r = (JSONObject)o;
                    JSONArray arr = r.optJSONArray("items");
                    dynamicPoolLabels.clear(); dynamicPoolRefs.clear(); dynamicPoolFeatures.clear();
                    dynamicPoolLabels.add("不开启"); dynamicPoolRefs.add(""); dynamicPoolFeatures.add(new JSONObject());
                    dynamicPoolLabels.add("枚举"); dynamicPoolRefs.add(""); dynamicPoolFeatures.add(new JSONObject());
                    int dynamicKeyNumber = 1;
                    if (arr != null) for (int i=0;i<arr.length();i++) {
                        JSONObject item = arr.optJSONObject(i); if (item == null) continue;
                        String ref = item.optString("ref", "").trim();
                        if (ref.length() == 0) continue;
                        String label = item.optString("label", "").trim();
                        dynamicPoolLabels.add(label.length() > 0 ? label : ("动态密钥" + dynamicKeyNumber));
                        dynamicKeyNumber++;
                        dynamicPoolRefs.add(ref);
                        JSONObject features = item.optJSONObject("features");
                        dynamicPoolFeatures.add(features == null ? new JSONObject() : features);
                    }
                    dynamicPoolLoaded[0] = true;
                    dynamicPoolAdapter.notifyDataSetChanged();
                    dynamicPool.setSelection(0);
                    applyDynamicAutoSelection.run();
                }});
            }
            addSwitch(box,maxFiles,maxFilesv);
            addSwitch(box, customMainFile, mainFileValue);

            // Password/signature and dynamic-library scheme selection are detected
            // immediately after the APK path becomes valid. dexkey/sokey behavior is
            // otherwise unchanged.
            final long[] securityDetectSeq = new long[]{0L};
            final boolean[] apkAutoScanRunning = new boolean[]{false};
            final String[] apkAutoScanReadyPath = new String[]{""};
            final String[] apkAutoScanReadyError = new String[]{""};
            final AlertDialog[] apkAnalysisLoading =
                    new AlertDialog[]{null};
            final String[] antiQiushuiNoticePath = new String[]{""};
            apk.addTextChangedListener(new android.text.TextWatcher(){
                public void beforeTextChanged(CharSequence text, int start, int count, int after) {}
                public void onTextChanged(CharSequence text, int start, int before, int count) {}
                public void afterTextChanged(android.text.Editable editable) {
                    final String selectedPath = editable == null ? "" : editable.toString().trim();
                    final long seq = ++securityDetectSeq[0];
                    detectedDynamicSo[0] = null;
                    detectedDynamicRestore[0] = null;
                    detectedIapecProtection[0] = null;
                    detectedNativeCompile[0] = null;
                    detectedDynamicPath[0] = selectedPath;
                    dynamicRestoreNoticePath[0] = "";
                    // 换 APK 时只撤销上一个 APK 的自动勾选，用户手动选择不在这里继承。
                    if (numericRestoreAuto[0]) {
                        numericRestoreProgrammatic[0] = true;
                        numericRestore.setChecked(false);
                        numericRestoreProgrammatic[0] = false;
                        numericRestoreAuto[0] = false;
                    }
                    numericRestoreUserOverride[0] = false;
                    if (nativeCompileAuto[0]) {
                        nativeCompileProgrammatic[0] = true;
                        nativeCompileRestore.setChecked(false);
                        nativeCompileProgrammatic[0] = false;
                        nativeCompileAuto[0] = false;
                    }
                    nativeCompileUserOverride[0] = false;
                    if (antiQiushuiAuto[0]) {
                        antiQiushuiProgrammatic[0] = true;
                        antiQiushui.setChecked(false);
                        antiQiushuiProgrammatic[0] = false;
                        antiQiushuiAuto[0] = false;
                    }
                    antiQiushuiUserOverride[0] = false;
                    if (antiIapecAuto[0]) {
                        antiIapecProgrammatic[0] = true;
                        antiIapec.setChecked(false);
                        antiIapecProgrammatic[0] = false;
                        antiIapecAuto[0] = false;
                    }
                    antiIapecUserOverride[0] = false;
                    if (antiIapecSelfDestructAuto[0]) {
                        antiIapecSelfDestructProgrammatic[0] = true;
                        antiIapecSelfDestruct.setChecked(false);
                        antiIapecSelfDestructProgrammatic[0] = false;
                        antiIapecSelfDestructAuto[0] = false;
                    }
                    antiIapecSelfDestructUserOverride[0] = false;
                    autoHiddenSokey[0] = "";
                    autoDexkeyValue[0] = "";
                    dynamicDexkeyReadyPath[0] = "";
                    dynamicDexkeyReadyValue[0] = "";
                    dynamicDexkeyFailedPath[0] = "";
                    dynamicAutoNotice[0] = Integer.MIN_VALUE;
                    antiQiushuiProgrammatic[0] = true;
                    antiQiushui.setChecked(false);
                    antiQiushuiProgrammatic[0] = false;
                    signatureVerify.setChecked(false);
                    apkAutoScanRunning[0] = false;
                    apkAutoScanReadyPath[0] = "";
                    apkAutoScanReadyError[0] = "";
                    try {
                        if (apkAnalysisLoading[0] != null &&
                                apkAnalysisLoading[0].isShowing()) {
                            apkAnalysisLoading[0].dismiss();
                        }
                    } catch(Exception ignored) {}
                    apkAnalysisLoading[0] = null;

                    if (selectedPath.length() == 0 ||
                            !selectedPath.toLowerCase(Locale.US)
                                    .endsWith(".apk")) {
                        return;
                    }

                    final File selectedApk = new File(selectedPath);
                    if (!selectedApk.isFile()) return;

                    apkAutoScanRunning[0] = true;
                    apkAnalysisLoading[0] =
                            showGoogleLoading(
                                    "正在自动分析 APK 参数...");
                    new Thread(new Runnable(){ public void run(){
                        Api.TaskSecurityOptions security = null;
                        Api.AntiQiushuiProbe antiProbe = null;
                        Api.LegacyIappProbe legacyProbe = null;
                        Api.DynamicSoFingerprintInfo dynamicInfo = null;
                        Api.DynamicRestoreProbe dynamicRestoreInfo = null;
                        Api.IapecProtectionProbe iapecProtectionInfo = null;
                        Api.NativeCompileProbe nativeCompileInfo = null;
                        String detectedMainFile = "";
                        String detectedSokey = "";
                        String detectedDexkey = "";
                        String dynamicError = "";
                        String dexkeyRuntimeError = "";
                        boolean dexkeyRuntimeAttempted = false;
                        boolean dexkeyRuntimeWhitelistBlocked = false;
                        // 先识别远古方案；远古任务不需要反加密探针和动态 SO 指纹。
                        try { legacyProbe = Api.detectLegacyIapp(selectedApk); } catch(Exception ignored) {}
                        try { security = Api.detectTaskSecurityOptions(selectedApk); } catch(Exception ignored) {}
                        if (legacyProbe == null || !legacyProbe.oldIapp) {
                            try { antiProbe = Api.detectAntiQiushuiProbe(selectedApk); } catch(Exception ignored) {}
                        }
                        try { detectedMainFile = Api.detectMainFileFromApk(selectedApk); } catch(Exception ignored) {}
                        if (legacyProbe != null && legacyProbe.oldIapp) {
                            detectedSokey = legacyProbe.sokey == null ? "" : legacyProbe.sokey.trim();
                        } else {
                            try { detectedSokey = Api.extractSokeyFromApkTextSearch(selectedApk); } catch(Exception ignored) {}
                        }
                        if ((legacyProbe != null && legacyProbe.oldIapp) || !useDynamicDexkeyMode()) {
                            try {
                                detectedDexkey = Api.normalizeDexKeyNumber(
                                        Api.extractDexKeyFromApk(selectedApk));
                            } catch(Exception ignored) {}
                        } else {
                            // 方案2在 APK 自动分析阶段直接运行。白名单预检必须发生在
                            // 加载目标 APK 代码之前；未返回有效 DexKey 时由 UI 立即
                            // 展开手动 dexkey 参数，绝不把空值提交给服务器。
                            dexkeyRuntimeAttempted = true;
                            try {
                                JSONObject precheck = new JSONObject();
                                precheck.put("client_dexkey_acquire_mode", "dynamic");
                                checkWhitelistBeforeUpload(selectedApk, 1, precheck);
                                DexKeyRuntime.Result resolved = DexKeyRuntime.extract(
                                        a.getApplicationContext(),
                                        selectedApk,
                                        10000L,
                                        true);
                                if (resolved.success) {
                                    detectedDexkey = Api.normalizeDexKeyNumber(
                                            resolved.value);
                                }
                                if (detectedDexkey == null ||
                                        detectedDexkey.trim().length() == 0) {
                                    dexkeyRuntimeError = resolved.error == null
                                            ? "" : resolved.error.trim();
                                }
                            } catch(Exception dynamicDexkeyError) {
                                dexkeyRuntimeError =
                                    dynamicDexkeyError.getMessage() == null
                                        ? String.valueOf(dynamicDexkeyError)
                                        : dynamicDexkeyError.getMessage();
                                dexkeyRuntimeWhitelistBlocked =
                                    dexkeyRuntimeError.indexOf("白名单") >= 0;
                            }
                        }
                        // 远古与 V3 都可能存在随机数字命令表；不能只凭 v/t/w 类名开启，只按随机数字表检测结果决定。
                        try { dynamicRestoreInfo = Api.detectDynamicRestore(selectedApk); } catch(Exception ignored) {}
                        // iAPEC 自动分析使用真实解释器 LiApEcPro/DynamicEncryption/run;
                        // 与十位数字指令字符串表联合判定，不把普通 com.iapp.app.run.* 当成动态加密。
                        try { iapecProtectionInfo = Api.detectIapecProtection(selectedApk); } catch(Exception ignored) {}
                        // 原生编译特征：Aid_YuCodeX 方法名以 12 位十六进制标识结尾；页面事件和模块函数独立 token 行统一修复。
                        try { nativeCompileInfo = Api.detectNativeCompile(selectedApk); } catch(Exception ignored) {}
                        if (legacyProbe == null || !legacyProbe.oldIapp) {
                            try { dynamicInfo = Api.inspectDynamicSoFingerprints(selectedApk); }
                            catch(Exception exc) { dynamicError = exc.getMessage()==null?String.valueOf(exc):exc.getMessage(); }
                        }
                        final Api.TaskSecurityOptions detectedSecurity = security;
                        final Api.LegacyIappProbe detectedLegacyProbe = legacyProbe;
                        final Api.AntiQiushuiProbe detectedAntiProbe = antiProbe;
                        final Api.DynamicSoFingerprintInfo detectedInfo = dynamicInfo;
                        final Api.DynamicRestoreProbe detectedRestoreInfo = dynamicRestoreInfo;
                        final Api.IapecProtectionProbe detectedIapecInfo = iapecProtectionInfo;
                        final Api.NativeCompileProbe detectedNativeCompileInfo = nativeCompileInfo;
                        final String detectedMain = detectedMainFile;
                        final String detectedSokeyFinal = detectedSokey == null ? "" : detectedSokey;
                        final String detectedDexkeyFinal =
                                detectedDexkey == null ? "" : detectedDexkey;
                        final String detectedError = dynamicError;
                        final String detectedDexkeyRuntimeError =
                                dexkeyRuntimeError == null ? "" : dexkeyRuntimeError;
                        final boolean detectedDexkeyRuntimeAttempted =
                                dexkeyRuntimeAttempted;
                        final boolean detectedDexkeyRuntimeWhitelistBlocked =
                                dexkeyRuntimeWhitelistBlocked;
                        a.runOnUiThread(new Runnable(){ public void run(){
                            if (seq != securityDetectSeq[0]) return;
                            if (!selectedPath.equals(
                                    apk.getText().toString().trim())) {
                                return;
                            }

                            try {
                                if (apkAnalysisLoading[0] != null &&
                                        apkAnalysisLoading[0].isShowing()) {
                                    apkAnalysisLoading[0].dismiss();
                                }
                            } catch(Exception ignored) {}
                            apkAnalysisLoading[0] = null;

                            if (detectedLegacyProbe != null &&
                                    detectedLegacyProbe.oldIapp) {
                                // V126：探针只能把远古方案打开，不能把用户手动选择的远古关掉。
                                legacyIapp.setChecked(true);
                                applyLegacyIappMode.run();
                            }
                            if (detectedSecurity != null) {
                                userPassword.setChecked(detectedSecurity.userPasswordRequired);
                                signatureVerify.setChecked(detectedSecurity.signatureVerifyRequired);
                            }
                            if (detectedAntiProbe != null && antiQiushuiEntitled && !legacyIapp.isChecked()
                                    && !antiQiushuiUserOverride[0]) {
                                // 没有标准 assets/lib.so 就自动走“反加密样本”。iApEcPro.so
                                // 等隐藏容器不再要求用户手动勾选，也不弹提示。
                                boolean needOuterRestore = !detectedAntiProbe.canonicalLibPresent;
                                antiQiushuiProgrammatic[0] = true;
                                antiQiushui.setChecked(needOuterRestore);
                                antiQiushuiProgrammatic[0] = false;
                                antiQiushuiAuto[0] = needOuterRestore;
                                antiQiushuiNoticePath[0] = "";
                            }
                            detectedIapecProtection[0] = detectedIapecInfo;
                            if (detectedIapecInfo != null && antiQiushuiEntitled) {
                                if (detectedIapecInfo.efficientEncrypted && !antiIapecUserOverride[0]) {
                                    antiIapecProgrammatic[0] = true;
                                    antiIapec.setChecked(true);
                                    antiIapecProgrammatic[0] = false;
                                    antiIapecAuto[0] = true;
                                }
                                if (detectedIapecInfo.selfDestruct && !antiIapecSelfDestructUserOverride[0]) {
                                    antiIapecSelfDestructProgrammatic[0] = true;
                                    antiIapecSelfDestruct.setChecked(true);
                                    antiIapecSelfDestructProgrammatic[0] = false;
                                    antiIapecSelfDestructAuto[0] = true;
                                }
                                if (detectedIapecInfo.dynamicEncrypted && !numericRestoreUserOverride[0]
                                        && hasFeature(5)) {
                                    numericRestoreProgrammatic[0] = true;
                                    numericRestore.setChecked(true);
                                    numericRestoreProgrammatic[0] = false;
                                    numericRestoreAuto[0] = true;
                                }
                            }
                            if (detectedMain.length() > 0) {
                                mainFileValue.setText(detectedMain);
                                customMainFile.setChecked(!"mian.iyu".equalsIgnoreCase(detectedMain));
                            }
                            if (detectedSokeyFinal.length() > 0) {
                                // 找到明文 sokey：静默提交，不展开参数 UI。
                                autoHiddenSokey[0] = detectedSokeyFinal;
                                hiddenv.setText("");
                                hidden.setChecked(false);
                                serverSokey.setChecked(false);
                            } else if (!legacyIapp.isChecked()) {
                                // V189：自动解析没有得到明文 sokey 时，不触碰枚举。
                                // 有功能15（或功能0）则自动走服务器获取；没有该功能
                                // 就立即展开手动 sokey 参数，禁止空参数任务先上传。
                                autoHiddenSokey[0] = "";
                                hiddenv.setText("");
                                if (hasFeature(FEATURE_SERVER_SOKEY)) {
                                    hidden.setChecked(false);
                                    serverSokey.setChecked(true);
                                } else {
                                    serverSokey.setChecked(false);
                                    hidden.setChecked(true);
                                    hiddenv.setVisibility(View.VISIBLE);
                                }
                            }
                            if (detectedDexkeyFinal.length() > 0) {
                                // 找到 dexkey：静默提交。方案2同时记录为当前 APK
                                // 的运行时结果，提交阶段不得再次清空。
                                autoDexkeyValue[0] = detectedDexkeyFinal;
                                fbv.setText("");
                                fb.setChecked(false);
                                dexkeyEnum.setChecked(false);
                                if (!legacyIapp.isChecked() &&
                                        useDynamicDexkeyMode()) {
                                    dynamicDexkeyReadyPath[0] = selectedPath;
                                    dynamicDexkeyReadyValue[0] =
                                        detectedDexkeyFinal;
                                    dynamicDexkeyFailedPath[0] = "";
                                }
                            } else {
                                autoDexkeyValue[0] = "";
                                fbv.setText("");
                                dexkeyEnum.setChecked(false);
                                dynamicDexkeyReadyPath[0] = "";
                                dynamicDexkeyReadyValue[0] = "";
                                if (!legacyIapp.isChecked() &&
                                        useDynamicDexkeyMode() &&
                                        detectedDexkeyRuntimeAttempted) {
                                    if (detectedDexkeyRuntimeWhitelistBlocked) {
                                        dynamicDexkeyFailedPath[0] = "";
                                        fb.setChecked(false);
                                        String message =
                                            detectedDexkeyRuntimeError.trim();
                                        toast(message.length() == 0
                                            ? "白名单保护" : message);
                                    } else {
                                        dynamicDexkeyFailedPath[0] =
                                            selectedPath;
                                        fb.setChecked(true);
                                        fbv.setVisibility(View.VISIBLE);
                                        toast("方案2未取得 DexKey，请填写 dexkey参数");
                                    }
                                } else {
                                    dynamicDexkeyFailedPath[0] = "";
                                    fb.setChecked(true);
                                    fbv.setVisibility(View.VISIBLE);
                                }
                            }
                            detectedDynamicRestore[0] = detectedRestoreInfo;
                            if (detectedRestoreInfo != null && detectedRestoreInfo.dynamicEncrypted
                                    && !numericRestoreUserOverride[0]) {
                                if (hasFeature(5)) {
                                    numericRestoreProgrammatic[0] = true;
                                    numericRestore.setChecked(true);
                                    numericRestoreProgrammatic[0] = false;
                                    numericRestoreAuto[0] = true;
                                    dynamicRestoreNoticePath[0] = selectedPath;
                                } else {
                                    // 无订阅时不弹提示，也不强行打开动态修复；由用户手动决定。
                                    dynamicRestoreNoticePath[0] = selectedPath;
                                }
                            }
                            detectedNativeCompile[0] = detectedNativeCompileInfo;
                            if (detectedNativeCompileInfo != null && detectedNativeCompileInfo.nativeCompiled
                                    && !nativeCompileUserOverride[0] && hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)) {
                                nativeCompileProgrammatic[0] = true;
                                nativeCompileRestore.setChecked(true);
                                nativeCompileProgrammatic[0] = false;
                                nativeCompileAuto[0] = true;
                            }
                            detectedDynamicSo[0] = detectedInfo;
                            detectedDynamicPath[0] = selectedPath;
                            if (!legacyIapp.isChecked() && detectedInfo != null && detectedInfo.hasLibraries()) applyDynamicAutoSelection.run();
                            apkAutoScanRunning[0] = false;
                            apkAutoScanReadyPath[0] = selectedPath;
                            apkAutoScanReadyError[0] = "";
                            // 自动探测失败不弹 toast，避免未加密样本/网络波动造成干扰。
                        }});
                    }}).start();
                }
            });

            final AlertDialog dlg = md3FeatureDialog(
                    "新建任务",
                    sv)
                    .setNegativeButton("取消", null)
                    .setPositiveButton("开始", null)
                    .create();

            dlg.setOnDismissListener(
                    new DialogInterface.OnDismissListener() {
                public void onDismiss(DialogInterface dialog) {
                    try {
                        if (apkAnalysisLoading[0] != null &&
                                apkAnalysisLoading[0].isShowing()) {
                            apkAnalysisLoading[0].dismiss();
                        }
                    } catch(Exception ignored) {}
                    apkAnalysisLoading[0] = null;
                }
            });

            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    final String path = apk.getText().toString().trim();
                    if (path.length()==0) { toast("请输入 APK 路径"); return; }
                    final File f = new File(path);
                    if (!f.exists() || !f.isFile()) { toast("APK 文件不存在"); return; }
                    if (path.equals(detectedDynamicPath[0]) && apkAutoScanRunning[0]) {
                        toast("APK参数解析中，请稍后再开始");
                        return;
                    }

                    // 选择文件后的异步识别只负责及时更新界面；真正提交前必须再同步
                    // 识别一次，避免用户刚选完 APK 就点“开始”导致参数尚未更新。
                    Api.LegacyIappProbe taskLegacyProbe = null;
                    // V117：同步探针只能自动开启远古方案，不能覆盖用户已经手动
                    // 勾选的最终参数。旧逻辑在探针未命中时强制 setChecked(false)，
                    // 导致明确选择“远古方案”的任务被提交成 V3。
                    final boolean legacySelectedBeforeSubmitProbe = legacyIapp.isChecked();
                    try {
                        taskLegacyProbe = Api.detectLegacyIapp(f);
                        legacyIapp.setChecked(legacySelectedBeforeSubmitProbe || taskLegacyProbe.oldIapp);
                        if (taskLegacyProbe.oldIapp && taskLegacyProbe.sokey.length() > 0) {
                            autoHiddenSokey[0] = taskLegacyProbe.sokey;
                            hiddenv.setText("");
                            hidden.setChecked(false);
                            serverSokey.setChecked(false);
                        }
                        applyLegacyIappMode.run();
                    } catch(Exception legacyError) {
                        legacyIapp.setChecked(legacySelectedBeforeSubmitProbe);
                    }
                    final boolean oldIappMode = legacyIapp.isChecked();
                    final Api.LegacyIappProbe taskLegacyProbeFinal = taskLegacyProbe;
                    final Api.AntiQiushuiProbe taskAntiProbe;
                    if (oldIappMode) {
                        taskAntiProbe = new Api.AntiQiushuiProbe(true, false, "assets/lib.so", 0);
                        antiQiushui.setChecked(false);
                    } else {
                        try {
                            taskAntiProbe = Api.detectAntiQiushuiProbe(f);
                        } catch(Exception antiError) {
                            toast("APK 读取失败");
                            return;
                        }
                        // 没有标准 assets/lib.so 时，只要具备功能17就自动开启外层恢复，
                        // 不再要求用户先手动勾选。无权限时维持原有功能不可用保护。
                        if (!taskAntiProbe.canonicalLibPresent && !antiQiushui.isChecked()) {
                            if (!antiQiushuiEntitled) { toast("功能不可用"); return; }
                            antiQiushuiProgrammatic[0] = true;
                            antiQiushui.setChecked(true);
                            antiQiushuiProgrammatic[0] = false;
                            antiQiushuiAuto[0] = true;
                        }
                    }

                    // 提交前同步复核 iAPEC 特征，避免用户刚选 APK 就点击开始时
                    // 异步分析尚未结束。手动覆盖仍优先；未覆盖则静默启用对应参数。
                    Api.IapecProtectionProbe taskIapecProbe = null;
                    try { taskIapecProbe = Api.detectIapecProtection(f); } catch(Exception ignored) {}
                    if (taskIapecProbe != null) {
                        detectedIapecProtection[0] = taskIapecProbe;
                        if (antiQiushuiEntitled && taskIapecProbe.efficientEncrypted && !antiIapecUserOverride[0]) {
                            antiIapecProgrammatic[0] = true; antiIapec.setChecked(true); antiIapecProgrammatic[0] = false; antiIapecAuto[0] = true;
                        }
                        if (antiQiushuiEntitled && taskIapecProbe.selfDestruct && !antiIapecSelfDestructUserOverride[0]) {
                            antiIapecSelfDestructProgrammatic[0] = true; antiIapecSelfDestruct.setChecked(true); antiIapecSelfDestructProgrammatic[0] = false; antiIapecSelfDestructAuto[0] = true;
                        }
                        if (hasFeature(5) && taskIapecProbe.dynamicEncrypted && !numericRestoreUserOverride[0]) {
                            numericRestoreProgrammatic[0] = true; numericRestore.setChecked(true); numericRestoreProgrammatic[0] = false; numericRestoreAuto[0] = true;
                        }
                    }

                    final Api.TaskSecurityOptions taskSecurity;
                    try {
                        taskSecurity = Api.detectTaskSecurityOptions(f);
                        userPassword.setChecked(taskSecurity.userPasswordRequired);
                        // 远古方案的 lib_key 也会受签名派生影响；提交前的同步检测必须同样更新开关。
                        signatureVerify.setChecked(taskSecurity.signatureVerifyRequired);
                    } catch(Exception securityError) {
                        toast("密码/签名参数读取失败：" + (securityError.getMessage()==null?String.valueOf(securityError):securityError.getMessage()));
                        return;
                    }
                    if (taskSecurity.userPasswordRequired && userPasswordValue.getText().toString().trim().length()==0) {
                        toast("检测到用户加密，请输入用户加密密码");
                        return;
                    }
                    // 轻量 APK 重打包后可能丢失 APK Signature Scheme v2/v3 块，
                    // 所以签名参与派生时从原 APK 读取证书并作为小参数发送。
                    final String taskSignatureHex = taskSecurity.signatureVerifyRequired ? extractArchiveSignatureHex(f) : "";

                    // Main-file/sokey/dexkey recognition is repeated synchronously before submit so a
                    // fast tap on “开始” cannot race the background APK scan.
                    try {
                        String detectedMain = Api.detectMainFileFromApk(f);
                        if (detectedMain.length() > 0) {
                            mainFileValue.setText(detectedMain);
                            customMainFile.setChecked(!"mian.iyu".equalsIgnoreCase(detectedMain));
                        }
                    } catch(Exception ignored) {}
                    String submitSokey = "";
                    try {
                        String sk = oldIappMode
                                ? (taskLegacyProbeFinal != null
                                    ? taskLegacyProbeFinal.sokey
                                    : Api.extractLegacySokeyFromApkConsensus(f))
                                : Api.extractSokeyFromApkTextSearch(f);
                        submitSokey = sk == null ? "" : sk.trim();
                    } catch(Exception ignored) {}
                    if (submitSokey.length() > 0) {
                        // 提交前同步确认：明文命中时静默使用。
                        autoHiddenSokey[0] = submitSokey;
                        hiddenv.setText("");
                        hidden.setChecked(false);
                        serverSokey.setChecked(false);
                    } else if (!oldIappMode) {
                        // 即使异步自动分析尚未写入结果，提交前也必须做同一决策。
                        // 不自动开启 sokey 枚举。
                        autoHiddenSokey[0] = "";
                        if (hasFeature(FEATURE_SERVER_SOKEY)) {
                            hidden.setChecked(false);
                            serverSokey.setChecked(true);
                        } else {
                            serverSokey.setChecked(false);
                            hidden.setChecked(true);
                            hiddenv.setVisibility(View.VISIBLE);
                        }
                    }
                    if (oldIappMode || !useDynamicDexkeyMode()) {
                        try {
                            String dk = Api.normalizeDexKeyNumber(Api.extractDexKeyFromApk(f));
                            if (dk != null && dk.trim().length() > 0) {
                                // 方案1：提交前同步确认，避免异步静态分析尚未完成。
                                autoDexkeyValue[0] = dk.trim();
                                fbv.setText("");
                                fb.setChecked(false);
                                dexkeyEnum.setChecked(false);
                            }
                        } catch(Exception ignored) {}
                    } else {
                        // 方案2把自动解析器替换为运行时执行，不调用原静态反编译器。
                        dexkeyEnum.setChecked(false);
                        if (path.equals(dynamicDexkeyReadyPath[0]) && dynamicDexkeyReadyValue[0].length() > 0) {
                            autoDexkeyValue[0] = dynamicDexkeyReadyValue[0];
                            fb.setChecked(false);
                            fbv.setText("");
                        } else if (fbv.getText().toString().trim().length() == 0) {
                            autoDexkeyValue[0] = "";
                        }
                    }
                    if (legacyIapp.isChecked()) {
                        boolean hasDexkeyNow = (fb.isChecked() && fbv.getText().toString().trim().length() > 0)
                                || (autoDexkeyValue[0] != null && autoDexkeyValue[0].trim().length() > 0)
                                || dexkeyEnum.isChecked();
                        if (!hasDexkeyNow) {
                            // 提交前再次确保缺失 dexkey 时进入手动“dexkey参数”，而不是枚举。
                            dexkeyEnum.setChecked(false);
                            fb.setChecked(true);
                            fbv.setText("");
                        }
                    }

                    Api.DynamicRestoreProbe restoreProbeTmp = null;
                    if (path.equals(detectedDynamicPath[0]) && detectedDynamicRestore[0] != null) {
                        restoreProbeTmp = detectedDynamicRestore[0];
                    } else {
                        Object cachedRestore = Api.apkScanCacheGet(Api.apkScanCacheKey(f, "dynamic_restore_v14"));
                        if (cachedRestore instanceof Api.DynamicRestoreProbe) restoreProbeTmp = (Api.DynamicRestoreProbe)cachedRestore;
                    }
                    final Api.DynamicRestoreProbe taskDynamicRestoreProbe = restoreProbeTmp;
                    if (taskDynamicRestoreProbe != null && taskDynamicRestoreProbe.dynamicEncrypted
                            && !numericRestoreUserOverride[0] && hasFeature(5) && !numericRestore.isChecked()) {
                        numericRestoreProgrammatic[0] = true;
                        numericRestore.setChecked(true);
                        numericRestoreProgrammatic[0] = false;
                        numericRestoreAuto[0] = true;
                    }

                    Api.NativeCompileProbe nativeCompileProbeTmp = null;
                    if (path.equals(detectedDynamicPath[0]) && detectedNativeCompile[0] != null) {
                        nativeCompileProbeTmp = detectedNativeCompile[0];
                    } else {
                        Object cachedNativeCompile = Api.apkScanCacheGet(Api.apkScanCacheKey(f, "native_compile_v7"));
                        if (cachedNativeCompile instanceof Api.NativeCompileProbe)
                            nativeCompileProbeTmp = (Api.NativeCompileProbe)cachedNativeCompile;
                    }
                    final Api.NativeCompileProbe taskNativeCompileProbe = nativeCompileProbeTmp;
                    if (taskNativeCompileProbe != null && taskNativeCompileProbe.nativeCompiled
                            && !nativeCompileUserOverride[0] && hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)
                            && !nativeCompileRestore.isChecked()) {
                        nativeCompileProgrammatic[0] = true;
                        nativeCompileRestore.setChecked(true);
                        nativeCompileProgrammatic[0] = false;
                        nativeCompileAuto[0] = true;
                    }

                    final Api.DynamicSoFingerprintInfo dynamicSoInfo;
                    if (oldIappMode) {
                        dynamicSoInfo = new Api.DynamicSoFingerprintInfo();
                    } else if (path.equals(detectedDynamicPath[0]) && detectedDynamicSo[0] != null) {
                        dynamicSoInfo = detectedDynamicSo[0];
                    } else {
                        Object cachedSo = Api.apkScanCacheGet(Api.apkScanCacheKey(f, "dynamic_so"));
                        dynamicSoInfo = cachedSo instanceof Api.DynamicSoFingerprintInfo ? (Api.DynamicSoFingerprintInfo)cachedSo : new Api.DynamicSoFingerprintInfo();
                    }

                    // Default SO fingerprints are built into the client.  For a
                    // non-default library, pool feature 15 is tried first; if no
                    // scheme matches, feature 4 (server extraction) is the fallback.
                    boolean explicitDynamicChoice = customDynamicKey.isChecked() || dynamicKey.isChecked() || dynamicPool.getSelectedItemPosition() > 0;
                    if (!oldIappMode && dynamicSoInfo.hasLibraries() && !dynamicSoInfo.defaultScheme && !explicitDynamicChoice) {
                        int matchedPoolIndex = -1;
                        if (hasFeature(FEATURE_DYNAMIC_KEY_POOL)) {
                            if (!dynamicPoolLoaded[0]) {
                                toast("检测到动态库，密钥池方案仍在加载，请稍后重试");
                                return;
                            }
                            matchedPoolIndex = Api.findFirstPoolFeatureMatch(dynamicSoInfo, dynamicPoolFeatures);
                        }
                        if (matchedPoolIndex >= 2) {
                            dynamicKey.setChecked(false);
                            dynamicPool.setEnabled(true);
                            dynamicPool.setSelection(matchedPoolIndex);
                        } else if (hasFeature(4)) {
                            dynamicPool.setSelection(0);
                            dynamicKey.setChecked(true);
                        } else if (hasFeature(FEATURE_DYNAMIC_KEY_POOL)) {
                            customDynamicKey.setChecked(true);
                            toast("请填写密钥");
                            return;
                        } else {
                            customDynamicKey.setChecked(true);
                            toast("请填写密钥");
                            return;
                        }
                    }

                    if (oldIappMode) {
                        dynamicKey.setChecked(false);
                        customDynamicKey.setChecked(false);
                        dynamicPool.setSelection(0);
                        // 远古方案只禁止 V3 动态 key/密钥池；“动态修复”仍可用于随机数字命令表还原。
                        antiQiushui.setChecked(false);
                    }
                    if (dynamicKey.isChecked() && !hasFeature(4)) { toast("功能不可用"); return; }
                    if (antiQiushui.isChecked() && !antiQiushuiEntitled) { antiQiushui.setChecked(false); }
                    if (antiIapec.isChecked() && !antiQiushuiEntitled) { antiIapec.setChecked(false); toast("功能不可用"); return; }
                    if (antiIapecSelfDestruct.isChecked() && !antiQiushuiEntitled) { antiIapecSelfDestruct.setChecked(false); toast("功能不可用"); return; }
                    if (numericRestore.isChecked() && !hasFeature(5)) { toast("功能不可用"); return; }
                    if (nativeCompileRestore.isChecked() && !hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)) { toast("功能不可用"); return; }
                    if (dynamicKey.isChecked() && customDynamicKey.isChecked()) { toast("只能选一个"); return; }
                    final int selectedPoolIndex = dynamicPool.getSelectedItemPosition();
                    final boolean useServerPool = dynamicPoolEntitled && selectedPoolIndex > 0 && !dynamicKey.isChecked() && !customDynamicKey.isChecked();
                    final String selectedPoolMode = useServerPool ? (selectedPoolIndex == 1 ? "enum" : "selected") : "";
                    final String selectedPoolRef = (useServerPool && selectedPoolIndex >= 2 && selectedPoolIndex < dynamicPoolRefs.size()) ? dynamicPoolRefs.get(selectedPoolIndex) : "";
                    if (useServerPool && "enum".equals(selectedPoolMode) && !hasFeature(FEATURE_DYNAMIC_KEY_POOL_ENUM)) { toast("功能不可用"); return; }
                    if (useServerPool && "selected".equals(selectedPoolMode) && !hasFeature(FEATURE_DYNAMIC_KEY_POOL)) { toast("功能不可用"); return; }
                    if (useServerPool && "selected".equals(selectedPoolMode) && selectedPoolRef.length()==0) { toast("请选择密钥"); return; }
                    if (useServerPool && "enum".equals(selectedPoolMode) && (sokeyEnum.isChecked() || dexkeyEnum.isChecked())) { toast("不能同时开启"); return; }
                    if (userPassword.isChecked() && userPasswordValue.getText().toString().trim().length()==0) { toast("请输入用户加密密码"); return; }
                    if (hidden.isChecked() && hiddenv.getText().toString().trim().length()==0) { toast("请输入 so密钥"); return; }
                    final boolean dynamicDexkeySelected = !oldIappMode && useDynamicDexkeyMode();
                    if (dynamicDexkeySelected && path.equals(dynamicDexkeyReadyPath[0])
                            && dynamicDexkeyReadyValue[0].length() > 0) {
                        autoDexkeyValue[0] = dynamicDexkeyReadyValue[0];
                        fb.setChecked(false);
                        dexkeyEnum.setChecked(false);
                    }
                    if (fb.isChecked() && !dexkeyEnum.isChecked()
                            && fbv.getText().toString().trim().length()==0
                            && (autoDexkeyValue[0] == null || autoDexkeyValue[0].trim().length()==0)) {
                        toast("请输入 dex密钥");
                        return;
                    }
                    if (serverSokey.isChecked() && !hasFeature(FEATURE_SERVER_SOKEY)) { toast("功能不可用"); return; }
                    if ((sokeyEnum.isChecked() || dexkeyEnum.isChecked()) && !hasFeature(2)) { toast("功能不可用"); return; }
                    if (sokeyEnum.isChecked() && dexkeyEnum.isChecked() && !hasExactFeature(FEATURE_JOINT_KEY_ENUM)) {
                        toast("功能不可用");
                        return;
                    }
                    if (customDynamicKey.isChecked()) {
                        String pk = customPostKey.getText().toString().trim().replace(" ", "");
                        String kx = customKeyXor.getText().toString().trim().replace(" ", "");
                        if (pk.length()==0 || kx.length()==0) { toast("请输入 post_key 和 xor_key"); return; }
                        if (!pk.matches("[0-9a-fA-F]+") || !kx.matches("[0-9a-fA-F]+") || (pk.length()%2)!=0 || (kx.length()%2)!=0) { toast("动态 key 格式错误"); return; }
                    }
                    if (oldIappMode && hidden.isChecked()) {
                        String oldSk = hiddenv.getText().toString().trim();
                        if (!oldSk.matches("[A-Za-z0-9]{4}")) { toast("sokey格式错误"); return; }
                    }
                    if (oldIappMode) {
                        serverSokey.setChecked(false);
                        boolean hasSokeyParam = (hidden.isChecked() && hiddenv.getText().toString().trim().length() > 0) || (autoHiddenSokey[0] != null && autoHiddenSokey[0].trim().length() > 0) || sokeyEnum.isChecked();
                        boolean hasDexkeyParam = (fb.isChecked() && fbv.getText().toString().trim().length() > 0) || (autoDexkeyValue[0] != null && autoDexkeyValue[0].trim().length() > 0) || dexkeyEnum.isChecked();
                        if (!hasSokeyParam) { toast("未能从客户端自动提取4位sokey，请手动填写sokey参数或开启sokey枚举"); return; }
                        if (!hasDexkeyParam) { toast("未能从客户端自动提取dexkey，请手动填写dexkey参数或开启dexkey枚举"); return; }
                    }
                    if (customMainFile.isChecked()) {
                        String mf = mainFileValue.getText().toString().trim();
                        if (mf.length()==0) { toast("请输入主文件名"); return; }
                        if (mf.indexOf("..") >= 0 || mf.indexOf("/") >= 0 || mf.indexOf("\\") >= 0 || !mf.matches("[-\\p{L}\\p{N}_.]+\\.(mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)")) { toast("主文件名格式错误"); return; }
                    }
                    // 方案2只替换客户端自动解析方式：先启动目标 APK 的运行时壳，
                    // 再解析并调用 com.iapp.app.f.b()。静态 DEX 中暂时没有该类并不判失败。
                    if (!oldIappMode && useDynamicDexkeyMode()
                            && fbv.getText().toString().trim().length() == 0
                            && (autoDexkeyValue[0] == null || autoDexkeyValue[0].trim().length() == 0)) {
                        if (path.equals(dynamicDexkeyFailedPath[0])) {
                            fb.setChecked(true);
                            fbv.setVisibility(View.VISIBLE);
                            toast("动态解析未取得 DexKey，请手动填写 dex密钥");
                            return;
                        }
                        if (dynamicDexkeyResolving[0]) {
                            toast("正在动态解析 DexKey");
                            return;
                        }
                        dynamicDexkeyResolving[0] = true;
                        final AlertDialog runtimeLoading = showGoogleLoading("正在动态解析 DexKey...");
                        new Thread(new Runnable(){ public void run(){
                            String value = "";
                            String error = "";
                            boolean whitelistBlocked = false;
                            try {
                                JSONObject precheck = new JSONObject();
                                precheck.put("client_dexkey_acquire_mode", "dynamic");
                                checkWhitelistBeforeUpload(f, 1, precheck);
                                DexKeyRuntime.Result resolved = DexKeyRuntime.extract(
                                        a.getApplicationContext(), f, 10000L, true);
                                if (resolved.success) value = Api.normalizeDexKeyNumber(resolved.value);
                                if (value.length() == 0) error = resolved.error;
                            } catch(Exception dynamicError) {
                                error = dynamicError.getMessage() == null
                                        ? String.valueOf(dynamicError) : dynamicError.getMessage();
                                whitelistBlocked = error.indexOf("白名单") >= 0;
                            }
                            final String resultValue = value;
                            final String resultError = error;
                            final boolean resultWhitelistBlocked = whitelistBlocked;
                            a.runOnUiThread(new Runnable(){ public void run(){
                                dynamicDexkeyResolving[0] = false;
                                try { if (runtimeLoading != null && runtimeLoading.isShowing()) runtimeLoading.dismiss(); }
                                catch(Exception ignored) {}
                                if (resultValue.length() > 0) {
                                    dynamicDexkeyReadyPath[0] = path;
                                    dynamicDexkeyReadyValue[0] = resultValue;
                                    dynamicDexkeyFailedPath[0] = "";
                                    autoDexkeyValue[0] = resultValue;
                                    fb.setChecked(false);
                                    fbv.setText("");
                                    try { dlg.getButton(AlertDialog.BUTTON_POSITIVE).performClick(); }
                                    catch(Exception ignored) {}
                                } else {
                                    dynamicDexkeyReadyPath[0] = "";
                                    dynamicDexkeyReadyValue[0] = "";
                                    autoDexkeyValue[0] = "";
                                    String message = resultError == null ? "" : resultError.trim();
                                    if (message.length() > 120) message = message.substring(0, 120);
                                    if (resultWhitelistBlocked) {
                                        dynamicDexkeyFailedPath[0] = "";
                                        fb.setChecked(false);
                                        toast(message.length() == 0 ? "白名单保护" : message);
                                    } else {
                                        dynamicDexkeyFailedPath[0] = path;
                                        fb.setChecked(true);
                                        fbv.setVisibility(View.VISIBLE);
                                        toast(message.length() == 0
                                                ? "动态解析未取得 DexKey，请手动填写"
                                                : "动态解析失败，请手动填写 dex密钥");
                                    }
                                }
                            }});
                        }}, "iapt-dexkey-runtime-request").start();
                        return;
                    }

                    // V189 最终客户端守卫：方案2没有返回 DexKey 时，必须停在
                    // 参数页并展开手动输入；不得创建本地任务或上传到服务器。
                    if (!oldIappMode && useDynamicDexkeyMode()
                            && !dexkeyEnum.isChecked()
                            && fbv.getText().toString().trim().length() == 0
                            && (autoDexkeyValue[0] == null ||
                                autoDexkeyValue[0].trim().length() == 0)) {
                        dynamicDexkeyFailedPath[0] = path;
                        fb.setChecked(true);
                        fbv.setVisibility(View.VISIBLE);
                        toast("方案2未取得 DexKey，请填写 dexkey参数");
                        return;
                    }

                    int localFeatureId = 1;
                    if (sokeyEnum.isChecked() || dexkeyEnum.isChecked()) localFeatureId = 2;
                    else if (dynamicKey.isChecked()) localFeatureId = 4;
                    else if (numericRestore.isChecked() || nativeCompileRestore.isChecked()) localFeatureId = FEATURE_NATIVE_COMPILE_RESTORE;
                    else if (antiIapec.isChecked() || antiIapecSelfDestruct.isChecked()) localFeatureId = FEATURE_ANTI_IAPEC;
                    else if (serverSokey.isChecked()) localFeatureId = FEATURE_SERVER_SOKEY;
                    else if (useServerPool && "enum".equals(selectedPoolMode)) localFeatureId = FEATURE_DYNAMIC_KEY_POOL_ENUM;
                    else if (useServerPool && "selected".equals(selectedPoolMode)) localFeatureId = FEATURE_DYNAMIC_KEY_POOL;
                    final Api.DynamicSoFingerprintInfo taskDynamicSoInfo = dynamicSoInfo;
                    final boolean taskRestoreEnabled = numericRestore.isChecked();
                    final boolean taskNativeCompileEnabled = nativeCompileRestore.isChecked();
                    final boolean taskAntiIapecEnabled = antiIapec.isChecked();
                    final boolean taskAntiIapecSelfDestructEnabled = antiIapecSelfDestruct.isChecked();
                    // V117：在真正创建本地占位任务前禁用按钮，避免极快连点
                    // 产生两个独立上传线程。列表层仍会按服务器 task_id 去重。
                    try { dlg.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false); } catch(Exception ignored) {}
                    final JSONObject localTask = addLocalTask(f.getName(), localFeatureId, "上传文件中", ad);
                    if (oldIappMode) {
                        try {
                            localTask.put("decrypt_scheme", "ancient");
                            localTask.put("decrypt_version", "ancient");
                            localTask.put("task_version", "ancient");
                            localTask.put("client_final_scheme", "ancient");
                            localTask.put("legacy_iapp", true);
                            localTask.put("old_iapp", true);
                        } catch(Exception ignored) {}
                    }
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        JSONObject opt = new JSONObject();
                        opt.put("fast_c", fast.isChecked() ? "on" : "off");
                        // v68：应用名必须依赖 resources.arsc 资源表解析，不再只依赖 AndroidManifest.xml 的 label 文本，避免中文名乱码/资源ID未解析。
                        opt.put("upload_arsc", true);
                        opt.put("include_arsc", true);
                        opt.put("client_app_name_source", "arsc_package_manager");
                        opt.put("decrypt_scheme", oldIappMode ? "ancient" : "v3");
                        opt.put("client_final_scheme", oldIappMode ? "ancient" : "v3");
                        opt.put("client_scheme_explicit", true);
                        if (oldIappMode) opt.put("client_route_lock", "ancient-endpoint-v121");
                        if (oldIappMode) {
                            opt.put("legacy_iapp", true);
                            opt.put("old_iapp", true);
                            opt.put("old_iapp_auto_detected", taskLegacyProbeFinal != null && taskLegacyProbeFinal.oldIapp);
                            opt.put("decrypt_version", "ancient");
                            opt.put("task_version", "ancient");
                            opt.put("dynamic_key", false);
                            opt.put("custom_dynamic_key", false);
                            opt.put("no_dynamic_key", true);
                            // 远古方案也允许“动态修复/数字函数表还原”；这里只禁止 V3 动态 key。
                        }
                        if (!oldIappMode && antiQiushui.isChecked()) {
                            opt.put("anti_encrypted_sample", true);
                            opt.put("anti_qiushui", true);
                            opt.put("hidden_resource_restore", true);
                            opt.put("anti_encrypted_sample_auto_detected", antiQiushuiAuto[0]);
                            opt.put("anti_encrypted_sample_auto_reason", taskAntiProbe.canonicalLibPresent ? "" : "missing-assets/lib.so");
                            // V129: anti-encrypted mode is a complete static-analysis
                            // request.  The server needs every DEX/SO/resource both to
                            // restore hidden lib.so and to recover metadata semantics
                            // such as versionName 1.0 -> 1.000000 from idbfj.
                            opt.put("static_resource_analysis", true);
                            opt.put("static_parameter_analysis", true);
                            opt.put("static_analysis_protocol", "resource-parameter-v1");
                            boolean skipResources = skipAntiResources.isChecked();
                            opt.put("no_decrypt_resource_files", skipResources);
                            opt.put("skip_anti_resources", skipResources);
                            opt.put("anti_resource_output", !skipResources);
                            if (antiQiushuiEntitled) {
                                opt.put("anti_qiushui_feature_id", FEATURE_ANTI_QIUSHUI);
                                JSONArray requiredFeatures = new JSONArray();
                                requiredFeatures.put(FEATURE_ANTI_QIUSHUI);
                                opt.put("required_feature_ids", requiredFeatures);
                            }
                        }
                        // 反iAPEC加密只负责“代码高效加密”字符串/源码密文；
                        // iApEcPro-数字(...) 由功能5“动态修复”负责，两者互不强制绑定。
                        opt.put("anti_iapec_encryption", taskAntiIapecEnabled);
                        opt.put("anti_iapec_auto_detected", taskAntiIapecEnabled && antiIapecAuto[0]);
                        if (taskAntiIapecEnabled) {
                            opt.put("anti_iapec_feature_id", FEATURE_ANTI_IAPEC);
                            opt.put("anti_iapec_restore_strategy", "efficient-string-only/base64+emoji-digit+xor-ZhaoLingYa/before-dynamic-and-filename-fixpoint");
                            JSONArray requiredFeatures = opt.optJSONArray("required_feature_ids");
                            if (requiredFeatures == null) requiredFeatures = new JSONArray();
                            boolean has17 = false;
                            for (int i = 0; i < requiredFeatures.length(); i++) {
                                if (requiredFeatures.optInt(i, -1) == FEATURE_ANTI_IAPEC) { has17 = true; break; }
                            }
                            if (!has17) requiredFeatures.put(FEATURE_ANTI_IAPEC);
                            opt.put("required_feature_ids", requiredFeatures);
                        }
                        // 反iAPEC自毁是独立参数，只恢复布局源码中被哈希/销毁的真实控件类型。
                        opt.put("anti_iapec_self_destruct", taskAntiIapecSelfDestructEnabled);
                        opt.put("anti_iapec_self_destruct_auto_detected", taskAntiIapecSelfDestructEnabled && antiIapecSelfDestructAuto[0]);
                        if (taskAntiIapecSelfDestructEnabled) {
                            opt.put("anti_iapec_self_destruct_feature_id", FEATURE_ANTI_IAPEC_SELF_DESTRUCT);
                            opt.put("anti_iapec_self_destruct_strategy", "libDestruction-profile+layout-semantics/control-type-backfill");
                            JSONArray requiredFeatures = opt.optJSONArray("required_feature_ids");
                            if (requiredFeatures == null) requiredFeatures = new JSONArray();
                            boolean has17 = false;
                            for (int i = 0; i < requiredFeatures.length(); i++) {
                                if (requiredFeatures.optInt(i, -1) == FEATURE_ANTI_IAPEC_SELF_DESTRUCT) { has17 = true; break; }
                            }
                            if (!has17) requiredFeatures.put(FEATURE_ANTI_IAPEC_SELF_DESTRUCT);
                            opt.put("required_feature_ids", requiredFeatures);
                        }
                        Api.IapecProtectionProbe submittedIapecProbe = detectedIapecProtection[0];
                        if (submittedIapecProbe != null) {
                            opt.put("client_iapec_efficient_detected", submittedIapecProbe.efficientEncrypted);
                            opt.put("client_iapec_dynamic_detected", submittedIapecProbe.dynamicEncrypted);
                            opt.put("client_iapec_dynamic_run_class_present", submittedIapecProbe.runClassPresent);
                            opt.put("client_iapec_dynamic_numeric_token_count", submittedIapecProbe.numericTokenCount);
                            opt.put("client_iapec_self_destruct_detected", submittedIapecProbe.selfDestruct);
                            opt.put("client_iapec_dynamic_dex_entry", submittedIapecProbe.dexEntry);
                        }
                        // DEX 上传显式开关：普通解密不上传 classes*.dex；动态修复/原生编译修复开启时上传全部 classes*.dex。
                        boolean staticAntiUpload = !oldIappMode && antiQiushui.isChecked();
                        boolean taskNeedDexUpload = taskRestoreEnabled || taskNativeCompileEnabled || staticAntiUpload;
                        opt.put("require_dex_upload", taskNeedDexUpload);
                        opt.put("client_need_dex", taskNeedDexUpload);
                        if (fb.isChecked() && !dexkeyEnum.isChecked() && fbv.getText().toString().trim().length() > 0)
                            opt.put("fb", Api.normalizeDexKeyNumber(fbv.getText().toString().trim()));
                        else if (!dexkeyEnum.isChecked() && autoDexkeyValue[0] != null && autoDexkeyValue[0].trim().length() > 0) {
                            opt.put("fb", Api.normalizeDexKeyNumber(autoDexkeyValue[0].trim()));
                            if (oldIappMode) opt.put("client_ancient_dexkey_auto", true);
                            else opt.put("client_v3_dexkey_auto", true);
                        }
                        String selectedSokey = "";
                        boolean selectedSokeyManual = false;
                        if (hidden.isChecked() && !sokeyEnum.isChecked() && !serverSokey.isChecked()) {
                            selectedSokey = hiddenv.getText().toString().trim();
                            selectedSokeyManual = selectedSokey.length() > 0;
                        } else if (!sokeyEnum.isChecked() && !serverSokey.isChecked() && autoHiddenSokey[0] != null) {
                            selectedSokey = autoHiddenSokey[0].trim();
                        }
                        if (oldIappMode) {
                            opt.put("ancient_client_auto_params", true);
                            opt.put("server_sokey", false);
                            if (selectedSokey.matches("[A-Za-z0-9]{4}")) {
                                opt.put("sokey", selectedSokey);
                                opt.put("old_sokey", selectedSokey);
                                opt.put("client_ancient_sokey_auto", !selectedSokeyManual);
                                opt.put("client_ancient_sokey_manual", selectedSokeyManual);
                            }
                        } else if (selectedSokey.length() > 0) {
                            opt.put("hidden", selectedSokey);
                        }
                        if (!oldIappMode && serverSokey.isChecked()) opt.put("server_sokey", true);
                        if (sokeyEnum.isChecked()) {
                            opt.put("sokey_enum", true);
                            opt.put("sokey_enum_seconds", 180);
                            opt.put("sokey_enum_files", 1);
                            opt.put("sokey_max_candidates", 0);
                        }
                        if (dexkeyEnum.isChecked()) {
                            opt.put("dexkey_enum", true);
                            opt.put("dexkey_enum_start", oldIappMode ? 3100000 : 1736417);
                            opt.put("dexkey_enum_stop", oldIappMode ? 10000000 : 5936417);
                            opt.put("no_dexkey_dex_hint", true);
                        }
                        if (sokeyEnum.isChecked() && dexkeyEnum.isChecked()) {
                            opt.put("joint_key_enum_requested", true);
                        }
                        // 只有 dexkey 枚举才禁止客户端自动提取 dexkey。
                        // sokey 枚举仍然需要一个已知 dexkey 来验证候选，因此必须保留本地提取并随任务上传。
                        if (dexkeyEnum.isChecked()) {
                            opt.put("disable_client_dexkey_auto", true);
                        }
                        if (sokeyEnum.isChecked() || dexkeyEnum.isChecked()) {
                            // 枚举并发数仅由服务端 .env 的 IAPT_ENUM_WORKERS 控制，客户端不再传入。
                            opt.put("enum_quiet", true);
                            opt.put("no_python_fallback", true);
                            opt.put("dexkey_mian_prefix_kb", 64);
                            opt.put("dexkey_max_so_keysets", 16);
                        }
                        if (taskDynamicSoInfo != null && taskDynamicSoInfo.hasLibraries()) {
                            opt.put("dynamic_key_features", taskDynamicSoInfo.features);
                            opt.put("dynamic_key_feature_version", Api.DYNAMIC_SO_FEATURE_VERSION);
                            opt.put("dynamic_key_sample_entry", taskDynamicSoInfo.firstEntry);
                            opt.put("dynamic_key_sample_abi", taskDynamicSoInfo.firstAbi);
                            opt.put("dynamic_key_default_match", taskDynamicSoInfo.defaultScheme);
                        }
                        if (userPassword.isChecked()) opt.put("user_password", userPasswordValue.getText().toString());
                        // Explicit skip fixes the old bug where an unchecked box
                        // still fell back to the decrypter's automatic signature mode.
                        boolean effectiveSignatureVerify = signatureVerify.isChecked()
                                || (oldIappMode && taskSecurity != null && taskSecurity.signatureVerifyRequired);
                        opt.put("signature_mode", effectiveSignatureVerify ? "verify" : "skip");
                        if (effectiveSignatureVerify) {
                            if (taskSignatureHex.length() > 0) {
                                opt.put("signature_bytes_hex", taskSignatureHex);
                                if (oldIappMode) opt.put("client_ancient_signature_auto", true);
                            } else if (oldIappMode) {
                                throw new Exception("远古方案签名参与派生，但客户端未能提取签名证书");
                            }
                        }
                        // “动态修复”是解密后的随机数字命令表替换：V3 与远古方案都可使用。
                        // 它不是功能8的源码/DEX还原任务，绝不能打开 dex_static_restore。
                        final boolean explicitRestore = taskRestoreEnabled;
                        final boolean ancientRestore = oldIappMode && explicitRestore;
                        final boolean v3Restore = !oldIappMode && explicitRestore;
                        if (!oldIappMode) {
                            opt.put("decrypt_version", "v3");
                            opt.put("task_version", "v3");
                        }
                        if (taskDynamicRestoreProbe != null) {
                            opt.put("dynamic_restore_detected", taskDynamicRestoreProbe.dynamicEncrypted);
                            opt.put("dynamic_restore_detector_version", Api.DYNAMIC_RESTORE_DETECTOR_VERSION);
                            opt.put("dynamic_restore_strategy", "iapec_numeric_dispatch+randomized_numeric_command_table");
                            opt.put("dynamic_restore_dex_entry", taskDynamicRestoreProbe.dexEntry);
                            opt.put("dynamic_restore_class", taskDynamicRestoreProbe.classDescriptor);
                            opt.put("dynamic_class", taskDynamicRestoreProbe.classDescriptor);
                            opt.put("numeric_restore_class", taskDynamicRestoreProbe.classDescriptor);
                            opt.put("dynamic_restore_class_name", taskDynamicRestoreProbe.className);
                            opt.put("dynamic_restore_class_code_units", taskDynamicRestoreProbe.codeUnits);
                            opt.put("dynamic_restore_class_method_count", taskDynamicRestoreProbe.methodCount);
                            opt.put("dynamic_restore_command_count", taskDynamicRestoreProbe.commandCount);
                            opt.put("dynamic_restore_largest_class_code_units", taskDynamicRestoreProbe.largestClassCodeUnits);
                            opt.put("dynamic_restore_random_table", taskDynamicRestoreProbe.randomizedNumericTable);
                            opt.put("dynamic_restore_baseline_table", taskDynamicRestoreProbe.baselineNumericTable);
                            opt.put("dynamic_restore_table_pairs", taskDynamicRestoreProbe.numericTablePairs);
                            opt.put("dynamic_restore_table_min", taskDynamicRestoreProbe.numericTableMin);
                            opt.put("dynamic_restore_table_max", taskDynamicRestoreProbe.numericTableMax);
                            opt.put("dynamic_restore_iapec_run_class", taskDynamicRestoreProbe.iapecRunClassPresent);
                            opt.put("dynamic_restore_iapec_numeric_token_count", taskDynamicRestoreProbe.iapecNumericTokenCount);
                            opt.put("dynamic_restore_auto_enabled", explicitRestore && numericRestoreAuto[0]);
                        }
                        opt.put("ancient_dynamic_restore", ancientRestore);
                        opt.put("v3_dynamic_restore", v3Restore);
                        opt.put("numeric_restore", explicitRestore);
                        opt.put("dynamic_restore", explicitRestore);
                        opt.put("iapec_numeric_dynamic_restore", explicitRestore);
                        opt.put("restore_fn_names", explicitRestore ? "on" : "off");

                        // 原生编译修复与动态修复共用功能5，但使用独立服务端处理器。
                        final boolean explicitNativeCompile = taskNativeCompileEnabled;
                        opt.put("native_compile_restore", explicitNativeCompile);
                        opt.put("v3_native_compile_restore", !oldIappMode && explicitNativeCompile);
                        opt.put("ancient_native_compile_restore", oldIappMode && explicitNativeCompile);
                        // v5: 服务端同时扫描已命名 .iyu 与 src/_unknown/*.bin 明文成员，
                        // 回填后再恢复文件名，并以新页面名进行最多三轮消歧重试。
                        opt.put("native_compile_package_tree", explicitNativeCompile);
                        opt.put("native_compile_token_fallback", explicitNativeCompile);
                        opt.put("native_compile_direct_v3_backfill", explicitNativeCompile);
                        opt.put("native_compile_restore_strategy", "manifest-package/exact-token/all-text-files/v3-syntax-backfill-before-filename-rescan");
                        opt.put("native_compile_restore_auto_enabled", explicitNativeCompile && nativeCompileAuto[0]);
                        if (taskNativeCompileProbe != null) {
                            opt.put("native_compile_detected", taskNativeCompileProbe.nativeCompiled);
                            opt.put("native_compile_detector_version", Api.NATIVE_COMPILE_RESTORE_DETECTOR_VERSION);
                            opt.put("native_compile_dex_entry", taskNativeCompileProbe.dexEntry);
                            opt.put("native_compile_event_method_count", taskNativeCompileProbe.eventMethodNameCount);
                            opt.put("native_compile_source_string_count", taskNativeCompileProbe.sourceStringCount);
                            opt.put("native_compile_reason", taskNativeCompileProbe.reason);
                        }
                        opt.put("dex_static_restore", false);
                        if (explicitRestore || explicitNativeCompile) {
                            opt.put("primary_feature_id", FEATURE_NATIVE_COMPILE_RESTORE);
                        }
                        if (!explicitRestore) {
                            opt.put("restore_props", false);
                            opt.put("restore_events", false);
                            opt.put("rename_vars", false);
                            opt.put("rename_files", false);
                            opt.put("rename_functions", false);
                            opt.put("restore_resource_names", false);
                            opt.put("auto_deobfuscate", false);
                            opt.put("auto_obfuscation_restore", false);
                            opt.put("deobfuscate", false);
                        }
                        if (!oldIappMode && dynamicKey.isChecked()) opt.put("dynamic_key", true);
                        if (!oldIappMode && customDynamicKey.isChecked()) {
                            opt.put("custom_dynamic_key", true);
                            opt.put("post_key", customPostKey.getText().toString().trim().replace(" ", ""));
                            opt.put("xor_key", customKeyXor.getText().toString().trim().replace(" ", ""));
                        }
                        if (!oldIappMode && useServerPool) {
                            opt.put("server_key_pool_mode", selectedPoolMode);
                            if ("selected".equals(selectedPoolMode)) opt.put("server_key_pool_ref", selectedPoolRef);
                        }
                        if (maxFiles.isChecked()) opt.put("max_output_files", maxFilesv.getText().toString().trim());
                        if (customMainFile.isChecked()) opt.put("main_file", mainFileValue.getText().toString().trim());
                        opt.put("client_dexkey_acquire_mode", useDynamicDexkeyMode() ? "dynamic" : "static");
                        opt.put("client_dexkey_acquire_mode_version", 187);
                        int wlFeature = 1;
                        if (sokeyEnum.isChecked() || dexkeyEnum.isChecked()) wlFeature = 2;
                        else if (dynamicKey.isChecked()) wlFeature = 4;
                        else if (numericRestore.isChecked() || nativeCompileRestore.isChecked()) wlFeature = FEATURE_NATIVE_COMPILE_RESTORE;
                        else if (taskAntiIapecEnabled || taskAntiIapecSelfDestructEnabled) wlFeature = FEATURE_ANTI_IAPEC;
                        else if (serverSokey.isChecked()) wlFeature = FEATURE_SERVER_SOKEY;
                        else if (useServerPool && "enum".equals(selectedPoolMode)) wlFeature = FEATURE_DYNAMIC_KEY_POOL_ENUM;
                        else if (useServerPool && "selected".equals(selectedPoolMode)) wlFeature = FEATURE_DYNAMIC_KEY_POOL;
                        checkWhitelistBeforeUpload(f, wlFeature, opt);
                        return api.uploadTask(f, opt);
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        void showDynamicKeyExtractDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox();
            box.setPadding(dp(4), dp(4), dp(4), dp(4));
            box.setBackgroundColor(Color.TRANSPARENT);
            sv.addView(box);

            final EditText path = edit("文件路径");
            path.setSingleLine(true);
            addM(box, path, -1, dp(50), 0, 4, 0, 8);
            Button browse = btn("浏览文件", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, browse, -1, dp(46), 0, 0, 0, 8);
            browse.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(path, true); }});

            final AlertDialog dlg = md3FeatureDialog("提取动态 Key", sv).setNegativeButton("取消", null).setPositiveButton("开始提取", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!hasFeature(4)) { toast("当前订阅不支持服务器获取动态 Key（功能4）"); return; }
                    if (!ensureStorageReady()) return;
                    final File src = new File(path.getText().toString().trim());
                    if (!src.exists() || !src.isFile()) { toast("文件不存在"); return; }
                    String lower = src.getName().toLowerCase(Locale.US);
                    if (!(lower.endsWith(".apk") || lower.endsWith(".zip") || lower.endsWith(".apks") || lower.endsWith(".so"))) {
                        toast("请选择 APK、SO ZIP、APKS 或 libygsiyu.so");
                        return;
                    }
                    final String resultName = dynamicKeyZipName(src.getName());
                    final JSONObject localTask = addLocalTask(resultName, 4, "上传文件中", ad);
                    try {
                        localTask.put("decrypt_version", "key");
                        localTask.put("task_version", "key");
                        localTask.put("app_name", "动态Key提取");
                    } catch(Exception ignored) {}
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        // APK/ZIP/APKS 只在客户端读取：临时打包其中全部 ABI 的 libygsiyu.so，由服务器做指令数据流还原。
                        // 不上传完整 APK、DEX、resources.arsc、Manifest 或其他资源。
                        // 单独选择 SO 时直接上传该 SO。
                        return api.extractDynamicKeyTask(src, src.getName());
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        void showServerSoKeyExtractDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox();
            box.setPadding(dp(4), dp(4), dp(4), dp(4));
            box.setBackgroundColor(Color.TRANSPARENT);
            sv.addView(box);

            final EditText path = edit("文件路径");
            path.setSingleLine(true);
            addM(box, path, -1, dp(50), 0, 4, 0, 8);
            Button browse = btn("浏览文件", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, browse, -1, dp(46), 0, 0, 0, 8);
            browse.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(path, true); }});

            final AlertDialog dlg = md3FeatureDialog("sokey（服务器获取）", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!hasFeature(FEATURE_SERVER_SOKEY)) { toast("功能不可用"); return; }
                    if (!ensureStorageReady()) return;
                    final File src = new File(path.getText().toString().trim());
                    if (!src.exists() || !src.isFile()) { toast("文件不存在"); return; }
                    String lower = src.getName().toLowerCase(Locale.US);
                    if (!(lower.endsWith(".apk") || lower.endsWith(".zip") || lower.endsWith(".apks") || lower.endsWith(".so"))) {
                        toast("请选择 APK、SO ZIP、APKS 或 libygsiyu.so");
                        return;
                    }

                    final String resultName = serverSoKeyZipName(src.getName());
                    final JSONObject localTask = addLocalTask(resultName, FEATURE_SERVER_SOKEY, "上传文件中", ad);
                    try {
                        localTask.put("decrypt_version", "sokey");
                        localTask.put("task_version", "sokey");
                        localTask.put("app_name", "服务器获取sokey");
                    } catch(Exception ignored) {}
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        // APK/ZIP/APKS 仅在客户端抽取全部 ABI 的 libygsiyu.so，避免上传完整安装包。
                        // 单个 SO 直接上传；服务端输出 ZIP，根目录仅包含 sokey.txt。
                        return api.extractServerSoKeyTask(src, src.getName());
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        String serverSoKeyZipName(String sourceName) {
            String name = sourceName == null ? "" : sourceName.trim();
            name = name.replaceAll("[\\/:*?\"<>|]", "_");
            int dot = name.lastIndexOf('.');
            if (dot > 0) name = name.substring(0, dot);
            if (name.length() == 0) name = "server_sokey";
            return name + "_sokey.zip";
        }

        String dynamicKeyZipName(String sourceName) {
            String name = sourceName == null ? "" : sourceName.trim();
            name = name.replaceAll("[\\/:*?\"<>|]", "_");
            int dot = name.lastIndexOf('.');
            if (dot > 0) name = name.substring(0, dot);
            if (name.length() == 0) name = "dynamic_key";
            return name + ".zip";
        }

        File iaptDownloadDir() {
            File dir = new File(Environment.getExternalStorageDirectory(), "iApt");
            if (!dir.exists()) dir.mkdirs();
            if (!dir.exists() || !dir.canWrite()) {
                File alt = a.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                dir = new File(alt == null ? a.getFilesDir() : alt, "iApt");
                if (!dir.exists()) dir.mkdirs();
            }
            return dir;
        }

        String normalizeSourcePath(String raw) {
            String p = raw == null ? "" : raw.trim();
            while (p.endsWith("/") && p.length() > 1) p = p.substring(0, p.length() - 1);
            if (p.length() == 0) return "";
            int slash = p.lastIndexOf('/');
            String last = slash >= 0 ? p.substring(slash + 1) : p;
            if ("src".equalsIgnoreCase(last)) return p;
            return p + "/src";
        }

        String normalizeProjectRootPath(String raw) {
            String p = raw == null ? "" : raw.trim();
            while (p.endsWith("/") && p.length() > 1) p = p.substring(0, p.length() - 1);
            return p;
        }

        void showSourceRestoreDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final EditText project = edit("项目根目录"); project.setSingleLine(true);
            box.addView(label("项目路径")); addM(box, project, -1, dp(50), 0, 4,0,8);
            Button pickProject = btn("浏览选择项目目录", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, pickProject, -1, dp(46), 0, 0, 0, 8);
            final CheckBox dexRestore = md3FeatureSwitch("同时进行 DEX 还原"); dexRestore.setChecked(false);
            box.addView(dexRestore, new LinearLayout.LayoutParams(-1, dp(40)));
            final CheckBox restoreProps = md3FeatureSwitch("还原抽离属性"); restoreProps.setChecked(true);
            final CheckBox restoreEvents = md3FeatureSwitch("还原抽离事件"); restoreEvents.setChecked(true);
            final CheckBox renameVars = md3FeatureSwitch("还原变量名"); renameVars.setChecked(true);
            final CheckBox renameFiles = md3FeatureSwitch("还原文件名"); renameFiles.setChecked(true);
            final CheckBox renameFunctions = md3FeatureSwitch("还原函数名"); renameFunctions.setChecked(true);
            final CheckBox restoreResourceNames = md3FeatureSwitch("还原资源名"); restoreResourceNames.setChecked(true);
            box.addView(restoreProps, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(restoreEvents, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameVars, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameFiles, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameFunctions, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(restoreResourceNames, new LinearLayout.LayoutParams(-1, dp(40)));
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, openPerm, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 6);
            pickProject.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showDirectoryBrowser(project); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});

            final AlertDialog dlg = md3FeatureDialog("混淆还原", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    if (!hasFeature(8)) { toast("当前订阅不支持混淆还原"); return; }
                    final String projectPath = normalizeProjectRootPath(project.getText().toString());
                    if (projectPath.length()==0) { toast("请选择项目根目录"); return; }
                    final File projectDir = new File(projectPath);
                    if (!projectDir.exists() || !projectDir.isDirectory()) { toast("项目目录不存在：" + projectPath); return; }
                    final File srcDir = new File(projectDir, "src");
                    if (!srcDir.exists() || !srcDir.isDirectory()) { toast("项目根目录下没有 src：" + srcDir.getAbsolutePath()); return; }
                    if (restoreResourceNames.isChecked()) {
                        File resDir = new File(projectDir, "res");
                        if (!resDir.exists() || !resDir.isDirectory()) { toast("开启资源名还原时需要 res 目录：" + resDir.getAbsolutePath()); return; }
                    }
                    final boolean useDexRestore = dexRestore.isChecked();
                    if (useDexRestore) {
                        File apkLib = new File(new File(projectDir, "apk"), "lib");
                        if (DexReadableAlias.countDexContainers(apkLib) <= 0) { toast("项目 apk/lib 下没有找到 DEX/APK/ZIP/JAR"); return; }
                    }
                    final String baseName = projectDir.getName().length() == 0 ? "project" : projectDir.getName();
                    final JSONObject localTask = addLocalTask(baseName + (useDexRestore ? "_dex_restore.zip" : "_src.zip"), 8, "上传中", ad);
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        File packed = useDexRestore
                                ? Api.prepareDexRestoreProjectZip(projectDir, restoreResourceNames.isChecked())
                                : Api.prepareSourceProjectZip(projectDir, restoreResourceNames.isChecked());
                        try {
                            JSONObject opt = new JSONObject();
                            opt.put("restore_props", restoreProps.isChecked());
                            opt.put("restore_events", restoreEvents.isChecked());
                            opt.put("rename_vars", renameVars.isChecked());
                            opt.put("rename_files", renameFiles.isChecked());
                            opt.put("rename_functions", renameFunctions.isChecked());
                            opt.put("restore_resource_names", restoreResourceNames.isChecked());
                            if (useDexRestore) {
                                putDexRestoreClientPolicy(opt);
                                return api.uploadStaticDexSourceRestoreTask(packed, null, baseName, opt);
                            }
                            return api.uploadSourceRestoreTask(packed, baseName, opt);
                        } finally {
                            try { packed.delete(); } catch(Exception e) {}
                        }
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        void putDexRestoreClientPolicy(JSONObject opt) throws Exception {
            opt.put("dex_static_restore", true);
            opt.put("decrypt_version", "dex_restore");
            opt.put("scan_source_apk_lib", true);
            opt.put("dex_input_mode", "project_apk_lib_auto");
            opt.put("dex_upload_source_only", true);
            opt.put("dex_direct_return_backfill", true);
            opt.put("dex_deterministic_constant_backfill", true);
            opt.put("dex_constant_fold_until_fixed", true);
            opt.put("dex_unresolved_readable_alias", true);
            opt.put("dex_rewrite_source_references", true);
            opt.put("dex_return_patched_inputs", true);
            opt.put("dex_readable_alias_style", "a1,b1,c1-same-length");
            opt.put("client_dex_preprocessed", true);
        }


        void showStaticDexSourceRestoreDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final EditText project = edit("项目根目录"); project.setSingleLine(true);
            box.addView(label("项目路径")); addM(box, project, -1, dp(50), 0, 4,0,8);
            Button pickProject = btn("浏览选择项目目录", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, pickProject, -1, dp(46), 0, 0, 0, 8);
            final CheckBox restoreProps = md3FeatureSwitch("还原抽离属性"); restoreProps.setChecked(true);
            final CheckBox restoreEvents = md3FeatureSwitch("还原抽离事件"); restoreEvents.setChecked(true);
            final CheckBox renameVars = md3FeatureSwitch("还原变量名"); renameVars.setChecked(true);
            final CheckBox renameFiles = md3FeatureSwitch("还原文件名"); renameFiles.setChecked(true);
            final CheckBox renameFunctions = md3FeatureSwitch("还原函数名"); renameFunctions.setChecked(true);
            final CheckBox restoreResourceNames = md3FeatureSwitch("还原资源名"); restoreResourceNames.setChecked(true);
            final CheckBox dexOnly = md3FeatureSwitch("只做 DEX 静态还原，不再二次重命名"); dexOnly.setChecked(false);
            box.addView(restoreProps, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(restoreEvents, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameVars, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameFiles, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(renameFunctions, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(restoreResourceNames, new LinearLayout.LayoutParams(-1, dp(40)));
            box.addView(dexOnly, new LinearLayout.LayoutParams(-1, dp(40)));
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, openPerm, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 6);
            pickProject.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showDirectoryBrowser(project); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});

            final AlertDialog dlg = md3FeatureDialog("DEX 还原", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    if (!hasFeature(8)) { toast("当前订阅不支持 DEX 还原"); return; }
                    final String projectPath = normalizeProjectRootPath(project.getText().toString());
                    if (projectPath.length()==0) { toast("请选择项目根目录"); return; }
                    final File projectDir = new File(projectPath);
                    if (!projectDir.exists() || !projectDir.isDirectory()) { toast("项目目录不存在：" + projectPath); return; }
                    final File srcDir = new File(projectDir, "src");
                    if (!srcDir.exists() || !srcDir.isDirectory()) { toast("项目根目录下没有 src：" + srcDir.getAbsolutePath()); return; }
                    if (restoreResourceNames.isChecked()) {
                        File resDir = new File(projectDir, "res");
                        if (!resDir.exists() || !resDir.isDirectory()) { toast("开启资源名还原时需要 res 目录：" + resDir.getAbsolutePath()); return; }
                    }
                    File apkLib = new File(new File(projectDir, "apk"), "lib");
                    if (DexReadableAlias.countDexContainers(apkLib) <= 0) { toast("项目 apk/lib 下没有找到 DEX/APK/ZIP/JAR"); return; }
                    final String baseName = projectDir.getName().length() == 0 ? "project" : projectDir.getName();
                    final JSONObject localTask = addLocalTask(baseName + "_dex_restore.zip", 8, "上传中", ad);
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        File packed = Api.prepareDexRestoreProjectZip(projectDir, restoreResourceNames.isChecked());
                        try {
                            JSONObject opt = new JSONObject();
                            opt.put("restore_props", restoreProps.isChecked());
                            opt.put("restore_events", restoreEvents.isChecked());
                            opt.put("rename_vars", renameVars.isChecked());
                            opt.put("rename_files", renameFiles.isChecked());
                            opt.put("rename_functions", renameFunctions.isChecked());
                            opt.put("restore_resource_names", restoreResourceNames.isChecked());
                            opt.put("dex_only", dexOnly.isChecked());
                            putDexRestoreClientPolicy(opt);
                            return api.uploadStaticDexSourceRestoreTask(packed, null, baseName, opt);
                        } finally {
                            try { packed.delete(); } catch(Exception e) {}
                        }
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }


        void showNumericSourceRestoreDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final CheckBox iactDynamic = md3FeatureSwitch("iACT 动态修复");
            final boolean antiIapecSelfDestructEntitled = hasExactFeature(FEATURE_ANTI_IAPEC_SELF_DESTRUCT);
            final CheckBox antiIapecSelfDestruct = md3FeatureSwitch("反iAPEC自毁");
            antiIapecSelfDestruct.setVisibility(antiIapecSelfDestructEntitled ? View.VISIBLE : View.GONE);
            antiIapecSelfDestruct.setEnabled(antiIapecSelfDestructEntitled);
            final EditText dexPath = edit("DEX/APK/ZIP/JAR 路径"); dexPath.setSingleLine(true);
            final EditText project = edit("项目路径"); project.setSingleLine(true);
            box.addView(iactDynamic, new LinearLayout.LayoutParams(-1, dp(40)));
            if (antiIapecSelfDestructEntitled) box.addView(antiIapecSelfDestruct, new LinearLayout.LayoutParams(-1, dp(40)));
            final TextView dexLabel = label("DEX 或包含 DEX 的安装包");
            box.addView(dexLabel); addM(box, dexPath, -1, dp(50), 0, 4,0,8);
            final Button pickDex = btn("浏览选择 DEX/APK", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, pickDex, -1, dp(46), 0, 0, 0, 8);
            box.addView(label("项目路径")); addM(box, project, -1, dp(50), 0, 4,0,8);
            final TextView tip = tv("动态修复同时支持 iApEcPro-数字(...) 与旧版随机数字命令表；上传 src/res 和 DEX/APK/ZIP/JAR。", 12, GRAY, 0);
            addM(box, tip, -1, -2, 0, 0, 0, 8);
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, openPerm, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 6);
            pickDex.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(dexPath, true); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});
            iactDynamic.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                int visibility = checked ? View.GONE : View.VISIBLE;
                dexLabel.setVisibility(visibility);
                dexPath.setVisibility(visibility);
                pickDex.setVisibility(visibility);
                tip.setText(checked
                    ? "iACT 动态解密上传 src，存在 res 时一并上传（不上传 DEX）"
                    : "普通动态修复同时还原 iAPEC 数字指令和旧版随机数字命令表；支持 DEX/APK/ZIP/JAR");
            }});

            final AlertDialog dlg = md3FeatureDialog("动态修复", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    if (!hasFeature(5)) { toast("功能不可用"); return; }
                    if (antiIapecSelfDestruct.isChecked() && !antiIapecSelfDestructEntitled) { antiIapecSelfDestruct.setChecked(false); toast("功能不可用"); return; }
                    final boolean useIact = iactDynamic.isChecked();
                    final File dexFile;
                    if (useIact) {
                        dexFile = null;
                    } else {
                        String dp = dexPath.getText().toString().trim();
                        if (dp.length()==0) { toast("请输入 DEX/APK/ZIP 路径"); return; }
                        dexFile = new File(dp);
                        if (!dexFile.exists() || !dexFile.isFile()) { toast("DEX/APK/ZIP 文件不存在"); return; }
                    }
                    final Api.DynamicRestoreProbe numericRestoreProbe;
                    if (dexFile != null) {
                        Api.DynamicRestoreProbe probe;
                        try { probe = Api.detectDynamicRestore(dexFile); }
                        catch(Exception e) { toast("动态类解析失败：" + (e.getMessage()==null?String.valueOf(e):e.getMessage())); return; }
                        numericRestoreProbe = probe;
                        // 自动解析成功或未命中都静默处理，不弹提示。
                    } else {
                        numericRestoreProbe = null;
                    }
                    Api.IapecProtectionProbe independentIapecProbe = null;
                    if (dexFile != null) {
                        try { independentIapecProbe = Api.detectIapecProtection(dexFile); } catch(Exception ignored) {}
                    }
                    if (independentIapecProbe != null && independentIapecProbe.selfDestruct
                            && antiIapecSelfDestructEntitled && !antiIapecSelfDestruct.isChecked()) {
                        antiIapecSelfDestruct.setChecked(true);
                    }
                    final Api.IapecProtectionProbe independentIapecProbeFinal = independentIapecProbe;
                    final boolean useAntiIapecSelfDestruct = antiIapecSelfDestruct.isChecked();
                    final String srcPath = normalizeSourcePath(project.getText().toString());
                    if (srcPath.length()==0) { toast("请输入项目路径"); return; }
                    final File srcDir = new File(srcPath);
                    if (!srcDir.exists() || !srcDir.isDirectory()) { toast("src 目录不存在：" + srcPath); return; }
                    final File projectDir = srcDir.getParentFile();
                    if (projectDir == null || !projectDir.exists() || !projectDir.isDirectory()) { toast("项目目录不存在"); return; }
                    final File resDir = new File(projectDir, "res");
                    final boolean includeRes = resDir.exists() && resDir.isDirectory();
                    final String baseName = projectDir.getName().length() == 0 ? "project" : projectDir.getName();
                    final JSONObject localTask = addLocalTask(baseName + (useIact ? "_iact.zip" : "_numeric.zip"), 5, "上传源码中", ad);
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        // 保留项目层级：ZIP 内必须是 src/**，存在 res 时同时携带 res/**。
                        File packed = Api.prepareSourceProjectZip(projectDir, includeRes);
                        try {
                            JSONObject options = new JSONObject();
                            options.put("iact_dynamic_decrypt", useIact);
                            options.put("skip_dex_upload", useIact);
                            options.put("no_dex_upload", useIact);
                            options.put("numeric_restore", true);
                            options.put("dynamic_restore", true);
                            options.put("iapec_numeric_dynamic_restore", true);
                            options.put("restore_fn_names", "on");
                            options.put("dynamic_restore_strategy", "iapec_numeric_dispatch+randomized_numeric_command_table");
                            options.put("anti_iapec_self_destruct", useAntiIapecSelfDestruct);
                            if (useAntiIapecSelfDestruct) {
                                options.put("anti_iapec_self_destruct_feature_id", FEATURE_ANTI_IAPEC_SELF_DESTRUCT);
                                options.put("anti_iapec_self_destruct_strategy", "libDestruction-profile+layout-semantics/control-type-backfill");
                                JSONArray requiredFeatures = new JSONArray();
                                requiredFeatures.put(5);
                                requiredFeatures.put(FEATURE_ANTI_IAPEC_SELF_DESTRUCT);
                                options.put("required_feature_ids", requiredFeatures);
                            }
                            if (numericRestoreProbe != null) {
                                options.put("dynamic_restore_detected", numericRestoreProbe.dynamicEncrypted);
                                options.put("dynamic_restore_detector_version", Api.DYNAMIC_RESTORE_DETECTOR_VERSION);
                                options.put("dynamic_restore_strategy", "iapec_numeric_dispatch+randomized_numeric_command_table");
                                options.put("dynamic_restore_dex_entry", numericRestoreProbe.dexEntry);
                                options.put("dynamic_restore_class", numericRestoreProbe.classDescriptor);
                                options.put("dynamic_class", numericRestoreProbe.classDescriptor);
                                options.put("numeric_restore_class", numericRestoreProbe.classDescriptor);
                                options.put("dynamic_restore_class_name", numericRestoreProbe.className);
                                options.put("dynamic_restore_class_code_units", numericRestoreProbe.codeUnits);
                                options.put("dynamic_restore_class_method_count", numericRestoreProbe.methodCount);
                                options.put("dynamic_restore_command_count", numericRestoreProbe.commandCount);
                                options.put("dynamic_restore_random_table", numericRestoreProbe.randomizedNumericTable);
                                options.put("dynamic_restore_baseline_table", numericRestoreProbe.baselineNumericTable);
                                options.put("dynamic_restore_table_pairs", numericRestoreProbe.numericTablePairs);
                                options.put("dynamic_restore_table_min", numericRestoreProbe.numericTableMin);
                                options.put("dynamic_restore_table_max", numericRestoreProbe.numericTableMax);
                                options.put("dynamic_restore_iapec_run_class", numericRestoreProbe.iapecRunClassPresent);
                                options.put("dynamic_restore_iapec_numeric_token_count", numericRestoreProbe.iapecNumericTokenCount);
                            }
                            if (independentIapecProbeFinal != null) {
                                options.put("iapec_dynamic_run_detected", independentIapecProbeFinal.dynamicEncrypted);
                                options.put("iapec_dynamic_run_class_present", independentIapecProbeFinal.runClassPresent);
                                options.put("iapec_dynamic_numeric_token_count", independentIapecProbeFinal.numericTokenCount);
                                options.put("anti_iapec_self_destruct_auto_detected", independentIapecProbeFinal.selfDestruct && useAntiIapecSelfDestruct);
                            }
                            return api.uploadNumericSourceRestoreTask(packed, dexFile, baseName, options);
                        } finally {
                            try { packed.delete(); } catch(Exception e) {}
                        }
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }

        void showNativeCompileSourceRestoreDialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final EditText dexPath = edit("DEX/APK/ZIP/JAR 路径"); dexPath.setSingleLine(true);
            final EditText project = edit("项目根目录或 src 目录"); project.setSingleLine(true);
            box.addView(label("包含原生编译代码的文件")); addM(box, dexPath, -1, dp(50), 0, 4,0,8);
            Button pickDex = btn("浏览选择 DEX/APK/ZIP/JAR", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, pickDex, -1, dp(46), 0, 0, 0, 8);
            box.addView(label("已解密项目路径")); addM(box, project, -1, dp(50), 0, 4,0,8);
            TextView tip = tv("独立扫描全部源码文件和 _unknown，将 DEX 中的事件/模块函数转成 V3 语法回填；存在 old_iapp_report.json 时会继续使用新版 V3 同款规则循环恢复文件名。", 12, GRAY, 0);
            addM(box, tip, -1, -2, 0, 0, 0, 8);
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            addM(box, openPerm, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 6);
            pickDex.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(dexPath, true); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});

            final AlertDialog dlg = md3FeatureDialog("原生编译修复", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    if (!hasFeature(FEATURE_NATIVE_COMPILE_RESTORE)) { toast("当前订阅不支持原生编译修复"); return; }
                    String dp = dexPath.getText().toString().trim();
                    if (dp.length()==0) { toast("请输入 DEX/APK/ZIP/JAR 路径"); return; }
                    final File dexFile = new File(dp);
                    if (!dexFile.exists() || !dexFile.isFile()) { toast("DEX/APK/ZIP/JAR 文件不存在"); return; }
                    final Api.NativeCompileProbe nativeProbe;
                    try { nativeProbe = Api.detectNativeCompile(dexFile); }
                    catch(Exception e) { toast("原生编译特征解析失败：" + (e.getMessage()==null?String.valueOf(e):e.getMessage())); return; }
                    final String selectedPath = normalizeProjectRootPath(project.getText().toString());
                    if (selectedPath.length()==0) { toast("请输入项目根目录或 src 目录"); return; }
                    File selectedDir = new File(selectedPath);
                    final File projectDir = "src".equalsIgnoreCase(selectedDir.getName()) && selectedDir.getParentFile() != null
                            ? selectedDir.getParentFile() : selectedDir;
                    if (!projectDir.exists() || !projectDir.isDirectory()) { toast("项目目录不存在：" + projectDir.getAbsolutePath()); return; }
                    final File srcDir = new File(projectDir, "src");
                    if (!srcDir.exists() || !srcDir.isDirectory()) { toast("项目根目录下没有 src：" + srcDir.getAbsolutePath()); return; }
                    final File resDir = new File(projectDir, "res");
                    final boolean includeRes = resDir.exists() && resDir.isDirectory();
                    final String baseName = projectDir.getName().length() == 0 ? "project" : projectDir.getName();
                    final JSONObject localTask = addLocalTask(baseName + "_native_compile.zip", FEATURE_NATIVE_COMPILE_RESTORE, "上传源码和DEX中", ad);
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        File packed = Api.prepareNativeCompileProjectZip(projectDir, includeRes);
                        try {
                            JSONObject options = new JSONObject();
                            options.put("native_compile_source_restore", true);
                            options.put("native_compile_restore", true);
                            options.put("native_compile_direct_v3_backfill", true);
                            options.put("native_compile_filename_fixpoint", true);
                            options.put("native_compile_all_text_files", true);
                            options.put("require_dex_upload", true);
                            options.put("native_compile_detected", nativeProbe.nativeCompiled);
                            options.put("native_compile_detector_version", Api.NATIVE_COMPILE_RESTORE_DETECTOR_VERSION);
                            options.put("native_compile_dex_entry", nativeProbe.dexEntry);
                            options.put("native_compile_event_method_count", nativeProbe.eventMethodNameCount);
                            options.put("native_compile_source_string_count", nativeProbe.sourceStringCount);
                            options.put("native_compile_reason", nativeProbe.reason);
                            options.put("native_compile_restore_strategy", "standalone/all-text-files/exact-token/v3-syntax+v3-filename-fixpoint");
                            return api.uploadNativeCompileSourceRestoreTask(packed, dexFile, baseName, options);
                        } finally {
                            try { packed.delete(); } catch(Exception e) {}
                        }
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }


        void showCreateTaskV6Dialog(final BaseAdapter ad) {
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4)); sv.addView(box);
            final EditText apk = edit("APK/DEX 路径"); apk.setSingleLine(true);
            box.addView(label("APK/DEX 路径")); addM(box, apk, -1, dp(50), 0, 4,0,8);
            TextView compactTip = tv("默认仅上传 DEX", 12, GRAY, 0);
            addM(box, compactTip, -1, -2, 0, 0, 0, 8);
            final TextView permTip = tv(storagePermissionStatus(), 12, GRAY, 0);
            Button pickApk = btn("浏览选择文件", Color.parseColor("#E2E8F0"), BLACK);
            Button openPerm = btn("开启/检查文件权限", Color.parseColor("#E2E8F0"), BLACK);
            LinearLayout fileBtns = hbox();
            addM(fileBtns, pickApk, 0, dp(46), 0, 0, 4, 0); ((LinearLayout.LayoutParams)pickApk.getLayoutParams()).weight = 1;
            addM(fileBtns, openPerm, 0, dp(46), 4, 0, 0, 0); ((LinearLayout.LayoutParams)openPerm.getLayoutParams()).weight = 1;
            addM(box, fileBtns, -1, dp(46), 0, 0, 0, 8);
            addM(box, permTip, -1, -2, 0, 0, 0, 12);
            pickApk.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showApkBrowser(apk, true); }});
            openPerm.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestPerms(); if (Build.VERSION.SDK_INT >= 30 && !hasAllFilesAccess()) openAllFilesAccessSettings(); permTip.setText(storagePermissionStatus()); }});
            final CheckBox noJava = md3FeatureSwitch("不恢复 Java 文件"); noJava.setChecked(false);
            box.addView(noJava, new LinearLayout.LayoutParams(-1, dp(40)));
            final CheckBox advanced = md3FeatureSwitch("高级分析解释层（尽量还原为iApp语句）"); advanced.setChecked(false);
            box.addView(advanced, new LinearLayout.LayoutParams(-1, dp(40)));
            final AlertDialog dlg = md3FeatureDialog("V6 反编译", sv).setNegativeButton("取消", null).setPositiveButton("开始", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    if (!ensureStorageReady()) return;
                    final String path = apk.getText().toString().trim();
                    if (path.length()==0) { toast("请输入路径"); return; }
                    final File f = new File(path);
                    if (!f.exists() || !f.isFile()) { toast("文件不存在"); return; }
                    if (!hasFeature(6)) { toast("当前订阅不支持 V6"); return; }
                    final JSONObject localTask = addLocalTask(f.getName(), 6, "上传文件中", ad);
                    dlg.dismiss();
                    submitTaskInBackground(localTask, ad, new Job(){ public Object run() throws Exception {
                        JSONObject opt = new JSONObject();
                        opt.put("v6_no_java", noJava.isChecked());
                        opt.put("v6_advanced_analysis", advanced.isChecked());
                        opt.put("v6_upload_mode", "dex_only");
                        checkWhitelistBeforeUpload(f, 6, opt);
                        return api.uploadTaskV6(f, opt);
                    }});
                }});
            }});
            showMd3FeatureDialogWindow(dlg);
        }


        String extractArchiveSignatureHex(File f) {
            if (f == null || !f.isFile()) return "";
            try {
                // GET_SIGNATURES 虽已弃用，但对旧 iApp 编译 SDK 和现代 APK
                // Signature Scheme v1/v2/v3 都有最好的兼容性，且不会引入 API 28
                // 的 SigningInfo 编译依赖。
                android.content.pm.PackageInfo pi = a.getPackageManager().getPackageArchiveInfo(
                        f.getAbsolutePath(), PackageManager.GET_SIGNATURES);
                if (pi != null && pi.signatures != null && pi.signatures.length > 0 && pi.signatures[0] != null) {
                    byte[] raw = pi.signatures[0].toByteArray();
                    if (raw != null && raw.length > 0) return Api.hex(raw);
                }
            } catch(Throwable ignored) {}
            return "";
        }

        String localPackageName(File f) {
            try {
                android.content.pm.PackageInfo pi = a.getPackageManager().getPackageArchiveInfo(f.getAbsolutePath(), 0);
                if (pi != null && pi.packageName != null && pi.packageName.length() > 0) return pi.packageName;
            } catch(Exception e) {}
            String n = f.getName();
            int dot = n.lastIndexOf('.');
            if(dot > 0) n = n.substring(0, dot);
            if(n.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")) return n;
            return "";
        }

        JSONObject localArchiveMeta(File f) {
            JSONObject o = new JSONObject();
            try {
                android.content.pm.PackageInfo pi = a.getPackageManager().getPackageArchiveInfo(f.getAbsolutePath(), PackageManager.GET_META_DATA);
                if (pi != null) {
                    if (pi.packageName != null && pi.packageName.length() > 0) {
                        o.put("package_name", pi.packageName);
                        o.put("package", pi.packageName);
                        o.put("pkg", pi.packageName);
                        o.put("packageName", pi.packageName);
                        o.put("client_package_name", pi.packageName);
                    }
                    if (pi.versionName != null && pi.versionName.length() > 0) o.put("version_name", pi.versionName);
                    try { o.put("version_code", String.valueOf(pi.versionCode)); } catch(Exception e) {}
                    try {
                        android.content.pm.ApplicationInfo ai = pi.applicationInfo;
                        if (ai != null) {
                            ai.sourceDir = f.getAbsolutePath();
                            ai.publicSourceDir = f.getAbsolutePath();
                            // 这里 loadLabel 会通过 APK 的 resources.arsc 解析 @string/app_name，避免直接读 AndroidManifest.xml 时出现资源ID或中文乱码。
                            CharSequence label = ai.loadLabel(a.getPackageManager());
                            if (label != null && label.length() > 0) {
                                String appLabel = String.valueOf(label);
                                o.put("app_name", appLabel);
                                o.put("client_app_name", appLabel);
                                o.put("label", appLabel);
                                o.put("client_app_name_source", "arsc_package_manager");
                            }
                        }
                    } catch(Exception e) {}
                }
            } catch(Exception e) {}
            return o;
        }

        String localFileSha256(File f) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InputStream is = new BufferedInputStream(new FileInputStream(f));
            try {
                byte[] buf = new byte[1024 * 1024];
                int n;
                while((n = is.read(buf)) > 0) md.update(buf, 0, n);
            } finally { try { is.close(); } catch(Exception e) {} }
            return Api.hex(md.digest());
        }

        void checkWhitelistBeforeUpload(File f, int featureId, JSONObject opt) throws Exception {
            String pkg = localPackageName(f);
            String sha = localFileSha256(f);
            JSONObject meta = localArchiveMeta(f);
            try {
                Iterator mk = meta.keys();
                while (mk.hasNext()) {
                    String k = String.valueOf(mk.next());
                    Object mv = meta.opt(k);
                    if (mv != null && String.valueOf(mv).trim().length() > 0) opt.put(k, mv);
                }
            } catch(Exception e) {}
            try {
                boolean sokeyEnum = Api.optBool(opt, "sokey_enum");
                boolean dexkeyEnum = Api.optBool(opt, "dexkey_enum");
                boolean disableDexkeyAuto = Api.optBool(opt, "disable_client_dexkey_auto");
                boolean dynamicDexkeyMode = "dynamic".equalsIgnoreCase(
                        opt.optString("client_dexkey_acquire_mode", "static"));

                // 方案2由客户端运行时解析器提前得到精确 DexKey；白名单预检不得再运行静态提取器。
                // sokey-only 在动态方法完成后再检查是否拿到 dexkey。
                boolean shouldExtractDexkey = !dynamicDexkeyMode
                        && !dexkeyEnum && (!disableDexkeyAuto || sokeyEnum);
                if (shouldExtractDexkey) {
                    String dk = Api.normalizeDexKeyNumber(Api.extractDexKeyFromApk(f));
                    if (dk != null && dk.trim().length() > 0) {
                        opt.put("dexkey", dk.trim());
                        opt.put("client_dexkey", dk.trim());
                        opt.put("client_fb_auto", dk.trim());
                        opt.remove("client_fb_dex_fallback");
                        if (!opt.has("fb") || opt.optString("fb", "").trim().length() == 0) opt.put("fb", dk.trim());
                    } else if (!opt.has("fb") || opt.optString("fb", "").trim().length() == 0) {
                        // No implicit DEX fallback. Enter dexkey manually or enable
                        // dexkey enumeration; DEX is reserved for dynamic restore.
                        opt.remove("client_fb_dex_fallback");
                        opt.put("client_dexkey_local_extract_failed", true);
                    }
                }

                if (dexkeyEnum || (disableDexkeyAuto && !sokeyEnum)) {
                    opt.remove("fb");
                    opt.remove("dexkey");
                    opt.remove("client_dexkey");
                    opt.remove("client_fb_auto");
                    opt.remove("fb_auto");
                }

                if (sokeyEnum) {
                    opt.remove("hidden");
                    if (!dexkeyEnum) {
                        String resolvedDexkey = opt.optString("fb", "").trim();
                        if (resolvedDexkey.length() == 0) resolvedDexkey = opt.optString("dexkey", "").trim();
                        if (resolvedDexkey.length() == 0) resolvedDexkey = opt.optString("client_dexkey", "").trim();
                        if (resolvedDexkey.length() == 0 && !Api.optBool(opt, "client_fb_dex_fallback")) {
                            if (dynamicDexkeyMode && !Api.optBool(opt, "client_dynamic_dexkey_attempted")) {
                                opt.put("client_sokey_enum_waiting_dynamic_dexkey", true);
                            } else {
                                throw new Exception("sokey枚举需要dex密钥，但当前 DexKey 获取方案未能取得有效结果；请切换方案、手动填写或同时开启dexkey枚举");
                            }
                        }
                    }
                }
            } catch(Exception e) {
                String msg = e == null ? "" : String.valueOf(e.getMessage());
                if (msg.indexOf("sokey枚举需要dex密钥") >= 0) throw e;
            }
            opt.put("package_name", pkg);
            opt.put("package", pkg);
            opt.put("pkg", pkg);
            opt.put("packageName", pkg);
            opt.put("client_package_name", pkg);
            opt.put("original_package_name", pkg);
            opt.put("code_hash", sha);
            opt.put("hash", sha);
            opt.put("sha256", sha);
            opt.put("apk_sha256", sha);
            opt.put("original_apk_sha256", sha);
            opt.put("client_apk_sha256", sha);
            opt.put("feature_id", featureId);
            JSONObject body = new JSONObject();
            body.put("package_name", pkg);
            body.put("package", pkg);
            body.put("pkg", pkg);
            body.put("packageName", pkg);
            body.put("code_hash", sha);
            body.put("hash", sha);
            body.put("sha256", sha);
            body.put("apk_sha256", sha);
            body.put("original_apk_sha256", sha);
            body.put("feature_id", featureId);
            body.put("filename", f.getName());
            JSONObject r = api.post("/whitelist/check", body);
            if(!r.optBoolean("allowed", true)) throw new Exception(r.optString("message", "白名单保护中，到期前禁止解密"));
        }

        TextView label(String s){ TextView t = tv(s, 13, BLACK, Typeface.BOLD); t.setPadding(0, dp(6), 0, dp(4)); return t; }
        CheckBox check(String s){ CheckBox c = new CheckBox(a); c.setText(s); c.setTextColor(BLACK); c.setTextSize(14); return c; }
        void addSwitch(LinearLayout box, final CheckBox c, final EditText e){
            box.addView(c, new LinearLayout.LayoutParams(-1, dp(40))); addM(box, e, -1, dp(50), 0, 2,0,8);
            c.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){ e.setVisibility(checked?View.VISIBLE:View.GONE); }});
        }

        void showDirectoryBrowser(final EditText target) {
            if (!ensureStorageReady()) return;
            File start = Environment.getExternalStorageDirectory();
            try {
                String p = target.getText().toString().trim();
                if (p.length() > 0) {
                    File f = new File(p);
                    if (f.isDirectory()) start = f;
                    else if (f.getParentFile() != null) start = f.getParentFile();
                }
            } catch(Exception ignored) {}
            final File[] cur = new File[]{start};
            final ArrayList<File> dirs = new ArrayList<File>();
            LinearLayout panel = vbox();
            panel.setPadding(dp(22), dp(22), dp(22), dp(18));
            panel.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 28));
            panel.addView(tv("选择项目目录", 23, TEXT_MAIN, Typeface.BOLD), new LinearLayout.LayoutParams(-1, -2));
            final TextView pathView = tv("", 12, TEXT_SUB, 0);
            pathView.setSingleLine(true);
            pathView.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
            LinearLayout pathCard = hbox();
            pathCard.setPadding(dp(14), dp(12), dp(14), dp(12));
            pathCard.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));
            pathCard.addView(pathView, new LinearLayout.LayoutParams(0, -2, 1));
            LinearLayout.LayoutParams pathLp = new LinearLayout.LayoutParams(-1, -2); pathLp.topMargin = dp(16); panel.addView(pathCard, pathLp);
            Button up = btn("上一级目录", MD3_PRIMARY_CONTAINER, MD3_ON_PRIMARY_CONTAINER);
            LinearLayout.LayoutParams upLp = new LinearLayout.LayoutParams(-1, dp(48)); upLp.topMargin = dp(10); panel.addView(up, upLp);
            final ListView list = new ListView(a);
            list.setDivider(null); list.setDividerHeight(0); list.setSelector(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
            list.setBackground(bg(MD3_SURFACE, 18)); list.setPadding(dp(6), dp(6), dp(6), dp(6));
            int listHeight = Math.min(dp(430), (int)(a.getResources().getDisplayMetrics().heightPixels * 0.50f));
            LinearLayout.LayoutParams listLp = new LinearLayout.LayoutParams(-1, listHeight); listLp.topMargin = dp(12); panel.addView(list, listLp);
            LinearLayout action = hbox(); action.setGravity(Gravity.RIGHT);
            Button choose = btn("选择当前目录", MD3_PRIMARY, Color.WHITE);
            Button close = btn("关闭", MD3_PRIMARY_CONTAINER, MD3_ON_PRIMARY_CONTAINER);
            action.addView(close, new LinearLayout.LayoutParams(dp(100), dp(48)));
            LinearLayout.LayoutParams chooseLp = new LinearLayout.LayoutParams(dp(150), dp(48)); chooseLp.leftMargin = dp(10); action.addView(choose, chooseLp);
            LinearLayout.LayoutParams actionLp = new LinearLayout.LayoutParams(-1, dp(48)); actionLp.topMargin = dp(14); panel.addView(action, actionLp);
            final BaseAdapter adapter = new BaseAdapter(){
                public int getCount(){ return dirs.size(); }
                public Object getItem(int i){ return dirs.get(i); }
                public long getItemId(int i){ return i; }
                public View getView(int i, View convertView, ViewGroup parent){
                    File f = dirs.get(i);
                    LinearLayout row = hbox(); row.setPadding(dp(12), dp(13), dp(12), dp(13)); row.setBackground(bg(MD3_SURFACE_CONTAINER_LOW, 15));
                    row.addView(textAvatar("夹", MD3_PRIMARY, 14, 13), new LinearLayout.LayoutParams(dp(46), dp(46)));
                    TextView n = tv(f.getName().length()==0?f.getAbsolutePath():f.getName(), 15, TEXT_MAIN, Typeface.BOLD);
                    n.setSingleLine(true); n.setEllipsize(android.text.TextUtils.TruncateAt.END);
                    LinearLayout.LayoutParams nlp = new LinearLayout.LayoutParams(0, -2, 1); nlp.leftMargin = dp(12); row.addView(n, nlp);
                    row.addView(tv("›", 22, MD3_PRIMARY, Typeface.BOLD), new LinearLayout.LayoutParams(-2, -2));
                    addClickAnim(row); return row;
                }
            };
            list.setAdapter(adapter);
            final Runnable refresh = new Runnable(){ public void run(){
                pathView.setText(cur[0].getAbsolutePath()); dirs.clear();
                File[] arr = null; try { arr = cur[0].listFiles(); } catch(Exception ignored) {}
                if (arr != null) {
                    Arrays.sort(arr, new Comparator<File>(){ public int compare(File x, File y){ return x.getName().compareToIgnoreCase(y.getName()); }});
                    for (File f : arr) if (f != null && f.isDirectory() && !f.getName().startsWith(".")) dirs.add(f);
                }
                adapter.notifyDataSetChanged();
            }};
            final AlertDialog dialog = new AlertDialog.Builder(a).create();
            up.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ File p = cur[0].getParentFile(); if (p != null && p.canRead()) { cur[0]=p; refresh.run(); } else toast("已经到顶层目录"); }});
            list.setOnItemClickListener(new AdapterView.OnItemClickListener(){ public void onItemClick(AdapterView<?> parent, View view, int position, long id){ cur[0]=dirs.get(position); refresh.run(); }});
            choose.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ target.setText(cur[0].getAbsolutePath()); target.setSelection(target.getText().length()); dialog.dismiss(); toast("已选择项目目录"); }});
            close.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ dialog.dismiss(); }});
            dialog.setCancelable(true); dialog.show();
            try {
                android.view.Window window = dialog.getWindow();
                if (window != null) {
                    window.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT));
                    window.setContentView(panel); window.addFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND);
                    android.view.WindowManager.LayoutParams attrs = window.getAttributes(); attrs.dimAmount=0.58f; window.setAttributes(attrs);
                    window.setLayout((int)(a.getResources().getDisplayMetrics().widthPixels*0.92f), ViewGroup.LayoutParams.WRAP_CONTENT);
                }
            } catch(Exception ignored) {}
            refresh.run();
        }

        void showApkBrowser(final EditText target) { showApkBrowser(target, false); }
        void showApkBrowser(final EditText target, final boolean allowDex) {
            if (!ensureStorageReady()) return;
            File start = Environment.getExternalStorageDirectory();
            try {
                String p = target.getText().toString().trim();
                if (p.length() > 0) {
                    File f = new File(p);
                    if (f.isFile() && f.getParentFile() != null) start = f.getParentFile();
                    else if (f.isDirectory()) start = f;
                }
            } catch(Exception e) {}
            showFileBrowser(start, target, allowDex);
        }

        void showFileBrowser(
                File startDir,
                final EditText target,
                final boolean allowDex) {
            final File[] cur = new File[]{
                    startDir == null
                            ? Environment.getExternalStorageDirectory()
                            : startDir
            };
            final ArrayList<File> items = new ArrayList<File>();

            LinearLayout panel = vbox();
            panel.setPadding(dp(22), dp(22), dp(22), dp(18));
            panel.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 28));

            TextView title = tv(
                    allowDex ? "选择文件" : "选择 APK 文件",
                    23,
                    TEXT_MAIN,
                    Typeface.BOLD);
            panel.addView(title, new LinearLayout.LayoutParams(-1, -2));

            TextView support = tv(
                    allowDex
                            ? "支持 APK / APKS / DEX / ZIP / JAR / SO"
                            : "仅显示 APK / APKS 文件",
                    13,
                    MD3_PRIMARY,
                    Typeface.BOLD);
            LinearLayout.LayoutParams supportLp =
                    new LinearLayout.LayoutParams(-1, -2);
            supportLp.topMargin = dp(5);
            panel.addView(support, supportLp);

            LinearLayout pathCard = hbox();
            pathCard.setPadding(dp(14), dp(12), dp(14), dp(12));
            pathCard.setBackground(bg(MD3_PRIMARY_CONTAINER, 16));

            final TextView pathView = tv("", 12, TEXT_SUB, 0);
            pathView.setSingleLine(true);
            pathView.setEllipsize(
                    android.text.TextUtils.TruncateAt.MIDDLE);
            pathCard.addView(
                    pathView,
                    new LinearLayout.LayoutParams(0, -2, 1));

            final ProgressBar browserLoading = new ProgressBar(a);
            browserLoading.setVisibility(View.GONE);
            LinearLayout.LayoutParams loadingLp =
                    new LinearLayout.LayoutParams(dp(24), dp(24));
            loadingLp.leftMargin = dp(8);
            pathCard.addView(browserLoading, loadingLp);

            LinearLayout.LayoutParams pathLp =
                    new LinearLayout.LayoutParams(-1, -2);
            pathLp.topMargin = dp(16);
            panel.addView(pathCard, pathLp);

            Button up = btn(
                    "上一级目录",
                    MD3_PRIMARY_CONTAINER,
                    MD3_ON_PRIMARY_CONTAINER);
            LinearLayout.LayoutParams upLp =
                    new LinearLayout.LayoutParams(-1, dp(48));
            upLp.topMargin = dp(10);
            panel.addView(up, upLp);

            final ListView list = new ListView(a);
            list.setDivider(null);
            list.setDividerHeight(0);
            list.setSelector(
                    new android.graphics.drawable.ColorDrawable(
                            Color.TRANSPARENT));
            list.setBackground(bg(MD3_SURFACE, 18));
            list.setClipToPadding(false);
            list.setPadding(dp(6), dp(6), dp(6), dp(6));

            int listHeight = Math.min(
                    dp(430),
                    (int)(a.getResources()
                            .getDisplayMetrics().heightPixels * 0.50f));
            LinearLayout.LayoutParams listLp =
                    new LinearLayout.LayoutParams(-1, listHeight);
            listLp.topMargin = dp(12);
            panel.addView(list, listLp);

            Button close = btn(
                    "关闭",
                    MD3_PRIMARY_CONTAINER,
                    MD3_ON_PRIMARY_CONTAINER);
            LinearLayout closeRow = hbox();
            closeRow.setGravity(Gravity.RIGHT);
            closeRow.addView(
                    close,
                    new LinearLayout.LayoutParams(dp(108), dp(48)));

            LinearLayout.LayoutParams closeLp =
                    new LinearLayout.LayoutParams(-1, dp(48));
            closeLp.topMargin = dp(14);
            panel.addView(closeRow, closeLp);

            final BaseAdapter adapter = new BaseAdapter() {
                public int getCount(){ return items.size(); }
                public Object getItem(int i){ return items.get(i); }
                public long getItemId(int i){ return i; }

                public View getView(
                        int i,
                        View convertView,
                        ViewGroup parent) {
                    File file = items.get(i);

                    LinearLayout holder = vbox();
                    holder.setPadding(dp(4), dp(4), dp(4), dp(4));

                    LinearLayout row = hbox();
                    row.setPadding(dp(12), dp(11), dp(12), dp(11));
                    row.setBackground(
                            bg(MD3_SURFACE_CONTAINER_LOW, 15));

                    String fileName = file.getName();
                    if (fileName.length() == 0) {
                        fileName = file.getAbsolutePath();
                    }

                    String badge = "夹";
                    int badgeColor = MD3_PRIMARY;
                    if (!file.isDirectory()) {
                        String lower =
                                fileName.toLowerCase(Locale.US);
                        if (lower.endsWith(".apk") ||
                                lower.endsWith(".apks")) {
                            badge = "APK";
                            badgeColor = MD3_PRIMARY;
                        } else if (lower.endsWith(".dex")) {
                            badge = "DEX";
                            badgeColor = Color.parseColor("#0369A1");
                        } else if (lower.endsWith(".zip")) {
                            badge = "ZIP";
                            badgeColor = Color.parseColor("#0F766E");
                        } else if (lower.endsWith(".jar")) {
                            badge = "JAR";
                            badgeColor = Color.parseColor("#A16207");
                        } else if (lower.endsWith(".so")) {
                            badge = "SO";
                            badgeColor = Color.parseColor("#C2410C");
                        } else {
                            badge = "文件";
                            badgeColor = TEXT_SUB;
                        }
                    }

                    TextView icon = textAvatar(
                            badge,
                            badgeColor,
                            badge.length() > 2 ? 10 : 14,
                            13);
                    row.addView(
                            icon,
                            new LinearLayout.LayoutParams(dp(46), dp(46)));

                    LinearLayout textBox = vbox();
                    TextView nameView = tv(
                            fileName,
                            15,
                            TEXT_MAIN,
                            Typeface.BOLD);
                    nameView.setSingleLine(true);
                    nameView.setEllipsize(
                            android.text.TextUtils.TruncateAt.END);
                    textBox.addView(
                            nameView,
                            new LinearLayout.LayoutParams(-1, -2));

                    String detail = file.isDirectory()
                            ? "文件夹"
                            : String.format(
                                    Locale.US,
                                    "%.2f MB",
                                    file.length() / 1024.0 / 1024.0);
                    TextView detailView = tv(
                            detail,
                            12,
                            TEXT_SUB,
                            0);
                    LinearLayout.LayoutParams detailLp =
                            new LinearLayout.LayoutParams(-1, -2);
                    detailLp.topMargin = dp(4);
                    textBox.addView(detailView, detailLp);

                    LinearLayout.LayoutParams textLp =
                            new LinearLayout.LayoutParams(0, -2, 1);
                    textLp.leftMargin = dp(12);
                    row.addView(textBox, textLp);

                    TextView arrow = tv(
                            file.isDirectory() ? "›" : "选择",
                            file.isDirectory() ? 22 : 12,
                            MD3_PRIMARY,
                            Typeface.BOLD);
                    arrow.setGravity(Gravity.CENTER);
                    row.addView(
                            arrow,
                            new LinearLayout.LayoutParams(-2, -2));

                    addClickAnim(row);
                    holder.addView(
                            row,
                            new LinearLayout.LayoutParams(-1, -2));
                    return holder;
                }
            };
            list.setAdapter(adapter);

            final Runnable[] refresh = new Runnable[1];
            final long[] browserRefreshSeq = new long[]{0L};

            refresh[0] = new Runnable() {
                public void run() {
                    final long seq = ++browserRefreshSeq[0];
                    final File dir0 = cur[0] == null
                            ? Environment.getExternalStorageDirectory()
                            : cur[0];

                    pathView.setText(dir0.getAbsolutePath());
                    browserLoading.setVisibility(View.VISIBLE);
                    items.clear();
                    adapter.notifyDataSetChanged();

                    new Thread(new Runnable() {
                        public void run() {
                            final ArrayList<File> found =
                                    new ArrayList<File>();
                            File[] files = null;
                            try {
                                files = dir0.listFiles();
                            } catch(Exception ignored) {}

                            if (files != null) {
                                Arrays.sort(
                                        files,
                                        new Comparator<File>() {
                                    public int compare(File left, File right) {
                                        if (left.isDirectory() !=
                                                right.isDirectory()) {
                                            return left.isDirectory()
                                                    ? -1
                                                    : 1;
                                        }
                                        return left.getName()
                                                .compareToIgnoreCase(
                                                        right.getName());
                                    }
                                });

                                for (int i = 0; i < files.length; i++) {
                                    File file = files[i];
                                    String fileName = file.getName();

                                    if (file.isDirectory()) {
                                        if (!fileName.startsWith(".")) {
                                            found.add(file);
                                        }
                                    } else {
                                        String lower =
                                                fileName.toLowerCase(
                                                        Locale.US);
                                        boolean supported =
                                                lower.endsWith(".apk") ||
                                                lower.endsWith(".apks") ||
                                                (allowDex &&
                                                    (lower.endsWith(".dex") ||
                                                     lower.endsWith(".zip") ||
                                                     lower.endsWith(".jar") ||
                                                     lower.endsWith(".so")));
                                        if (supported) found.add(file);
                                    }
                                }
                            }

                            a.runOnUiThread(new Runnable() {
                                public void run() {
                                    if (seq != browserRefreshSeq[0]) return;
                                    if (cur[0] == null ||
                                            !dir0.getAbsolutePath().equals(
                                                    cur[0].getAbsolutePath())) {
                                        return;
                                    }

                                    browserLoading.setVisibility(View.GONE);
                                    items.clear();
                                    items.addAll(found);
                                    adapter.notifyDataSetChanged();

                                    if (items.size() == 0) {
                                        toast(
                                                allowDex
                                                        ? "当前目录没有支持的文件"
                                                        : "当前目录没有 APK");
                                    }
                                }
                            });
                        }
                    }).start();
                }
            };

            final AlertDialog[] dlgRef = new AlertDialog[1];

            up.setOnClickListener(new View.OnClickListener() {
                public void onClick(View view) {
                    resetClickAnimTree(view);
                    File parent = cur[0] == null
                            ? null
                            : cur[0].getParentFile();
                    if (parent != null && parent.canRead()) {
                        cur[0] = parent;
                        refresh[0].run();
                    } else {
                        toast("已经到顶层目录");
                    }
                }
            });

            list.setOnItemClickListener(
                    new AdapterView.OnItemClickListener() {
                public void onItemClick(
                        AdapterView<?> parent,
                        View view,
                        int position,
                        long id) {
                    resetClickAnimTree(view);
                    File file = items.get(position);

                    if (file.isDirectory()) {
                        cur[0] = file;
                        refresh[0].run();
                    } else {
                        if (dlgRef[0] != null) {
                            dlgRef[0].dismiss();
                        }
                        target.setText(file.getAbsolutePath());
                        target.setSelection(target.getText().length());
                        toast("已选择文件");
                    }
                }
            });

            final AlertDialog dialog =
                    new AlertDialog.Builder(a).create();
            dlgRef[0] = dialog;

            close.setOnClickListener(new View.OnClickListener() {
                public void onClick(View view) {
                    resetClickAnimTree(view);
                    dialog.dismiss();
                }
            });

            dialog.setCancelable(true);
            dialog.show();

            try {
                android.view.Window window = dialog.getWindow();
                if (window != null) {
                    window.setBackgroundDrawable(
                            new android.graphics.drawable.ColorDrawable(
                                    Color.TRANSPARENT));
                    window.setContentView(panel);
                    window.addFlags(
                            android.view.WindowManager.LayoutParams
                                    .FLAG_DIM_BEHIND);

                    android.view.WindowManager.LayoutParams attrs =
                            window.getAttributes();
                    attrs.dimAmount = 0.58f;
                    window.setAttributes(attrs);

                    window.setLayout(
                            (int)(a.getResources()
                                    .getDisplayMetrics().widthPixels * 0.92f),
                            ViewGroup.LayoutParams.WRAP_CONTENT);
                }
            } catch(Exception ignored) {}

            refresh[0].run();
        }

        void openTaskDetail(final JSONObject task0) {
            if (task0 == null) return;

            final int id = task0.optInt("id", 0);
            JSONObject initial = null;

            if (id > 0) {
                initial = cacheGet("task_detail_" + id, 0);
            }
            if (initial == null) {
                try {
                    initial = new JSONObject();
                    initial.put("task", new JSONObject(task0.toString()));
                } catch(Exception e) {
                    initial = new JSONObject();
                }
            }

            final AlertDialog immediateDialog =
                    showTaskDetailDialog(initial);
            if (id <= 0) return;

            final boolean[] replacing = new boolean[]{false};
            final boolean[] userClosed = new boolean[]{false};

            if (immediateDialog != null) {
                immediateDialog.setOnDismissListener(
                        new DialogInterface.OnDismissListener() {
                    public void onDismiss(DialogInterface dialog) {
                        if (!replacing[0]) userClosed[0] = true;
                    }
                });
            }

            new Thread(new Runnable() {
                public void run() {
                    try {
                        final JSONObject latest =
                                api.getFast("/tasks/" + id);
                        final JSONObject latestTask =
                                taskFromDetail(latest);
                        if (latestTask != null) {
                            normalizeKnownAncientTask(latestTask);
                        }
                        cachePut("task_detail_" + id, latest);

                        a.runOnUiThread(new Runnable() {
                            public void run() {
                                if (userClosed[0]) return;
                                replacing[0] = true;
                                try {
                                    if (immediateDialog != null &&
                                            immediateDialog.isShowing()) {
                                        immediateDialog.dismiss();
                                    }
                                } catch(Exception ignored) {}
                                showTaskDetailDialog(latest);
                                replacing[0] = false;
                            }
                        });
                    } catch(final Exception e) {
                        a.runOnUiThread(new Runnable() {
                            public void run() {
                                if (!userClosed[0]) {
                                    toast("详情刷新失败，已显示当前任务信息");
                                }
                            }
                        });
                    }
                }
            }).start();
        }


        AlertDialog.Builder md3TaskDetailDialog(
                String titleText, View contentView) {
            LinearLayout panel = vbox();
            panel.setTag("iapt_md3_task_detail_panel");
            panel.setPadding(dp(24), dp(24), dp(24), dp(18));
            panel.setBackground(bg(MD3_SURFACE_CONTAINER_HIGH, 24));

            TextView title = tv(
                    titleText == null ? "任务详情" : titleText,
                    20,
                    TEXT_MAIN,
                    Typeface.BOLD);
            panel.addView(title, new LinearLayout.LayoutParams(-1, -2));

            LinearLayout.LayoutParams contentLp =
                    new LinearLayout.LayoutParams(-1, -2);
            contentLp.topMargin = dp(18);
            panel.addView(contentView, contentLp);

            return new AlertDialog.Builder(a).setView(panel);
        }

        void styleMd3TaskDetailWindow(AlertDialog dialog) {
            try {
                if (dialog == null || dialog.getWindow() == null) return;

                android.view.Window window = dialog.getWindow();
                window.setBackgroundDrawable(
                        bg(MD3_SURFACE_CONTAINER_HIGH, 24));
                window.setLayout(
                        (int)(a.getResources()
                                .getDisplayMetrics().widthPixels * 0.92f),
                        ViewGroup.LayoutParams.WRAP_CONTENT);

                Button close = dialog.getButton(
                        AlertDialog.BUTTON_NEGATIVE);
                if (close != null) {
                    close.setText("关闭");
                    close.setAllCaps(false);
                    close.setTextColor(MD3_PRIMARY);
                    close.setTextSize(15);
                    close.setTypeface(
                            Typeface.create(
                                    "sans-serif-medium",
                                    Typeface.BOLD));
                    close.setBackground(
                            new android.graphics.drawable.ColorDrawable(
                                    Color.TRANSPARENT));
                    close.setStateListAnimator(null);

                    if (close.getParent() instanceof ViewGroup) {
                        ((ViewGroup)close.getParent())
                                .setBackgroundColor(Color.TRANSPARENT);
                    }
                }
            } catch(Exception ignored) {}
        }

        AlertDialog showTaskDetailDialog(final JSONObject detail) {
            final JSONObject t = detail.optJSONObject("task");
            if (t == null) { toast("任务详情为空"); return null; }
            normalizeKnownAncientTask(t);
            final boolean whitelistProtected = isWhitelistProtectedTask(t, detail);
            LinearLayout box = vbox();
            box.setPadding(dp(2), dp(4), dp(2), dp(2));
            box.setBackgroundColor(Color.TRANSPARENT);
            int fc = whitelistProtected ? 0 : completedDetailFileCount(detail); double sec = taskTotalMs(t, detail)/1000.0;
            String _taskStatusRaw = whitelistProtected
                    ? "whitelist_protected"
                    : t.optString("status", "").trim().toLowerCase(Locale.US);
            if ("failed".equals(_taskStatusRaw) && fc > 0) {
                try { t.put("status", "running"); t.put("error_text", ""); } catch(Exception ignored) {}
                _taskStatusRaw = "running";
            }
            final String taskStatus = _taskStatusRaw;
            String statusText = taskStatus.length()==0 ? "未知" : taskStatus;
            if ("whitelist_protected".equals(taskStatus)) statusText = "白名单保护";
            else if ("queued".equals(taskStatus)) statusText = "排队中";
            else if ("running".equals(taskStatus)) statusText = "解密中";
            else if ("done".equals(taskStatus)) statusText = "已完成";
            else if ("failed".equals(taskStatus)) statusText = "失败";
            else if ("cancelled".equals(taskStatus)) statusText = "已停止";
            String uploadCost = quotaText(detail, "upload_quota_cost", quotaText(detail, "resource_quota_cost", "0"));
            String decryptCost = quotaText(detail, "decrypt_quota_cost", quotaText(detail, "decrypt_quota_deducted", "0"));
            String downloadCost = quotaText(detail, "download_quota_deducted", "0");
            String totalCost = quotaText(detail, "total_quota_deducted", "0");
            String pendingDownload = quotaText(detail, "download_quota_pending", quotaText(detail, "download_quota_cost", "0"));
            String line = "状态："+statusText+"\n输出文件数："+fc+" 个文件\n总耗时："+String.format(Locale.US,"%.2f",sec)+" 秒\n上传扣费："+uploadCost+"\n解密扣费："+decryptCost+"\n下载扣费："+downloadCost+"\n总扣费："+totalCost;
            if (!"0".equals(pendingDownload) && !"0.00".equals(pendingDownload)) line += "\n下载还需：" + pendingDownload;
            boolean showDecryptDetails = !whitelistProtected && shouldShowV3DecryptDetails(t, detail);
            String decryptSummary = showDecryptDetails ? formatDecryptSummary(detail, t) : "";
            if (showDecryptDetails && decryptSummary.length() == 0 && isKnownAncientTask(t)) {
                if ("running".equals(taskStatus) && fc > 0) decryptSummary = "远古解密已写出文件，正在提交最终报告。";
                else if ("done".equals(taskStatus)) decryptSummary = "远古解密已完成；服务端未返回详细报告摘要。";
            }
            String projectMeta = showDecryptDetails ? formatProjectMeta(t) : "";
            String mergedSummary = decryptSummary;
            if (projectMeta.length() > 0) {
                mergedSummary = mergedSummary.length() > 0 ? (mergedSummary + "\n" + projectMeta) : projectMeta;
            }
            if (whitelistProtected) {
                line += "\n\n保护结果：白名单保护";
            } else if (showDecryptDetails && mergedSummary.length() > 0) {
                line += "\n\n解密情况：\n" + mergedSummary;
            }
            TextView info = tv(line, 14, BLACK, 0); info.setPadding(0,0,0,dp(16)); box.addView(info);
            Button search = btn(
                    "搜索文件名",
                    MD3_PRIMARY_CONTAINER,
                    MD3_ON_PRIMARY_CONTAINER);
            Button down = btn("下载 ZIP", BLUE, Color.WHITE);
            final Button stop = btn("停止解密", Color.parseColor("#FFF0F3"), Color.parseColor("#FF3B72"));
            if (!whitelistProtected) {
                addM(box, search, -1, dp(48),0,0,0,10);
                addM(box, down, -1, dp(48),0,0,0,0);
            }
            if ("queued".equals(taskStatus) || "running".equals(taskStatus)) addM(box, stop, -1, dp(48),0,10,0,0);
            
            final AlertDialog dlg = md3TaskDetailDialog(
                    safe(t.optString("apk_name", "任务详情")),
                    box)
                    .setNegativeButton("关闭", null)
                    .create();
            if (!whitelistProtected) {
                search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showSearchDialog(t.optInt("id",0)); }});
                down.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ downloadZip(t); }});
            }
            stop.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                new AlertDialog.Builder(a)
                    .setTitle("停止解密")
                    .setMessage("确定停止这个任务？已生成的临时文件会保留，但任务不会继续运行。")
                    .setNegativeButton("取消", null)
                    .setPositiveButton("停止", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                        async("正在停止解密...", new Job(){ public Object run() throws Exception {
                            return api.post("/task-control/"+t.optInt("id",0)+"/stop", new JSONObject());
                        }}, new Done(){ public void ok(Object o){
                            JSONObject r=(JSONObject)o;
                            toast(r.optString("message", "已停止"));
                            cacheDrop("task_detail_" + t.optInt("id",0));
                            cacheDrop("tasks");
                            dlg.dismiss();
                            showTasks();
                        }});
                    }})
                    .show();
            }});
            
            dlg.show();
            styleMd3TaskDetailWindow(dlg);
            return dlg;
        }

        JSONObject projectMetaObject(JSONObject t) {
            try {
                JSONObject pm = t.optJSONObject("project_meta");
                if (pm != null) return pm;
                String raw = t.optString("project_meta_json", "");
                if (raw != null && raw.trim().length() > 0 && !"null".equalsIgnoreCase(raw.trim())) return new JSONObject(raw);
            } catch(Exception e) {}
            return null;
        }

        String projectMetaString(JSONObject pm, String... keys) {
            if (pm == null || keys == null) return "";
            for (int i=0; i<keys.length; i++) {
                try {
                    String k = keys[i];
                    if (k == null || !pm.has(k) || pm.isNull(k)) continue;
                    String v = String.valueOf(pm.opt(k)).trim();
                    if (v.length() == 0 || "null".equalsIgnoreCase(v) || "none".equalsIgnoreCase(v)
                            || "unknown".equalsIgnoreCase(v) || "未知".equals(v) || "未识别".equals(v)) continue;
                    return v;
                } catch(Exception ignored) {}
            }
            return "";
        }

        long projectMetaTimestampMs(JSONObject pm) {
            String raw = projectMetaString(pm,
                    "build_timestamp_ms", "buildTimestampMs", "build_timestamp", "buildTimestamp",
                    "pack_timestamp", "packTimestamp", "pack_time", "packTime",
                    "compile_timestamp", "compileTimestamp", "timestamp", "打包时间戳");
            if (raw.length() == 0) return 0L;
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d{10,13})").matcher(raw);
                if (!m.find()) return 0L;
                long ts = Long.parseLong(m.group(1));
                if (ts > 0L && ts < 100000000000L) ts *= 1000L;
                return ts;
            } catch(Exception ignored) { return 0L; }
        }

        String formatProjectMeta(JSONObject t) {
            try {
                JSONObject pm = projectMetaObject(t);
                if (pm == null) return "";
                StringBuilder sb = new StringBuilder();

                String packerId = projectMetaString(pm,
                        "packer_id", "packerId", "pack_id", "packId", "builder_id", "builderId",
                        "builder_uid", "builderUid", "user_id", "userId", "uid", "owner_id", "ownerId",
                        "owner", "ownerInfo", "packer", "builder", "author", "creator", "maker", "producer", "account",
                        "author_id", "authorId", "iapp_uid", "iappUid", "打包者ID", "打包ID", "打包者", "所有者");
                String uuid = projectMetaString(pm,
                        "uuid", "device_uuid", "deviceUuid", "deviceUUID", "machine_uuid", "machineUuid",
                        "device_id", "deviceId", "device_uid", "deviceUid", "android_id", "androidId", "machine_id", "machineId",
                        "device_code", "deviceCode", "machine_code", "machineCode", "hardware_id", "hardwareId", "terminal_id", "terminalId",
                        "设备UUID", "手机UUID", "机器码", "设备码", "设备编号");
                String model = projectMetaString(pm,
                        "device_model", "deviceModel", "phone_model", "phoneModel", "product_model",
                        "productModel", "brand_model", "brandModel", "model", "device", "phone", "product", "buildModel", "androidModel", "Build.MODEL",
                        "ro.product.model", "设备型号", "手机型号", "打包机型", "设备机型", "机型", "设备", "手机");

                boolean decrypted = pm.optBoolean("project_decrypted", false)
                        || pm.has("project_file") || pm.has("build_timestamp_ms") || pm.has("build_timestamp");

                if (packerId.length() > 0) sb.append("打包 ID：").append(packerId).append("\n");
                else if (decrypted) sb.append("打包 ID：未识别\n");

                if (uuid.length() > 0) sb.append("UUID：").append(uuid).append("\n");
                else if (decrypted) sb.append("UUID：未识别\n");

                if (model.length() > 0) sb.append("打包机型：").append(model).append("\n");
                else if (decrypted) sb.append("打包机型：未识别\n");

                long tsMs = projectMetaTimestampMs(pm);
                if (tsMs > 0L) sb.append("打包毫秒时间戳：").append(tsMs).append("\n");

                String buildTime = projectMetaString(pm,
                        "build_time", "buildTime", "pack_time_text", "packTimeText",
                        "compile_time", "compileTime", "打包时间", "编译时间");
                if (buildTime.length() > 0) sb.append("打包时间：").append(buildTime).append("\n");

                if (sb.length() == 0 && decrypted) sb.append("包名.project：已解密，但未识别到标准字段\n");
                return sb.toString().trim();
            } catch(Exception e) { return ""; }
        }


        double taskTotalMs(JSONObject t, JSONObject detail) {
            try {
                double v = t == null ? 0.0 : t.optDouble("total_ms", 0.0);
                if (v > 0.0) return v;
                if (detail != null) {
                    v = detail.optDouble("total_ms", 0.0);
                    if (v <= 0.0) v = detail.optDouble("elapsed_ms", 0.0);
                    if (v <= 0.0) v = detail.optDouble("duration_ms", 0.0);
                    if (v > 0.0) return v;
                }
                JSONObject r = null;
                if (t != null) {
                    r = t.optJSONObject("ancient_report");
                    if (r == null) r = t.optJSONObject("decrypt_report");
                }
                if (r == null && detail != null) {
                    r = detail.optJSONObject("ancient_report");
                    if (r == null) r = detail.optJSONObject("decrypt_report");
                }
                if (r != null) {
                    v = r.optDouble("total_ms", 0.0);
                    if (v <= 0.0) v = r.optDouble("elapsed_ms", 0.0);
                    if (v <= 0.0) v = r.optDouble("duration_ms", 0.0);
                    if (v > 0.0) return v;
                }
                // 服务端旧记录 total_ms=0 时，使用 updated_at-created_at 作为展示兜底。
                if (t != null) {
                    long c = parseTime(safe(t.optString("created_at", "")));
                    long u = parseTime(safe(t.optString("updated_at", "")));
                    if (c > 0 && u > c) return (double)(u - c);
                }
                return 0.0;
            } catch(Exception e) { return 0.0; }
        }

        String formatDecryptSummary(JSONObject detail, JSONObject t) {
            try {
                boolean forceAncient = isKnownAncientTask(t) || isKnownAncientTask(detail);
                boolean forceModern = !forceAncient && (rawTaskSaysModern(t) || rawTaskSaysModern(detail));
                String direct = safe(t == null ? "" : t.optString("decrypt_summary", "")).trim();
                if (direct.length() == 0 && detail != null) direct = safe(detail.optString("decrypt_summary", "")).trim();
                JSONObject r = null;
                if (t != null) {
                    r = t.optJSONObject(forceAncient ? "ancient_report" : "decrypt_report");
                    if (r == null) r = t.optJSONObject(forceAncient ? "decrypt_report" : "ancient_report");
                }
                if (r == null && detail != null) {
                    r = detail.optJSONObject(forceAncient ? "ancient_report" : "decrypt_report");
                    if (r == null) r = detail.optJSONObject(forceAncient ? "decrypt_report" : "ancient_report");
                }
                StringBuilder sb = new StringBuilder();
                JSONObject staticOptions = t == null ? null : taskNestedObject(t, "options_json");
                if (staticOptions == null && t != null) staticOptions = taskNestedObject(t, "options");
                if (staticOptions == null && detail != null) staticOptions = taskNestedObject(detail, "options_json");
                if (staticOptions == null && detail != null) staticOptions = taskNestedObject(detail, "options");
                if (direct.length() > 0) {
                    String[] lines = direct.split("\n");
                    for (int i=0;i<lines.length;i++) {
                        String line = lines[i] == null ? "" : lines[i].trim();
                        if (line.length() == 0) continue;
                        // V128: task family is authoritative.  Ancient tasks must never show
                        // stale V3 summary lines; V3 tasks must never show stale ancient lines.
                        if (forceAncient && (line.indexOf("新版 V3") >= 0 || line.indexOf("方案：V3") >= 0 || line.indexOf("包名.project") >= 0)) continue;
                        if (forceModern && (line.indexOf("远古") >= 0 || line.indexOf("old-iApp") >= 0)) continue;
                        if (sb.length() > 0) sb.append("\n");
                        sb.append(line);
                    }
                }
                if (r != null) {
                    String scheme = safe(r.optString("scheme", "")).trim().toLowerCase(Locale.US);
                    String fam = safe(r.optString("family", "")).trim().toLowerCase(Locale.US);
                    boolean modern = !forceAncient && (forceModern || "v3".equals(scheme) || "v3".equals(fam) || scheme.indexOf("新版") >= 0);
                    if (modern) {
                        addDecryptLine(sb, "方案", "新版 V3");
                        String sk = r.optString("sokey", "");
                        if (sk.length() == 0) sk = r.optString("hidden", "");
                        addDecryptLine(sb, "sokey", sk);
                        String dk = r.optString("dexkey", "");
                        if (dk.length() == 0) dk = r.optString("fb", "");
                        addDecryptLine(sb, "dexkey", dk);
                        addDecryptLine(sb, "包名.project", r.optString("project_file", ""));
                        JSONObject dr = r.optJSONObject("dynamic_restore");
                        if (dr != null) addDecryptLine(sb, "动态修复", dr.optBoolean("enabled", false) ? "已开启" : "未开启");
                        if (staticOptions != null) {
                            boolean antiStatic = taskBool(staticOptions, "anti_encrypted_sample")
                                    || taskBool(staticOptions, "anti_qiushui")
                                    || taskBool(staticOptions, "hidden_resource_restore");
                            boolean resourceStatic = antiStatic || taskBool(staticOptions, "static_resource_analysis");
                            boolean parameterStatic = antiStatic || taskBool(staticOptions, "static_parameter_analysis");
                            addDecryptLine(sb, "反加密样本", antiStatic ? "已开启" : "未开启");
                            boolean antiIapecStatic = taskBool(staticOptions, "anti_iapec_encryption");
                            String antiIapecState = antiIapecStatic ? "已开启" : "未开启";
                            int antiIapecRestored = staticOptions.optInt("anti_iapec_restored_count", 0);
                            if (antiIapecStatic && antiIapecRestored > 0) antiIapecState = "已还原";
                            addDecryptLine(sb, "反iAPEC加密", antiIapecState);
                            addDecryptLine(sb, "反iAPEC自毁", taskBool(staticOptions, "anti_iapec_self_destruct") ? "已开启" : "未开启");
                            addDecryptLine(sb, "静态资源分析", resourceStatic ? "已开启" : "未开启");
                            addDecryptLine(sb, "静态参数分析", parameterStatic ? "已开启" : "未开启");
                            String uploadMode = safe(staticOptions.optString("client_upload_mode", "")).trim();
                            boolean fullApk = taskBool(staticOptions, "client_full_apk_uploaded")
                                    || uploadMode.toLowerCase(Locale.US).contains("full-apk");
                            if (antiStatic || resourceStatic || parameterStatic || uploadMode.length() > 0) {
                                addDecryptLine(sb, "上传内容", fullApk ? "完整 APK" : "轻量 APK");
                            }
                        }
                    } else {
                        if (sb.toString().indexOf("方案：远古") < 0) addDecryptLine(sb, "方案", "远古");
                        addDecryptLine(sb, "sokey", r.optString("sokey", ""));
                        addDecryptLine(sb, "sokey来源", r.optString("sokey_source", ""));
                        addDecryptLine(sb, "dexkey", r.optString("dexkey", ""));
                        addDecryptLine(sb, "dexkey来源", r.optString("dexkey_source", ""));
                        addDecryptLine(sb, "签名模式", r.optString("signature_mode", ""));
                        addDecryptLine(sb, "主文件", r.optString("main_file", ""));
                        if (r.has("decrypted_count") || r.has("member_count")) addDecryptLine(sb, "成员解密", r.optInt("decrypted_count",0)+"/"+r.optInt("member_count",0));
                        if (r.has("written_count")) addDecryptLine(sb, "写出文件", String.valueOf(r.optInt("written_count",0)));
                        int unknownFileCount = r.optInt("unknown_name_count", 0);
                        JSONObject filenameRescan = r.optJSONObject("filename_rescan");
                        if (filenameRescan != null) {
                            unknownFileCount = filenameRescan.optInt("unknown_remaining", unknownFileCount);
                        }
                        addDecryptLine(sb, "未知文件数", String.valueOf(Math.max(0, unknownFileCount)));
                        if (staticOptions != null) {
                            boolean antiIapecStatic = taskBool(staticOptions, "anti_iapec_encryption");
                            String antiIapecState = antiIapecStatic ? "已开启" : "未开启";
                            int antiIapecRestored = staticOptions.optInt("anti_iapec_restored_count", 0);
                            if (antiIapecStatic && antiIapecRestored > 0) antiIapecState = "已还原";
                            addDecryptLine(sb, "反iAPEC加密", antiIapecState);
                            addDecryptLine(sb, "反iAPEC自毁", taskBool(staticOptions, "anti_iapec_self_destruct") ? "已开启" : "未开启");
                        }
                        JSONObject dr = r.optJSONObject("dynamic_restore");
                        if (dr != null) {
                            if (dr.optBoolean("enabled", false)) {
                                String e = safe(dr.optString("error", "")).trim();
                                addDecryptLine(sb, "动态修复", e.length() > 0 ? ("已开启，但失败：" + e) : "已开启，服务端 DEX 映射替换");
                            } else if (dr.length() > 0) {
                                addDecryptLine(sb, "动态修复", "未开启");
                            }
                        }
                        double ms = r.optDouble("total_ms", 0.0);
                        if (ms > 0.0) addDecryptLine(sb, "引擎耗时", String.format(Locale.US, "%.2f 秒", ms/1000.0));
                    }
                }
                String taskStatus = safe(t == null ? "" : t.optString("status", "")).trim().toLowerCase(Locale.US);
                if (taskStatus.length() == 0 && detail != null) taskStatus = safe(detail.optString("status", "")).trim().toLowerCase(Locale.US);
                if ("failed".equals(taskStatus) || "error".equals(taskStatus)) {
                    String failure = safe(t == null ? "" : t.optString("error", t.optString("message", ""))).trim();
                    if (failure.length() == 0 && detail != null) failure = safe(detail.optString("error", detail.optString("message", ""))).trim();
                    if (failure.length() > 240) failure = failure.substring(0, 240) + "…";
                    if (failure.length() > 0) addDecryptLine(sb, "失败原因", failure);
                }
                if (forceAncient && sb.toString().indexOf("方案：远古") < 0) {
                    String old = sb.toString().trim();
                    sb.setLength(0);
                    addDecryptLine(sb, "方案", "远古");
                    if (old.length() > 0) sb.append("\n").append(old);
                }
                // V133: normalize the final display to exactly one scheme line.
                // Old API layers may still return a stale V3 summary together with
                // an ancient report; the task family is authoritative.
                String rawSummary = sb.toString().trim();
                StringBuilder normalized = new StringBuilder();
                String[] finalLines = rawSummary.split("\n");
                if (forceAncient) addDecryptLine(normalized, "方案", "远古");
                else if (forceModern) addDecryptLine(normalized, "方案", "新版 V3");
                for (int i=0;i<finalLines.length;i++) {
                    String line = finalLines[i] == null ? "" : finalLines[i].trim();
                    if (line.length() == 0 || line.startsWith("方案：")) continue;
                    if (forceAncient && (line.indexOf("新版 V3") >= 0 || line.indexOf("方案：V3") >= 0)) continue;
                    if (forceModern && (line.indexOf("远古") >= 0 || line.indexOf("old-iApp") >= 0)) continue;
                    if (normalized.length() > 0) normalized.append("\n");
                    normalized.append(line);
                }
                return normalized.toString().trim();
            } catch(Exception e) { return ""; }
        }


        void addDecryptLine(StringBuilder sb, String k, String v) {
            try {
                v = safe(v).trim();
                if (v.length() == 0 || "null".equalsIgnoreCase(v) || "none".equalsIgnoreCase(v)) return;
                String line = k + "：" + v;
                if (sb.indexOf(line) >= 0) return;
                if (sb.length() > 0) sb.append("\n");
                sb.append(line);
            } catch(Exception ignored) {}
        }

        String formatProjectMetaOneLine(JSONObject t) {
            String x = formatProjectMeta(t);
            if (x == null || x.length() == 0) return "";
            return x.replace("\n", "  ·  ");
        }

        void showSearchDialog(final int taskId) {
            LinearLayout box = vbox(); box.setPadding(dp(4), dp(4), dp(4), dp(4));
            final EditText name = edit("输入文件名，多个可用逗号/换行分隔"); 
            name.setSingleLine(false);
            name.setMinLines(2);
            name.setGravity(Gravity.CENTER_VERTICAL);
            final CheckBox recursive = check("启用递归引用");
            
            final TextView result = tv("", 13, BLACK, 0); result.setPadding(dp(8),dp(12),dp(8),dp(12));
            result.setBackground(bg(BG, 12));
            result.setVisibility(View.GONE);
            
            box.addView(name, new LinearLayout.LayoutParams(-1, dp(86))); 
            box.addView(recursive, new LinearLayout.LayoutParams(-1, dp(40)));
            addM(box, result, -1, -2, 0, 12, 0, 0);
            
            final AlertDialog dlg = mdDialog("搜索", box).setNegativeButton("关闭", null).setPositiveButton("查找", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    final String q = name.getText().toString().trim();
                    if(q.length()==0){ toast("请输入文件名"); return; }
                    async("正在从已解密外壳查找...", new Job(){ public Object run() throws Exception {
                        JSONObject body = new JSONObject();
                        body.put("find", q);
                        body.put("find_recursive", recursive.isChecked());
                        return api.post("/tasks/"+taskId+"/shell-find", body);
                    }}, new Done(){ public void ok(Object o){
                        JSONObject r = (JSONObject)o;
                        StringBuilder text = new StringBuilder();
                        text.append("找到：").append(r.optInt("found_count", 0)).append(" 个");
                        text.append("，新增：").append(r.optInt("added_count", 0)).append(" 个\n");
                        JSONArray items = r.optJSONArray("items");
                        if (items != null) {
                            for (int i=0; i<items.length() && i<30; i++) {
                                JSONObject it = items.optJSONObject(i);
                                if (it == null) continue;
                                text.append("✓ ").append(it.optString("source_name", it.optString("rel_path", ""))).append("\n");
                            }
                        }
                        JSONArray missing = r.optJSONArray("not_found");
                        if (missing != null && missing.length() > 0) {
                            text.append("未找到：\n");
                            for (int i=0; i<missing.length() && i<30; i++) text.append("× ").append(missing.optString(i, "")).append("\n");
                        }
                        result.setText(text.toString().trim());
                        result.setVisibility(View.VISIBLE);
                        cacheDrop("task_detail_" + taskId);
                        cacheDrop("tasks");
                        toast(r.optInt("found_count",0) > 0 ? "查找完成" : "没有找到文件");
                    }});
                }});
            }});
            
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
            dlg.show();
        }

        void downloadZip(final JSONObject task) {
            if (!ensureStorageReady()) return;
            async("正在下载并解密 ZIP...", new Job(){ public Object run() throws Exception {
                File dir = new File(Environment.getExternalStorageDirectory(), "iApt");
                if (!dir.exists()) dir.mkdirs();
                if (!dir.exists() || !dir.canWrite()) {
                    File alt = a.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                    dir = new File(alt == null ? a.getFilesDir() : alt, "iApt");
                    if (!dir.exists()) dir.mkdirs();
                }
                return api.downloadTask(task.optInt("id",0), dir, safe(task.optString("apk_name", "task")));
            }}, new Done(){ public void ok(Object o){
                final File f = (File)o; toast("已保存："+f.getAbsolutePath());
                
                AlertDialog mdNotice = new AlertDialog.Builder(a)
                    .setTitle("下载完成")
                    .setMessage(f.getAbsolutePath())
                    .setPositiveButton("打开", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){ openFile(f); }})
                    .setNegativeButton("关闭", null)
                    .create();
                if (mdNotice.getWindow() != null) mdNotice.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
                mdNotice.show();
            }});
        }

        void openFile(File f) {
            try {
                Intent it = new Intent(Intent.ACTION_VIEW);
                it.setDataAndType(Uri.fromFile(f), "application/zip");
                it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                a.startActivity(it);
            } catch(Exception e) { toast("无法打开，请到文件管理器查看"); }
        }

        void showMine() {
            topLevelPage = true;
            currentMainTab = 2;
            setTab(2);
            clearContent();
            ScrollView sv = new ScrollView(a);
            sv.setVerticalScrollBarEnabled(false);
            final LinearLayout page = vbox();
            page.setPadding(dp(16), dp(16), dp(16), dp(40));
            sv.addView(page);
            content.addView(sv, new FrameLayout.LayoutParams(-1, -1));
            applyPageTransition(sv);

            JSONObject cached = cacheGet("me", 5 * 60 * 1000);
            if (cached != null) { applyMeResponse(cached); renderMine(page, cached); }
            else { page.addView(tv("正在后台刷新用户信息...", 13, TEXT_SUB, 0)); }

            async("后台刷新用户信息...", new Job(){ public Object run() throws Exception { return api.get("/me"); }}, new Done(){ public void ok(Object o){
                JSONObject r = (JSONObject)o; cachePut("me", r); applyMeResponse(r); renderMine(page, r);
            }});
        }

        LinearLayout mdListItem(String title, String letter, int color) {
            LinearLayout row = hbox();
            row.setPadding(dp(12), dp(16), dp(12), dp(16));

            TextView t = tv(title, 16, TEXT_MAIN, 0);
            row.addView(t, new LinearLayout.LayoutParams(0, -2, 1));

            TextView arrow = tv("›", 22, TEXT_SUB, 0);
            arrow.setGravity(Gravity.CENTER);
            row.addView(arrow, new LinearLayout.LayoutParams(-2, -2));

            addClickAnim(row);
            return row;
        }

        LinearLayout card(String title) {
            LinearLayout c = vbox();
            c.setPadding(dp(18), dp(16), dp(18), dp(16));
            c.setBackground(bg(CARD, 22));
            softElev(c, 2);
            TextView t = tv(title, 15, BLACK, Typeface.BOLD);
            c.addView(t, new LinearLayout.LayoutParams(-1, dp(30)));
            return c;
        }



        LinearLayout heroBlock(String title, String sub) {
            LinearLayout hero = vbox();
            hero.setPadding(dp(20), dp(18), dp(20), dp(18));
            hero.setBackground(bg(Color.WHITE, 24));
            softElev(hero, 3);
            TextView h = tv(title, 22, BLACK, Typeface.BOLD);
            TextView d = tv(sub, 13, GRAY, Typeface.BOLD);
            addM(hero, h, -1, dp(30), 0, 0, 0, 8);
            addM(hero, d, -1, dp(22), 0, 0, 0, 0);
            return hero;
        }

        Button actionTile(String text, int bgColor, int txtColor) {
            Button v = btn(text, bgColor, txtColor);
            softElev(v, 2);
            return v;
        }

        void renderMine(LinearLayout page, JSONObject r) {
            page.removeAllViews();
            final JSONObject u = r.optJSONObject("user") == null ? new JSONObject() : r.optJSONObject("user");

            LinearLayout profile = vbox();
            profile.setBackground(bg(MD3_SURFACE_CONTAINER_LOW, 16));
            profile.setPadding(dp(20), dp(20), dp(20), dp(20));
            String displayName = u.optString("name", "").length() == 0 ? u.optString("username", "用户") : u.optString("name", "");
            String role = isAdmin ? "管理员" : "普通用户";
            profile.addView(tv(role, 20, TEXT_MAIN, Typeface.BOLD), new LinearLayout.LayoutParams(-1, -2));
            profile.addView(tv("ID: " + u.optString("username", displayName), 14, TEXT_SUB, 0), new LinearLayout.LayoutParams(-1, -2));

            LinearLayout quotaRow = hbox();
            quotaRow.setGravity(Gravity.CENTER_VERTICAL);
            TextView balance = pill("余额  " + String.format(Locale.US,"%.2f", u.optDouble("balance",0)), Color.argb(28, Color.red(MD3_PRIMARY), Color.green(MD3_PRIMARY), Color.blue(MD3_PRIMARY)), MD3_PRIMARY, 12);
            JSONObject quota = u.optJSONObject("quota");
            TextView quotaChip = pill("额度  " + (quota==null?"0":quotaText(quota,"total","0")), Color.argb(25, 56, 142, 60), Color.parseColor("#388E3C"), 12);
            quotaRow.addView(balance, new LinearLayout.LayoutParams(-2, dp(34)));
            LinearLayout.LayoutParams qcLp = new LinearLayout.LayoutParams(-2, dp(34));
            qcLp.leftMargin = dp(10);
            quotaRow.addView(quotaChip, qcLp);
            LinearLayout.LayoutParams quotaLp = new LinearLayout.LayoutParams(-1, dp(36));
            quotaLp.topMargin = dp(14);
            profile.addView(quotaRow, quotaLp);

            addClickAnim(profile);
            profile.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showEditProfileDialog(); }});
            LinearLayout.LayoutParams pcLp = new LinearLayout.LayoutParams(-1, -2);
            pcLp.bottomMargin = dp(24);
            page.addView(profile, pcLp);

            LinearLayout redeem = mdListItem("兑换", "", MD3_PRIMARY);
            LinearLayout sub = mdListItem("订阅管理", "", MD3_PRIMARY);
            LinearLayout checkin = mdListItem("签到", "", MD3_PRIMARY);
            addM(page, redeem, -1, -2, 0, 0, 0, 0);
            addM(page, sub, -1, -2, 0, 0, 0, 0);
            addM(page, checkin, -1, -2, 0, 0, 0, 0);

            if(isAdmin) {
                LinearLayout adminBtn = mdListItem("后台管理", "", MD3_PRIMARY);
                addM(page, adminBtn, -1, -2, 0, 0, 0, 0);
                adminBtn.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showAdmin(); }});
            }

            if(isMaintUser()) {
                LinearLayout maint = mdListItem("服务器维护", "", MD3_PRIMARY);
                addM(page, maint, -1, -2, 0, 0, 0, 0);
                maint.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showMaintenance(); }});
            }

            LinearLayout logout = mdListItem("退出登录", "", Color.parseColor("#E11D48"));
            addM(page, logout, -1, -2, 0, 0, 0, 0);

            redeem.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showRedeemDialog(); }});
            sub.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showSubscriptions(); }});
            checkin.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ doCheckin(); }});
            logout.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ logoutToLogin(); }});
        }




        void showIappJumpPage() {
            topLevelPage = false;
            currentMainTab = 1;
            clearContent(); setTab(1);
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            LinearLayout page = vbox(); page.setPadding(dp(16),dp(16),dp(16),dp(90)); sv.addView(page); content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            LinearLayout hero = heroBlock("跳转界面", "按iApp文件名跳转"); addM(page, hero, -1, -2, 0, 0, 0, 14);

            LinearLayout cfg = card("目标");
            final EditText pkg = edit("包名"); pkg.setSingleLine(true); pkg.setText(sp.getString("iapp_jump_pkg", ""));
            final EditText act = edit("文件名"); act.setSingleLine(true); act.setText(sp.getString("iapp_jump_activity", "mian.iyu"));
            final TextView out = tv("", 12, BLACK, 0); out.setTextIsSelectable(true); out.setMovementMethod(new ScrollingMovementMethod());
            Button pick = btn("选择软件", Color.parseColor("#EEF2F7"), BLACK);
            Button launchMain = btn("默认首页", Color.parseColor("#EEF2F7"), BLACK);
            Button go = btn("跳转", BLUE, Color.WHITE);
            Button save = btn("保存", Color.parseColor("#EAF4EF"), Color.parseColor("#4E725F"));
            cfg.addView(tv("不用LSP，不注入目标软件；通过 OpenFilexmlui 打开指定文件。", 12, GRAY, 0));
            cfg.addView(tv("文件名可填：mian.iyu、aa.iyu、ll.ilua、xx.ijava、xx.ijs。", 12, GRAY, 0));
            addM(cfg, pkg, -1, dp(48), 0, 10, 0, 8);
            addM(cfg, act, -1, dp(48), 0, 0, 0, 8);
            LinearLayout r1 = hbox(); r1.addView(pick, new LinearLayout.LayoutParams(0, dp(44), 1)); Space s1 = new Space(a); r1.addView(s1, new LinearLayout.LayoutParams(dp(10), 1)); r1.addView(launchMain, new LinearLayout.LayoutParams(0, dp(44), 1));
            addM(cfg, r1, -1, dp(44), 0, 0, 0, 8);
            LinearLayout r2 = hbox(); r2.addView(save, new LinearLayout.LayoutParams(0, dp(44), 1)); Space s2 = new Space(a); r2.addView(s2, new LinearLayout.LayoutParams(dp(10), 1)); r2.addView(go, new LinearLayout.LayoutParams(0, dp(44), 1));
            addM(cfg, r2, -1, dp(44), 0, 0, 0, 8);
            addM(cfg, out, -1, -2, 0, 0, 0, 0);
            addM(page, cfg, -1, -2, 0, 0, 0, 14);

            Button back = btn("返回功能", Color.parseColor("#EEF2F7"), BLACK); addM(page, back, -1, dp(48), 0, 0, 0, 0);
            back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showFuncs(); }});
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                String p = pkg.getText().toString().trim(); String c = act.getText().toString().trim();
                sp.edit().putString("iapp_jump_pkg", p).putString("iapp_jump_activity", c).apply(); toast("已保存");
            }});
            go.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                String p = pkg.getText().toString().trim(); String c = act.getText().toString().trim();
                String r = jumpToIappActivity(p, c); out.setText(r); if(r.indexOf("成功") >= 0) toast("已跳转"); else toast("跳转失败");
            }});
            launchMain.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                String p = pkg.getText().toString().trim(); if(p.length()==0){ toast("请输入包名"); return; }
                act.setText("mian.iyu"); out.setText("默认首页：mian.iyu");
            }});
            pick.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showJumpAppPicker(pkg, act, out); }});
        }

        String jumpToIappActivity(String pkg, String file) {
            try {
                if(pkg == null || pkg.trim().length()==0) return "请输入包名";
                pkg = pkg.trim();
                String openFile = normalizeIappOpenFile(file);
                ArrayList<String> candidates = jumpActivityCandidates(pkg, openFile);
                String last = "";
                for(int i=0;i<candidates.size();i++) {
                    String c = candidates.get(i);
                    try {
                        Intent it = new Intent(Intent.ACTION_MAIN);
                        it.setClassName(pkg, c);
                        it.putExtra("OpenFilexmlui", openFile);
                        it.putExtra("OpenFilexmluiPath", openFile);
                        it.putExtra("OpenFile", openFile);
                        it.putExtra("filename", openFile);
                        it.putExtra("file", openFile);
                        it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
                        a.startActivity(it);
                        sp.edit().putString("iapp_jump_pkg", pkg).putString("iapp_jump_activity", openFile).apply();
                        return "成功：" + pkg + "/" + c + "\nOpenFilexmlui=" + openFile;
                    } catch(Exception e) { last = e.getMessage()==null?String.valueOf(e):e.getMessage(); }
                }
                return "失败：" + last + "\n文件：" + openFile + "\n候选：" + candidates.toString();
            } catch(Exception e) { return "失败：" + (e.getMessage()==null?String.valueOf(e):e.getMessage()); }
        }

        ArrayList<String> jumpActivityCandidates(String pkg, String rawFile) {
            ArrayList<String> list = new ArrayList<String>();
            try {
                String file = normalizeIappOpenFile(rawFile);
                String low = file.toLowerCase(Locale.US);
                if(low.endsWith(".iyu") || low.endsWith(".myu")) {
                    addUnique(list, "com.iapp.app.run.mian");
                } else if(low.endsWith(".ilua") || low.endsWith(".mlua") || low.endsWith(".lua")) {
                    addUnique(list, "com.iapp.app.run.main");
                } else if(low.endsWith(".ijava") || low.endsWith(".mjava") || low.endsWith(".java")) {
                    addUnique(list, "com.iapp.app.run.main3");
                } else if(low.endsWith(".ijs") || low.endsWith(".mjs") || low.endsWith(".js")) {
                    addUnique(list, "com.iapp.app.run.main2");
                }
                // 兜底：不同 iApp 版本命名可能不同，逐个尝试。
                addUnique(list, "com.iapp.app.run.mian");
                addUnique(list, "com.iapp.app.run.main");
                addUnique(list, "com.iapp.app.run.main2");
                addUnique(list, "com.iapp.app.run.main3");
                String launch = getLaunchActivityName(pkg);
                if(launch.length() > 0) addUnique(list, launch);
            } catch(Exception e) {}
            return list;
        }

        String normalizeIappOpenFile(String raw) {
            try {
                String x = raw == null ? "" : raw.trim();
                if(x.length()==0) x = "mian.iyu";
                x = x.replace('\\', '/');
                while(x.startsWith("/")) x = x.substring(1);
                int q = x.indexOf('?'); if(q >= 0) x = x.substring(0, q);
                if(x.indexOf('\n') >= 0) x = x.substring(0, x.indexOf('\n'));
                if(x.indexOf('\r') >= 0) x = x.substring(0, x.indexOf('\r'));
                if(x.indexOf('/') >= 0) {
                    String[] parts = x.split("/");
                    StringBuilder sb = new StringBuilder();
                    for(int i=0;i<parts.length;i++) {
                        String part = safeJumpPathPart(parts[i]);
                        if(part.length()==0 || ".".equals(part) || "..".equals(part)) continue;
                        if(sb.length()>0) sb.append('/');
                        sb.append(part);
                    }
                    x = sb.toString();
                } else {
                    x = safeJumpPathPart(x);
                }
                if(x.length()==0) x = "mian.iyu";
                String low = x.toLowerCase(Locale.US);
                if(!(low.endsWith(".iyu") || low.endsWith(".myu") || low.endsWith(".ilua") || low.endsWith(".mlua") || low.endsWith(".lua") || low.endsWith(".ijava") || low.endsWith(".mjava") || low.endsWith(".java") || low.endsWith(".ijs") || low.endsWith(".mjs") || low.endsWith(".js"))) {
                    x = x + ".iyu";
                }
                return x.toLowerCase(Locale.US);
            } catch(Exception e) { return "mian.iyu"; }
        }

        String safeJumpPathPart(String s) {
            if(s == null) return "";
            StringBuilder sb = new StringBuilder();
            for(int i=0;i<s.length();i++) {
                char c = s.charAt(i);
                if(c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || c < 32) sb.append('_');
                else if(c == '\\' || c == '/') sb.append('_');
                else sb.append(c);
            }
            String x = sb.toString().trim();
            while(x.startsWith(".")) x = x.substring(1);
            return x;
        }

        void addUnique(ArrayList<String> list, String x) {
            if(x == null) return;
            x = x.trim();
            if(x.length()==0) return;
            for(int i=0;i<list.size();i++) if(x.equals(list.get(i))) return;
            list.add(x);
        }

        String normalizeActivityInput(String pkg, String cls) {
            try {
                if(cls == null) return "";
                cls = cls.trim();
                if(cls.startsWith("/")) cls = cls.substring(1).trim();
                if(cls.startsWith(".")) return pkg + cls;
                if(cls.indexOf('/') >= 0) {
                    String[] p = cls.split("/", 2);
                    if(p.length == 2) {
                        String right = p[1].trim();
                        if(right.startsWith(".")) return p[0].trim() + right;
                        return right;
                    }
                }
                if(cls.indexOf('.') < 0) return "com.iapp.app.run." + cls;
                return cls;
            } catch(Exception e) { return cls; }
        }

        String getLaunchActivityName(String pkg) {
            try {
                Intent it = a.getPackageManager().getLaunchIntentForPackage(pkg);
                if(it != null && it.getComponent() != null) return it.getComponent().getClassName();
            } catch(Exception e) {}
            return "";
        }

        void showJumpAppPicker(final EditText pkgEdit, final EditText actEdit, final TextView out) {
            try {
                final ArrayList<android.content.pm.ApplicationInfo> apps = new ArrayList<android.content.pm.ApplicationInfo>();
                List<android.content.pm.ApplicationInfo> all = a.getPackageManager().getInstalledApplications(0);
                if(all != null) {
                    for(int i=0;i<all.size();i++) {
                        android.content.pm.ApplicationInfo ai = all.get(i);
                        if(ai == null || ai.packageName == null) continue;
                        if(a.getPackageName().equals(ai.packageName)) continue;
                        apps.add(ai);
                    }
                }
                Collections.sort(apps, new Comparator<android.content.pm.ApplicationInfo>(){ public int compare(android.content.pm.ApplicationInfo x, android.content.pm.ApplicationInfo y){
                    String xs = String.valueOf(x.loadLabel(a.getPackageManager())); String ys = String.valueOf(y.loadLabel(a.getPackageManager())); return xs.compareToIgnoreCase(ys);
                }});
                LinearLayout box = vbox(); box.setPadding(dp(12), dp(8), dp(12), dp(4));
                final EditText manual = edit("搜索/包名"); manual.setSingleLine(true); box.addView(manual, new LinearLayout.LayoutParams(-1, dp(48)));
                final ArrayAdapter<String> adapter = new ArrayAdapter<String>(a, android.R.layout.simple_list_item_1, new ArrayList<String>());
                final ListView lv = new ListView(a); box.addView(lv, new LinearLayout.LayoutParams(-1, dp(420))); lv.setAdapter(adapter);
                final Runnable refresh = new Runnable(){ public void run(){
                    adapter.clear(); String q = manual.getText().toString().trim().toLowerCase(Locale.US);
                    int count = 0;
                    for(int i=0;i<apps.size() && count<300;i++) {
                        android.content.pm.ApplicationInfo ai = apps.get(i);
                        String name = String.valueOf(ai.loadLabel(a.getPackageManager())); String line = name + "\n" + ai.packageName;
                        if(q.length()==0 || line.toLowerCase(Locale.US).indexOf(q)>=0) { adapter.add(line); count++; }
                    }
                    adapter.notifyDataSetChanged();
                }};
                refresh.run();
                manual.addTextChangedListener(new android.text.TextWatcher(){ public void beforeTextChanged(CharSequence s,int st,int c,int a2){} public void onTextChanged(CharSequence s,int st,int b,int c){ refresh.run(); } public void afterTextChanged(android.text.Editable e){} });
                final AlertDialog dlg = new AlertDialog.Builder(a).setTitle("选择软件").setView(box).setNegativeButton("取消", null).create();
                lv.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener(){ public void onItemClick(android.widget.AdapterView<?> p, View v, int pos, long id){
                    String line = String.valueOf(adapter.getItem(pos)); int n = line.lastIndexOf('\n'); String pk = n>=0 ? line.substring(n+1).trim() : line.trim();
                    pkgEdit.setText(pk); if(actEdit.getText().toString().trim().length()==0) actEdit.setText("mian.iyu"); if(out != null) out.setText("已选择：" + pk + "\n文件名：" + actEdit.getText().toString().trim()); dlg.dismiss();
                }});
                dlg.show();
            } catch(Exception e) { toast("读取软件失败：" + e.getMessage()); }
        }

        void showHookPage() { showFbHookPage(); }

        void showFbHookPage() {
            topLevelPage = false;
            currentMainTab = 1;
            clearContent(); setTab(1);
            pruneHookEventCache();
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            LinearLayout page = vbox(); page.setPadding(dp(16),dp(16),dp(16),dp(90)); sv.addView(page); content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            syncHookFeatureFlags();
            LinearLayout hero = heroBlock("动态获取dex密钥", "运行时读取 dex密钥"); addM(page, hero, -1, -2, 0, 0, 0, 14);

            LinearLayout status = card("状态");
            final TextView lspStatus = tv(lspHookStatusText(), 12, BLACK, 0);
            status.addView(lspStatus);
            status.addView(tv("目标：dex密钥", 12, GRAY, 0));
            status.addView(tv("只记录获取到的非空返回值", 12, GRAY, 0));
            status.addView(tv("改开关后强停重开目标软件", 12, GRAY, 0));
            addM(page, status, -1, -2, 0, 0, 0, 14);

            LinearLayout switches = card("动态获取dex密钥开关");
            final TextView swState = tv("动态获取dex密钥：" + (hookFbEnabled() ? "开启" : "关闭"), 13, BLACK, Typeface.BOLD);
            final CheckBox fbSwitch = check("动态获取dex密钥");
            fbSwitch.setChecked(hookFbEnabled());
            fbSwitch.setEnabled(hasFbHookFeature());
            if (!hasFbHookFeature()) { fbSwitch.setText("动态获取dex密钥（未开通）"); fbSwitch.setTextColor(GRAY); }
            switches.addView(swState, new LinearLayout.LayoutParams(-1, dp(42)));
            switches.addView(fbSwitch, new LinearLayout.LayoutParams(-1, dp(42)));
            addM(page, switches, -1, -2, 0, 0, 0, 14);
            fbSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (checked && !hasFbHookFeature()) { b.setChecked(false); toast("当前订阅不支持动态获取dex密钥"); return; }
                hookSp.edit().putBoolean("hook_fb_enabled", checked && hasFbHookFeature()).commit();
                swState.setText("动态获取dex密钥：" + (hookFbEnabled() ? "开启" : "关闭"));
                lspStatus.setText(lspHookStatusText());
            }});

            addHookScopeCard(page);

            LinearLayout events = card("获取记录");
            final TextView ev = tv(hookEventsText(80, "fb"), 12, BLACK, 0); ev.setMovementMethod(new ScrollingMovementMethod());
            Button refresh = btn("刷新记录", Color.parseColor("#E8EEFF"), BLUE);
            Button detect = btn("检测模块", Color.parseColor("#E8EEFF"), BLUE);
            Button clear = btn("清空获取记录", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
            addM(events, ev, -1, dp(220), 0, 4, 0, 10);
            addM(events, refresh, -1, dp(48), 0, 0, 0, 8);
            addM(events, detect, -1, dp(48), 0, 0, 0, 8);
            addM(events, clear, -1, dp(48), 0, 0, 0, 0);
            addM(page, events, -1, -2, 0, 0, 0, 14);

            Button back = btn("返回功能", Color.parseColor("#EEF2F7"), BLACK); addM(page, back, -1, dp(48), 0, 0, 0, 0);
            back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showFuncs(); }});
            refresh.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "fb")); }});
            detect.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspSelfTest(); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "fb")); }});
            clear.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ clearHookEvents("fb"); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "fb")); }});
        }

        void showDynamicHookPage() {
            topLevelPage = false;
            currentMainTab = 1;
            clearContent(); setTab(1);
            pruneHookEventCache();
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            LinearLayout page = vbox(); page.setPadding(dp(16),dp(16),dp(16),dp(90)); sv.addView(page); content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            syncHookFeatureFlags();
            LinearLayout hero = heroBlock("动态解密", "运行时源码采集"); addM(page, hero, -1, -2, 0, 0, 0, 14);

            LinearLayout status = card("状态");
            final TextView lspStatus = tv(lspHookStatusText(), 12, BLACK, 0);
            status.addView(lspStatus);
            status.addView(tv("采集：iApp界面/事件/脚本", 12, GRAY, 0));
            status.addView(tv("输出：/sdcard/iApt/dump/包名/", 12, GRAY, 0));
            status.addView(tv("文件：iyu/myu/mjava/mjs/mlua/ijs/ilua/ijava/java", 12, GRAY, 0));
            status.addView(tv("同页面内容会合并", 12, GRAY, 0));
            status.addView(tv("开启后强停重开目标软件", 12, GRAY, 0));
            addM(page, status, -1, -2, 0, 0, 0, 14);

            LinearLayout switches = card("动态解密开关");
            final TextView swState = tv("动态解密：" + (hookDynamicEnabled() ? "开启" : "关闭"), 13, BLACK, Typeface.BOLD);
            final CheckBox dynSwitch = check("动态解密");
            dynSwitch.setChecked(hookDynamicEnabled());
            dynSwitch.setEnabled(hasDynamicHookFeature());
            if (!hasDynamicHookFeature()) { dynSwitch.setText("动态解密（未开通）"); dynSwitch.setTextColor(GRAY); }
            switches.addView(swState, new LinearLayout.LayoutParams(-1, dp(42)));
            switches.addView(dynSwitch, new LinearLayout.LayoutParams(-1, dp(42)));
            switches.addView(tv("与动态获取dex密钥独立", 12, GRAY, 0));
            switches.addView(tv("输出：/sdcard/iApt/dump/包名/", 12, GRAY, 0));
            Button permBtn = btn("授予文件权限", Color.parseColor("#E8EEFF"), BLUE);
            switches.addView(permBtn, new LinearLayout.LayoutParams(-1, dp(46)));
            addM(page, switches, -1, -2, 0, 0, 0, 14);
            permBtn.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                try {
                    Intent it = new Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION");
                    it.setData(Uri.parse("package:" + a.getPackageName()));
                    a.startActivity(it);
                } catch(Throwable e) {
                    try { a.startActivity(new Intent("android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION")); }
                    catch(Throwable ex) { toast("打开权限失败"); }
                }
            }});
            dynSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (checked && !hasDynamicHookFeature()) { b.setChecked(false); toast("当前订阅不支持动态解密"); return; }
                hookSp.edit().putBoolean("hook_dynamic_enabled", checked && hasDynamicHookFeature()).commit();
                swState.setText("动态解密：" + (hookDynamicEnabled() ? "开启" : "关闭"));
                lspStatus.setText(lspHookStatusText());
            }});

            addHookScopeCard(page);

            LinearLayout events = card("动态记录");
            final TextView ev = tv(hookEventsText(80, "dynamic"), 12, BLACK, 0); ev.setMovementMethod(new ScrollingMovementMethod());
            Button refresh = btn("刷新记录", Color.parseColor("#E8EEFF"), BLUE);
            Button detect = btn("检测模块", Color.parseColor("#E8EEFF"), BLUE);
            Button clear = btn("清空动态记录", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
            addM(events, ev, -1, dp(220), 0, 4, 0, 10);
            addM(events, refresh, -1, dp(48), 0, 0, 0, 8);
            addM(events, detect, -1, dp(48), 0, 0, 0, 8);
            addM(events, clear, -1, dp(48), 0, 0, 0, 0);
            addM(page, events, -1, -2, 0, 0, 0, 14);

            Button back = btn("返回功能", Color.parseColor("#EEF2F7"), BLACK); addM(page, back, -1, dp(48), 0, 0, 0, 0);
            back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showFuncs(); }});
            refresh.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "dynamic")); }});
            detect.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspSelfTest(); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "dynamic")); }});
            clear.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ clearHookEvents("dynamic"); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "dynamic")); }});
        }


        void showFunctionControlPage() {
            topLevelPage = false;
            currentMainTab = 1;
            clearContent(); setTab(1);
            pruneHookEventCache();
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            LinearLayout page = vbox(); page.setPadding(dp(16),dp(16),dp(16),dp(90)); sv.addView(page); content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            syncHookFeatureFlags();
            LinearLayout hero = heroBlock("函数控制", "运行时规则"); addM(page, hero, -1, -2, 0, 0, 0, 14);

            LinearLayout status = card("状态");
            final TextView lspStatus = tv(lspHookStatusText(), 12, BLACK, 0);
            status.addView(lspStatus);
            status.addView(tv("修改后重启目标软件生效", 12, GRAY, 0));
            addM(page, status, -1, -2, 0, 0, 0, 14);

            LinearLayout switches = card("开关");
            final TextView swState = tv("函数控制：" + (hookFuncEnabled() ? "开启" : "关闭"), 13, BLACK, Typeface.BOLD);
            final CheckBox funcSwitch = check("函数控制");
            funcSwitch.setChecked(hookFuncEnabled());
            funcSwitch.setEnabled(hasFunctionControlFeature());
            if (!hasFunctionControlFeature()) { funcSwitch.setText("函数控制（未开通）"); funcSwitch.setTextColor(GRAY); }
            switches.addView(swState, new LinearLayout.LayoutParams(-1, dp(42)));
            switches.addView(funcSwitch, new LinearLayout.LayoutParams(-1, dp(42)));
            switches.addView(tv("拦截：跳过指定调用", 12, GRAY, 0));
            switches.addView(tv("替换：把函数名改成另一个", 12, GRAY, 0));
            addM(page, switches, -1, -2, 0, 0, 0, 14);
            funcSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(){ public void onCheckedChanged(CompoundButton b, boolean checked){
                if (checked && !hasFunctionControlFeature()) { b.setChecked(false); toast("当前订阅不支持此功能"); return; }
                hookSp.edit().putBoolean("hook_func_enabled", checked && hasFunctionControlFeature()).commit();
                swState.setText("函数控制：" + (hookFuncEnabled() ? "开启" : "关闭"));
                lspStatus.setText(lspHookStatusText());
            }});

            addHookScopeCard(page);

            LinearLayout rulesCard = card("规则列表");
            final LinearLayout list = vbox();
            final Runnable refreshRules = new Runnable(){ public void run(){ renderIappFuncRules(list); }};
            Button addBlock = btn("拦截函数", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
            Button addFake = btn("替换函数", BLUE, Color.WHITE);
            Button addTextDel = btn("删除内容", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
            Button addTextRep = btn("替换内容", BLUE, Color.WHITE);
            Button clearRules = btn("清空规则", Color.parseColor("#EEF2F7"), BLACK);
            rulesCard.addView(tv("支持函数名和内容片段", 12, GRAY, 0));
            rulesCard.addView(tv("可删除或替换指定内容", 12, GRAY, 0));
            addM(rulesCard, list, -1, -2, 0, 8, 0, 8);
            addM(rulesCard, addBlock, -1, dp(46), 0, 0, 0, 8);
            addM(rulesCard, addFake, -1, dp(46), 0, 0, 0, 8);
            addM(rulesCard, addTextDel, -1, dp(46), 0, 0, 0, 8);
            addM(rulesCard, addTextRep, -1, dp(46), 0, 0, 0, 8);
            addM(rulesCard, clearRules, -1, dp(46), 0, 0, 0, 0);
            addM(page, rulesCard, -1, -2, 0, 0, 0, 14);
            refreshRules.run();
            addBlock.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showIappFuncRuleDialog("拦截", refreshRules); }});
            addFake.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showIappFuncRuleDialog("伪造", refreshRules); }});
            addTextDel.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showIappTextRuleDialog("内容删除", refreshRules); }});
            addTextRep.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showIappTextRuleDialog("内容替换", refreshRules); }});
            clearRules.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                new AlertDialog.Builder(a).setTitle("清空规则").setMessage("确认清空所有规则？")
                    .setNegativeButton("取消", null)
                    .setPositiveButton("清空", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){ hookSp.edit().putString("hook_func_rules", "").apply(); refreshRules.run(); toast("已清空"); }})
                    .show();
            }});

            LinearLayout events = card("函数控制记录");
            events.addView(tv("只显示命中的代码和修改后的代码", 12, GRAY, 0));
            final TextView ev = tv(hookEventsText(80, "func"), 12, BLACK, 0);
            ev.setMovementMethod(new ScrollingMovementMethod());
            Button refreshEvents = btn("刷新记录", Color.parseColor("#E8EEFF"), BLUE);
            Button detectEvents = btn("检测模块", Color.parseColor("#E8EEFF"), BLUE);
            Button clearEvents = btn("清空函数控制记录", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
            addM(events, ev, -1, dp(220), 0, 8, 0, 10);
            addM(events, refreshEvents, -1, dp(48), 0, 0, 0, 8);
            addM(events, detectEvents, -1, dp(48), 0, 0, 0, 8);
            addM(events, clearEvents, -1, dp(48), 0, 0, 0, 0);
            addM(page, events, -1, -2, 0, 0, 0, 14);
            refreshEvents.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "func")); }});
            detectEvents.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ lspSelfTest(); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "func")); }});
            clearEvents.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ clearHookEvents("func"); lspStatus.setText(lspHookStatusText()); ev.setText(hookEventsText(80, "func")); }});

            Button back = btn("返回功能", Color.parseColor("#EEF2F7"), BLACK); addM(page, back, -1, dp(48), 0, 0, 0, 0);
            back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showFuncs(); }});
        }

        void renderIappFuncRules(final LinearLayout list) {
            list.removeAllViews();
            final ArrayList<String[]> rs = parseIappFuncRulesUi(hookSp.getString("hook_func_rules", ""));
            if (rs.size() == 0) {
                TextView empty = tv("暂无规则", 13, GRAY, 0);
                empty.setGravity(Gravity.CENTER);
                list.addView(empty, new LinearLayout.LayoutParams(-1, dp(48)));
                return;
            }
            for (int i=0;i<rs.size();i++) {
                final int idx = i;
                String[] r = rs.get(i);
                LinearLayout row = hbox(); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(10), dp(8), dp(10), dp(8)); row.setBackground(bg(Color.parseColor("#F8FAFC"), 14));
                LinearLayout texts = vbox();
                texts.addView(tv(ruleTitle(r), 14, BLACK, Typeface.BOLD));
                texts.addView(tv(ruleSub(r), 12, GRAY, 0));
                row.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));
                Button del = btn("删除", Color.parseColor("#FCEBEC"), Color.parseColor("#C45454"));
                row.addView(del, new LinearLayout.LayoutParams(dp(78), dp(40)));
                addM(list, row, -1, -2, 0, 4, 0, 8);
                del.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    ArrayList<String[]> cur = parseIappFuncRulesUi(hookSp.getString("hook_func_rules", ""));
                    if (idx >= 0 && idx < cur.size()) cur.remove(idx);
                    hookSp.edit().putString("hook_func_rules", buildIappFuncRulesText(cur)).apply();
                    renderIappFuncRules(list);
                    toast("已删除，重启目标软件生效");
                }});
            }
        }

        String ruleTitle(String[] r) {
            if (r == null || r.length < 2) return "规则";
            if ("伪造".equals(r[0]) && r.length >= 3) return r[1] + " → " + r[2];
            if ("内容替换".equals(r[0]) && r.length >= 3) return previewRuleText(r[1]) + " → " + previewRuleText(r[2]);
            if ("内容删除".equals(r[0])) return "内容删除 " + previewRuleText(r[1]);
            return "拦截 " + r[1];
        }

        String ruleSub(String[] r) {
            if (r == null || r.length < 2) return "";
            if ("伪造".equals(r[0])) return "把 " + r[1] + "(...) 改成 " + (r.length >= 3 ? r[2] : "") + "(...)";
            if ("内容替换".equals(r[0])) return "替换匹配内容";
            if ("内容删除".equals(r[0])) return "删除匹配内容";
            return "跳过 " + r[1] + "(...)";
        }

        String previewRuleText(String s) {
            if (s == null) return "";
            String x = s.replace('\n', ' ').replace('\r', ' ').trim();
            if (x.length() > 22) x = x.substring(0, 22) + "...";
            return x;
        }

        ArrayList<String[]> parseIappFuncRulesUi(String raw) {
            ArrayList<String[]> out = new ArrayList<String[]>();
            if (raw == null || raw.length() == 0) return out;
            String[] lines = raw.split("\\n");
            for (int i=0;i<lines.length;i++) {
                String line = lines[i] == null ? "" : lines[i].trim();
                if (line.length() == 0 || line.startsWith("#") || line.startsWith("//")) continue;
                String[] p = line.split("\\|", -1);
                if (p.length >= 2 && ("内容删除".equals(p[0]))) out.add(new String[]{"内容删除", decodeRuleTextUi(p[1])});
                else if (p.length >= 3 && ("内容替换".equals(p[0]))) out.add(new String[]{"内容替换", decodeRuleTextUi(p[1]), decodeRuleTextUi(p[2])});
                else if (p.length >= 2 && ("拦截".equals(p[0]) || "关闭".equals(p[0]) || "禁用".equals(p[0]))) out.add(new String[]{"拦截", p[1].trim()});
                else if (p.length >= 3 && ("伪造".equals(p[0]) || "替换".equals(p[0]))) out.add(new String[]{"伪造", p[1].trim(), p[2].trim()});
            }
            return out;
        }

        String buildIappFuncRulesText(ArrayList<String[]> rs) {
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<rs.size();i++) {
                String[] r = rs.get(i);
                if (r == null || r.length < 2) continue;
                if (sb.length() > 0) sb.append('\n');
                if ("内容删除".equals(r[0])) sb.append("内容删除|").append(encodeRuleTextUi(r[1]));
                else if ("内容替换".equals(r[0]) && r.length >= 3) sb.append("内容替换|").append(encodeRuleTextUi(r[1])).append('|').append(encodeRuleTextUi(r[2]));
                else if ("伪造".equals(r[0]) && r.length >= 3) sb.append("伪造|").append(cleanFuncName(r[1])).append('|').append(cleanFuncName(r[2]));
                else sb.append("拦截|").append(cleanFuncName(r[1]));
            }
            return sb.toString();
        }

        String encodeRuleTextUi(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<s.length();i++) {
                char c = s.charAt(i);
                if (c == '\\') sb.append("\\\\");
                else if (c == '\n') sb.append("\\n");
                else if (c == '\r') sb.append("\\r");
                else if (c == '\t') sb.append("\\t");
                else if (c == '|') sb.append("\\p");
                else sb.append(c);
            }
            return sb.toString();
        }

        String decodeRuleTextUi(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<s.length();i++) {
                char c = s.charAt(i);
                if (c == '\\' && i + 1 < s.length()) {
                    char n = s.charAt(++i);
                    if (n == 'n') sb.append('\n');
                    else if (n == 'r') sb.append('\r');
                    else if (n == 't') sb.append('\t');
                    else if (n == 'p') sb.append('|');
                    else if (n == '\\') sb.append('\\');
                    else { sb.append('\\'); sb.append(n); }
                } else sb.append(c);
            }
            return sb.toString();
        }

        String cleanFuncName(String s) {
            if (s == null) return "";
            String x = s.trim();
            if (x.endsWith("()")) x = x.substring(0, x.length()-2).trim();
            x = x.replace("|", "").replace("\n", "").replace("\r", "");
            return x;
        }

        void showIappFuncRuleDialog(final String mode, final Runnable after) {
            LinearLayout box = vbox(); box.setPadding(dp(16), dp(8), dp(16), dp(4));
            final EditText from = edit("原函数名"); from.setSingleLine(true);
            final EditText to = edit("目标函数名"); to.setSingleLine(true);
            addM(box, from, -1, dp(48), 0, 0, 0, 8);
            if ("伪造".equals(mode)) addM(box, to, -1, dp(48), 0, 0, 0, 8);
            TextView tip = tv("保存后重启目标软件生效", 12, GRAY, 0);
            box.addView(tip);
            final AlertDialog dlg = mdDialog(("伪造".equals(mode) ? "添加函数替换" : "添加函数拦截"), box).setNegativeButton("取消", null).setPositiveButton("保存", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    String f = cleanFuncName(from.getText().toString());
                    String t = cleanFuncName(to.getText().toString());
                    if (f.length() == 0) { toast("请输入函数名"); return; }
                    if ("伪造".equals(mode) && t.length() == 0) { toast("请输入目标函数"); return; }
                    ArrayList<String[]> cur = parseIappFuncRulesUi(hookSp.getString("hook_func_rules", ""));
                    if ("伪造".equals(mode)) cur.add(new String[]{"伪造", f, t}); else cur.add(new String[]{"拦截", f});
                    hookSp.edit().putString("hook_func_rules", buildIappFuncRulesText(cur)).apply();
                    dlg.dismiss();
                    if (after != null) after.run();
                    toast("已保存，重启目标软件生效");
                }});
            }});
            dlg.show();
        }

        void showIappTextRuleDialog(final String mode, final Runnable after) {
            LinearLayout box = vbox(); box.setPadding(dp(16), dp(8), dp(16), dp(4));
            final EditText from = edit("原内容");
            from.setSingleLine(false); from.setMinLines(3); from.setGravity(Gravity.TOP | Gravity.LEFT);
            final EditText to = edit("新内容");
            to.setSingleLine(false); to.setMinLines(3); to.setGravity(Gravity.TOP | Gravity.LEFT);
            addM(box, from, -1, dp(96), 0, 0, 0, 8);
            if ("内容替换".equals(mode)) addM(box, to, -1, dp(96), 0, 0, 0, 8);
            box.addView(tv("保存后强停重开目标软件", 12, GRAY, 0));
            final AlertDialog dlg = mdDialog(("内容替换".equals(mode) ? "添加内容替换" : "添加内容删除"), box).setNegativeButton("取消", null).setPositiveButton("保存", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    String f = from.getText().toString();
                    String t = to.getText().toString();
                    if (f.length() == 0) { toast("请输入原内容"); return; }
                    ArrayList<String[]> cur = parseIappFuncRulesUi(hookSp.getString("hook_func_rules", ""));
                    if ("内容替换".equals(mode)) cur.add(new String[]{"内容替换", f, t}); else cur.add(new String[]{"内容删除", f});
                    hookSp.edit().putString("hook_func_rules", buildIappFuncRulesText(cur)).apply();
                    dlg.dismiss();
                    if (after != null) after.run();
                    toast("已保存，重启目标软件生效");
                }});
            }});
            dlg.show();
        }

        void addHookScopeCard(LinearLayout page) {
            LinearLayout scope = card("作用域");
            final TextView pkgs = tv(hookPackageText(), 13, BLACK, Typeface.BOLD);
            Button choose = btn("选择软件", BLUE, Color.WHITE);
            Button req = btn("申请作用域", Color.parseColor("#E8EEFF"), BLUE);
            addM(scope, pkgs, -1, -2, 0, 4, 0, 10);
            addM(scope, choose, -1, dp(48), 0, 0, 0, 8);
            addM(scope, req, -1, dp(48), 0, 0, 0, 0);
            addM(page, scope, -1, -2, 0, 0, 0, 14);
            choose.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showHookAppPicker(new Runnable(){ public void run(){ pkgs.setText(hookPackageText()); }}); }});
            req.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ requestLsposedScope(); }});
        }

        java.util.LinkedHashSet<String> hookPackages() {
            java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<String>();
            try {
                java.util.Set<String> ss = sp.getStringSet("hook_scope_pkgs", null);
                if (ss != null) out.addAll(ss);
                String old = sp.getString("hook_scope_pkg", "");
                if (old.length() > 0) out.add(old);
            } catch(Exception e) {}
            return out;
        }

        void saveHookPackages(java.util.Set<String> set) {
            sp.edit().putStringSet("hook_scope_pkgs", new java.util.LinkedHashSet<String>(set)).apply();
        }

        String hookPackageText() {
            java.util.LinkedHashSet<String> ps = hookPackages();
            if (ps.size() == 0) return "未选择软件";
            StringBuilder sb = new StringBuilder();
            for(String p: ps) { if(sb.length()>0) sb.append("\n"); sb.append(p); }
            return sb.toString();
        }

        void showHookAppPicker(final Runnable after) {
            try {
                final java.util.ArrayList<android.content.pm.ApplicationInfo> apps = new java.util.ArrayList<android.content.pm.ApplicationInfo>();
                java.util.List<android.content.pm.ApplicationInfo> all = a.getPackageManager().getInstalledApplications(0);
                for(android.content.pm.ApplicationInfo ai: all) {
                    if (ai == null || ai.packageName == null) continue;
                    if ("com.iapt.client".equals(ai.packageName)) continue;
                    if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                    apps.add(ai);
                }
                java.util.Collections.sort(apps, new java.util.Comparator<android.content.pm.ApplicationInfo>(){
                    public int compare(android.content.pm.ApplicationInfo x, android.content.pm.ApplicationInfo y) {
                        String a1 = String.valueOf(x.loadLabel(a.getPackageManager()));
                        String b1 = String.valueOf(y.loadLabel(a.getPackageManager()));
                        return a1.compareToIgnoreCase(b1);
                    }
                });

                final java.util.LinkedHashSet<String> cur = hookPackages();
                LinearLayout box = vbox(); box.setPadding(dp(14), dp(10), dp(14), dp(4));
                final EditText manual = edit("输入包名"); manual.setSingleLine(true);
                Button addPkg = btn("添加包名", BLUE, Color.WHITE);
                addM(box, manual, -1, dp(48), 0, 0, 0, 8);
                addM(box, addPkg, -1, dp(44), 0, 0, 0, 10);

                final ListView lv = new ListView(a);
                lv.setDividerHeight(1);
                final BaseAdapter adapter = new BaseAdapter(){
                    public int getCount(){ return apps.size(); }
                    public Object getItem(int p){ return apps.get(p); }
                    public long getItemId(int p){ return p; }
                    public View getView(final int pos, View cv, android.view.ViewGroup parent){
                        final android.content.pm.ApplicationInfo ai = apps.get(pos);
                        LinearLayout row = hbox(); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(8), dp(8), dp(8), dp(8));
                        ImageView icon = new ImageView(a);
                        try { icon.setImageDrawable(ai.loadIcon(a.getPackageManager())); } catch(Exception e) {}
                        row.addView(icon, new LinearLayout.LayoutParams(dp(42), dp(42)));

                        LinearLayout texts = vbox(); texts.setPadding(dp(10), 0, dp(8), 0);
                        String label = String.valueOf(ai.loadLabel(a.getPackageManager()));
                        texts.addView(tv(label, 14, BLACK, Typeface.BOLD));
                        texts.addView(tv(ai.packageName, 11, GRAY, 0));
                        row.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));

                        final CheckBox cb = new CheckBox(a); cb.setChecked(cur.contains(ai.packageName));
                        row.addView(cb, new LinearLayout.LayoutParams(dp(48), dp(48)));
                        row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                            if (cur.contains(ai.packageName)) cur.remove(ai.packageName); else cur.add(ai.packageName);
                            cb.setChecked(cur.contains(ai.packageName));
                        }});
                        cb.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                            if (((CheckBox)v).isChecked()) cur.add(ai.packageName); else cur.remove(ai.packageName);
                        }});
                        return row;
                    }
                };
                lv.setAdapter(adapter);
                box.addView(lv, new LinearLayout.LayoutParams(-1, dp(420)));

                addPkg.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    String p = manual.getText().toString().trim();
                    if (p.length() == 0) { toast("请输入包名"); return; }
                    if (p.indexOf(' ') >= 0 || p.indexOf('/') >= 0 || p.indexOf('\\') >= 0) { toast("包名不正确"); return; }
                    cur.add(p);
                    manual.setText("");
                    adapter.notifyDataSetChanged();
                    toast("已添加");
                }});

                AlertDialog dlg = new AlertDialog.Builder(a)
                    .setTitle("选择软件")
                    .setView(box)
                    .setNegativeButton("取消", null)
                    .setPositiveButton("保存", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                        saveHookPackages(cur); toast("已保存"); if(after != null) after.run();
                    }})
                    .create();
                dlg.show();
            } catch(Exception e) { toast("读取软件失败：" + e.getMessage()); }
        }

        void requestLsposedScope() {
            String pkgs = hookPackageText();
            if (pkgs.indexOf("未选择") >= 0) { toast("请先选择软件"); return; }
            try {
                android.content.ClipboardManager cm = (android.content.ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setPrimaryClip(android.content.ClipData.newPlainText("iAPT Hook作用域", pkgs));
            } catch(Exception e) {}
            try {
                String[] managers = new String[]{"org.lsposed.manager", "org.lsposed.lspd", "de.robv.android.xposed.installer"};
                for(int i=0;i<managers.length;i++) {
                    Intent it = a.getPackageManager().getLaunchIntentForPackage(managers[i]);
                    if (it != null) {
                        it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        a.startActivity(it);
                        toast("已复制包名，请在LSPosed启用iAPT并勾选作用域");
                        return;
                    }
                }
                Intent it = new Intent(Intent.ACTION_VIEW, Uri.parse("lsposed://modules"));
                a.startActivity(it);
            } catch(Exception e) { toast("请手动打开LSPosed并勾选作用域"); }
        }


        String lspHookStatusText() {
            StringBuilder sb = new StringBuilder();
            try {
                boolean meta = false;
                try {
                    android.content.pm.ApplicationInfo ai = a.getPackageManager().getApplicationInfo(a.getPackageName(), android.content.pm.PackageManager.GET_META_DATA);
                    meta = ai != null && ai.metaData != null && ai.metaData.getBoolean("xposedmodule", false);
                } catch(Exception e) {}
                boolean provider = false;
                boolean receiver = false;
                try {
                    android.content.pm.ProviderInfo pi = a.getPackageManager().resolveContentProvider("com.iapt.client.hook", 0);
                    provider = pi != null && a.getPackageName().equals(pi.packageName);
                } catch(Exception e) {}
                try {
                    android.content.Intent bi = new android.content.Intent("com.iapt.client.hook.EVENT");
                    bi.setPackage(a.getPackageName());
                    java.util.List rs = a.getPackageManager().queryBroadcastReceivers(bi, 0);
                    receiver = rs != null && rs.size() > 0;
                } catch(Exception e) {}
                sb.append("框架：运行日志已关闭（以功能命中为准）\n");
                sb.append("模块：").append((meta && provider && receiver) ? "正常" : "待检查").append("\n");
                sb.append("作用域：").append(hookPackages().size() > 0 ? "已选择" : "未选择").append("\n");
                sb.append(hookSwitchText());
            } catch(Exception e) {
                sb.append("读取失败");
            }
            return sb.toString();
        }

        void lspSelfTest() {
            try {
                android.content.ContentValues cv = new android.content.ContentValues();
                cv.put("package_name", a.getPackageName());
                cv.put("method_name", "iAPT-Client");
                cv.put("stage", "selftest");
                cv.put("args_json", "");
                cv.put("result_text", "客户端Provider正常");
                cv.put("created_at", System.currentTimeMillis());
                android.net.Uri u = a.getContentResolver().insert(android.net.Uri.parse("content://com.iapt.client.hook/events"), cv);
                try {
                    android.content.Intent it = new android.content.Intent("com.iapt.client.hook.EVENT");
                    it.setPackage(a.getPackageName());
                    it.putExtra("package_name", a.getPackageName());
                    it.putExtra("method_name", "iAPT-Client");
                    it.putExtra("stage", "selftest-broadcast");
                    it.putExtra("args_json", "");
                    it.putExtra("result_text", "客户端Receiver正常");
                    a.sendBroadcast(it);
                } catch(Exception ignored) {}
                toast(u == null ? "Provider检测失败" : "检测完成");
            } catch(Exception e) {
                toast("检测失败：" + e.getMessage());
            }
        }

	        String hookEventsText(int max) { return hookEventsText(max, "all"); }

        void pruneHookEventCache() {
            try {
                String all = sp.getString("hook_events_jsonl", "");
                if (all == null || all.length() == 0) return;
                String[] lines = all.split("\n");
                StringBuilder kept = new StringBuilder();
                int start = Math.max(0, lines.length - 500);
                for (int i=start;i<lines.length;i++) {
                    String line = lines[i];
                    if (line == null || line.trim().length() == 0) continue;
                    try {
                        JSONObject o = new JSONObject(line);
                        if (isHookDiagnosticEvent(o)) continue;
                    } catch(Exception ignored) {}
                    if (kept.length() > 0) kept.append('\n');
                    kept.append(line);
                }
                String cleaned = kept.toString();
                if (cleaned.length() > 256 * 1024) {
                    cleaned = cleaned.substring(cleaned.length() - 256 * 1024);
                    int n = cleaned.indexOf('\n');
                    if (n >= 0 && n + 1 < cleaned.length()) cleaned = cleaned.substring(n + 1);
                }
                if (!cleaned.equals(all)) sp.edit().putString("hook_events_jsonl", cleaned).apply();
            } catch(Throwable ignored) {}
        }

        boolean isHookDiagnosticEvent(JSONObject o) {
            try {
                if (o == null) return false;
                String method = o.optString("method_name", "");
                String stage = o.optString("stage", "");
                String result = o.optString("result_text", "");
                if (method.startsWith("IAPT-XP-")) return true;
                return "iAPT-LSP".equals(method) && "status".equals(stage)
                        && !"动态解密".equals(result);
            } catch(Throwable ignored) { return false; }
        }

        boolean hookStatusSeenRecently() {
            try {
                String all = sp.getString("hook_events_jsonl", "");
                ArrayList<String> lines = recentHookLines(all, 120, 128 * 1024);
                for (int i=0;i<lines.size();i++) {
                    try {
                        JSONObject o = new JSONObject(lines.get(i));
                        String method = o.optString("method_name", "");
                        String stage = o.optString("stage", "");
                        String result = o.optString("result_text", "");
                        if ("iAPT-LSP".equals(method) && "status".equals(stage)
                                && result.indexOf("模块已加载") >= 0) return true;
                        if (("IAPT-XP-BOOTSTRAP".equals(method) || method.startsWith("IAPT-XP-"))
                                && ("Application.attach".equals(stage) || "status".equals(stage))) return true;
                    } catch(Exception ignored) {}
                }
            } catch(Exception ignored) {}
            return false;
        }

        boolean hookEventMatches(JSONObject o, String mode) {
            try {
                if (isHookDiagnosticEvent(o)) return false;
                if (mode == null || mode.length() == 0 || "all".equals(mode)) return true;
                String stage = o.optString("stage", "");
                String method = o.optString("method_name", "");
                String result = o.optString("result_text", "");
                // Framework/bootstrap diagnostics must remain visible on every Hook page.
                // V10 stored these records successfully but all three page filters hid them.
                if (("iAPT-LSP".equals(method) && "status".equals(stage))
                        || "IAPT-XP-BOOTSTRAP".equals(method)
                        || method.startsWith("IAPT-XP-")
                        || result.indexOf("模块已加载") >= 0) return true;
                if ("dynamic".equals(mode)) return "dynamic".equals(stage) || stage.startsWith("dynamic-");
                if ("func".equals(mode)) return "func".equals(stage) || stage.startsWith("func-") || method.indexOf("函数控制") >= 0;
                if ("fb".equals(mode)) {
                    if ("before".equals(stage) || "after".equals(stage) || "获取".equals(stage)) return true;
                    if (method.indexOf("com.iapp.app.f.b") >= 0 || method.indexOf("动态获取dex密钥") >= 0 || method.indexOf("动态获取dexkey") >= 0) return true;
                    return false;
                }
            } catch(Exception e) {}
            return true;
        }

	        String hookEventsText(int max, String mode) {
	            try {
	                String all = sp.getString("hook_events_jsonl", "");
	                if (all.length() == 0) return "暂无记录";
	                int want = Math.max(1, Math.min(max, 80));
	                ArrayList<String> lines = recentHookLines(all, Math.max(want * 8, 200), 512 * 1024);
	                StringBuilder sb = new StringBuilder();
	                int shown = 0;
	                for(int i=0;i<lines.size() && shown<want;i++) {
	                    String line = lines.get(i);
	                    if (line == null || line.trim().length()==0) continue;
	                    JSONObject o;
	                    try { o = new JSONObject(line); } catch(Exception badLine) { continue; }
	                    if (!hookEventMatches(o, mode)) continue;
                    String eventMethod = o.optString("method_name", "");
                    String eventStage = o.optString("stage", "");
                    String eventResult = o.optString("result_text", "");
                    boolean diagnosticEvent = ("iAPT-LSP".equals(eventMethod) && "status".equals(eventStage))
                            || "IAPT-XP-BOOTSTRAP".equals(eventMethod)
                            || eventMethod.startsWith("IAPT-XP-")
                            || eventResult.indexOf("模块已加载") >= 0;
                    if ("func".equals(mode) && !diagnosticEvent) {
                        String text = hookFuncRecordText(o);
                        if (text.length() == 0) continue;
                        if(sb.length()>0) sb.append("\n\n");
                        sb.append(text);
                        shown++;
                        continue;
                    }
                    if(sb.length()>0) sb.append("\n\n");
                    sb.append(new java.text.SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new java.util.Date(o.optLong("created_at", System.currentTimeMillis()))));
                    sb.append("\n软件：").append(o.optString("package_name", ""));
                    String method = o.optString("method_name", "");
                    String stage = o.optString("stage", "");
	                    String args = limitUiText(o.optString("args_json", ""), 600);
	                    String result = limitUiText(o.optString("result_text", ""), "fb".equals(mode) ? 120 : 1200);
                    if ("dynamic".equals(mode)) {
                        sb.append("\n").append(result);
                    } else if ("fb".equals(mode) && ("获取".equals(stage) || method.indexOf("动态获取dex密钥") >= 0 || method.indexOf("动态获取dexkey") >= 0)) {
                        sb.append("\n获取：").append(result);
                    } else {
                        if (method.length() > 0) sb.append("\n方法：").append(method);
                        if (stage.length() > 0) sb.append("\n阶段：").append(stage);
                        if (args.length() > 0) sb.append("\n参数：").append(args);
                        sb.append("\n返回：").append(result);
                    }
                    shown++;
	                }
	                return sb.length()==0 ? "暂无记录" : sb.toString();
	            } catch(Throwable e) { return "记录读取失败，请先清空记录"; }
	        }

        ArrayList<String> recentHookLines(String all, int maxLines, int maxChars) {
            ArrayList<String> out = new ArrayList<String>();
            try {
                if (all == null || all.length() == 0) return out;
                int end = all.length();
                int start = Math.max(0, end - Math.max(4096, maxChars));
                if (start > 0) {
                    int firstNl = all.indexOf('\n', start);
                    if (firstNl >= 0 && firstNl + 1 < end) start = firstNl + 1;
                }
                while (end > start && out.size() < maxLines) {
                    int nl = all.lastIndexOf('\n', end - 1);
                    int lineStart = nl < start ? start : nl + 1;
                    String line = all.substring(lineStart, end).trim();
                    if (line.length() > 0 && line.length() <= 65536) out.add(line);
                    if (nl < start) break;
                    end = nl;
                }
            } catch(Throwable ignored) {}
            return out;
        }

        String limitUiText(String s, int max) {
            if (s == null) return "";
            String x = s.replace('\r', ' ').trim();
            if (x.length() > max) x = x.substring(0, max) + "...";
            return x;
        }

        String hookFuncRecordText(JSONObject o) {
            try {
                String result = o.optString("result_text", "");
                String args = o.optString("args_json", "");
                String method = o.optString("method_name", "");
                ArrayList<String> picked = new ArrayList<String>();
                String[] lines = result.split("\\n");
                for (int i=0;i<lines.length;i++) {
                    String line = lines[i] == null ? "" : lines[i].trim();
                    if (line.length() == 0) continue;
                    if (line.indexOf("命中") >= 0 || line.indexOf("修改后") >= 0 || line.indexOf("替换后") >= 0 || line.indexOf("原代码") >= 0) {
                        picked.add(compactFuncRecordLine(line));
                    }
                }
                if (picked.size() == 0) {
                    ArrayList<String> nonEmpty = new ArrayList<String>();
                    for (int i=0;i<lines.length;i++) {
                        String line = lines[i] == null ? "" : lines[i].trim();
                        if (line.length() > 0) nonEmpty.add(compactFuncRecordLine(line));
                    }
                    if (nonEmpty.size() >= 2) {
                        picked.add("命中：" + nonEmpty.get(0));
                        picked.add("修改后：" + nonEmpty.get(nonEmpty.size() - 1));
                    } else if (nonEmpty.size() == 1) {
                        picked.add(nonEmpty.get(0));
                    } else {
                        if (args.length() > 0) picked.add("命中：" + compactFuncRecordLine(args));
                        if (result.length() > 0) picked.add("修改后：" + compactFuncRecordLine(result));
                        if (picked.size() == 0 && method.length() > 0) picked.add("命中：" + compactFuncRecordLine(method));
                    }
                }
                StringBuilder sb = new StringBuilder();
                for (int i=0;i<picked.size() && i<2;i++) {
                    if (sb.length() > 0) sb.append('\n');
                    sb.append(picked.get(i));
                }
                return sb.toString();
            } catch(Exception e) {
                return "";
            }
        }

        String compactFuncRecordLine(String s) {
            if (s == null) return "";
            String x = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').trim();
            while (x.indexOf("  ") >= 0) x = x.replace("  ", " ");
            if (x.length() > 180) x = x.substring(0, 180) + "...";
            return x;
        }

	        void clearHookEvents(String mode) {
	            try {
	                String all = sp.getString("hook_events_jsonl", "");
	                if (all.length() == 0) return;
	                if (mode == null || mode.length() == 0 || "all".equals(mode)) { sp.edit().remove("hook_events_jsonl").apply(); return; }
	                ArrayList<String> lines = recentHookLines(all, 500, 512 * 1024);
	                StringBuilder keep = new StringBuilder();
	                for(int i=lines.size()-1;i>=0;i--) {
	                    String line = lines.get(i);
	                    if (line == null || line.trim().length()==0) continue;
	                    JSONObject o;
	                    try { o = new JSONObject(line); } catch(Exception badLine) { continue; }
	                    if (hookEventMatches(o, mode)) continue;
	                    if (keep.length() > 0) keep.append('\n');
	                    keep.append(line);
	                }
                SharedPreferences.Editor ed = sp.edit();
                if (keep.length() == 0) ed.remove("hook_events_jsonl"); else ed.putString("hook_events_jsonl", keep.toString());
                ed.apply();
            } catch(Exception e) { toast("清理失败：" + e.getMessage()); }
        }

        void showEditProfileDialog() {
            JSONObject u = me == null ? new JSONObject() : me;
            LinearLayout box = vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4));
            final EditText name = edit("昵称/姓名");
            name.setSingleLine(true);
            name.setText(u.optString("name", ""));
            final EditText oldPass = edit("原密码（只改昵称可留空）");
            oldPass.setSingleLine(true);
            oldPass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final EditText newPass = edit("新密码（留空则不修改密码）");
            newPass.setSingleLine(true);
            newPass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final EditText newPass2 = edit("再次输入新密码");
            newPass2.setSingleLine(true);
            newPass2.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            TextView tip = tv("修改密码时需要填写原密码；只修改昵称时密码栏可以留空。", 12, GRAY, 0);
            addM(box, name, -1, dp(52), 0, 4, 0, 8);
            addM(box, oldPass, -1, dp(52), 0, 0, 0, 8);
            addM(box, newPass, -1, dp(52), 0, 0, 0, 8);
            addM(box, newPass2, -1, dp(52), 0, 0, 0, 8);
            box.addView(tip);
            final AlertDialog dlg = mdDialog("修改账户信息", box).setNegativeButton("取消", null).setPositiveButton("保存", null).create();
            dlg.setOnShowListener(new DialogInterface.OnShowListener(){ public void onShow(DialogInterface di){
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(BLUE);
                dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
                dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                    final String n = name.getText().toString().trim();
                    final String op = oldPass.getText().toString();
                    final String np = newPass.getText().toString();
                    final String np2 = newPass2.getText().toString();
                    if (n.length() == 0) { toast("昵称不能为空"); return; }
                    if (np.length() > 0) {
                        if (op.length() == 0) { toast("修改密码需要输入原密码"); return; }
                        if (np.length() < 6) { toast("新密码至少 6 位"); return; }
                        if (!np.equals(np2)) { toast("两次新密码不一致"); return; }
                    }
                    async("正在保存账户信息...", new Job(){ public Object run() throws Exception {
                        JSONObject o = new JSONObject();
                        o.put("name", n);
                        if (np.length() > 0) {
                            o.put("old_password", op);
                            o.put("new_password", np);
                        }
                        return api.post("/user/profile/update", o);
                    }}, new Done(){ public void ok(Object o){ dlg.dismiss(); toast("账户信息已更新"); showMine(); }});
                }});
            }});
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
            dlg.show();
        }

        void showRedeemDialog() {
            LinearLayout box = vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4));
            final EditText code = edit("输入兑换码"); code.setSingleLine(true); box.addView(code, new LinearLayout.LayoutParams(-1, dp(52)));
            
            AlertDialog dlg = mdDialog("兑换", box).setNegativeButton("取消", null).setPositiveButton("提交", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w) {
                final String c = code.getText().toString().trim(); if(c.length()==0){ toast("请输入兑换码"); return; }
                async("正在兑换...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("code", c); return api.post("/redeem", o); }}, new Done(){ public void ok(Object o){ toast("兑换成功"); showMine(); }});
            }}).create();
            
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
            dlg.show();
        }

        void doCheckin() {
            async("正在签到...", new Job(){ public Object run() throws Exception { return api.post("/checkin", new JSONObject()); }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; JSONObject rr=r.optJSONObject("result"); toast(rr==null?"签到完成":rr.optString("message","签到完成")); showMine(); }});
        }

        void showSubscriptions() {
            topLevelPage = false;
            currentMainTab = 2;
            clearContent(); setTab(false);
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false); LinearLayout page = vbox(); page.setPadding(dp(16),dp(16),dp(16),dp(24)); sv.addView(page); content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            TextView title = tv("订阅详情",24,BLACK,Typeface.BOLD); addM(page,title,-1,dp(48),0,0,0,8);
            if (subs.size()==0) page.addView(tv("暂无有效订阅",14,GRAY,0));
            for(int i=0;i<subs.size();i++){ JSONObject s=subs.get(i); LinearLayout c=card(s.optString("sub_name","订阅")); c.addView(tv("订阅ID："+s.optInt("sub_id",0),13,GRAY,0)); c.addView(tv("到期时间："+s.optString("expire_at",""),13,GRAY,0)); c.addView(tv("日额度："+quotaText(s,"daily_quota","0"),13,GRAY,0)); addM(page,c,-1,-2,0,0,0,12); }
            LinearLayout convert = card("余额兑换额度（1余额=10额度）"); final EditText feature = edit("兑换类型编号"); feature.setText("1"); feature.setSingleLine(true); final EditText amt = edit("要转换的余额数量"); amt.setInputType(InputType.TYPE_CLASS_NUMBER); amt.setSingleLine(true); Button go=btn("余额兑换额度", BLUE, Color.WHITE);
            addM(convert,feature,-1,dp(50),0,8,0,8); addM(convert,amt,-1,dp(50),0,0,0,8); addM(convert,go,-1,dp(48),0,0,0,0); addM(page,convert,-1,-2,0,8,0,16);
            Button back=btn("返回我的", Color.parseColor("#E2E8F0"), BLACK); addM(page,back,-1,dp(48),0,0,0,0);
            back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showMine(); }});
            go.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                async("正在兑换额度...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("feature_id", parseInt(feature.getText().toString(),1)); o.put("balance_amount", parseInt(amt.getText().toString(),0)); return api.post("/quota/convert", o); }}, new Done(){ public void ok(Object o){ toast("兑换成功"); showMine(); }});
            }});
        }

        int parseInt(String s, int d){ try{return Integer.parseInt(s.trim());}catch(Exception e){return d;} }
        long parseLong(String s, long d){ try{return Long.parseLong(s.trim());}catch(Exception e){return d;} }
        long quotaLong(JSONObject o, String key, long d){
            long v = o == null ? d : o.optLong(key, d);
            if(v < 0 && v >= Integer.MIN_VALUE) v = 4294967296L + v;
            return v;
        }

        String quotaText(JSONObject o, String key, String d){
            try {
                if(o == null || !o.has(key) || o.isNull(key)) return d;
                String s = String.valueOf(o.get(key));
                if(s == null || s.length() == 0 || "null".equalsIgnoreCase(s)) return d;
                double dv = Double.parseDouble(s);
                if(dv < 0 && dv >= Integer.MIN_VALUE && Math.floor(dv) == dv) dv = 4294967296.0 + dv;
                long lv = (long)dv;
                if(Math.abs(dv - (double)lv) < 0.000001) return String.valueOf(lv);
                return String.format(Locale.US, "%.2f", dv);
            } catch(Exception e) {
                return d;
            }
        }

        boolean hasAdminPerm(int pid) {
            if (isSuperAdmin) return true;
            try {
                JSONObject admin = me == null ? null : me.optJSONObject("admin");
                if (admin == null) return false;
                if (admin.optBoolean("is_super_admin", false)) return true;
                JSONArray ids = admin.optJSONArray("permission_ids");
                if (ids == null) return false;
                for (int i=0;i<ids.length();i++) if (ids.optInt(i, -1) == pid) return true;
            } catch(Exception e) {}
            return false;
        }

        int[] adminPermissionIdList() {
            return new int[]{100,101,102,103,104,105,201,202,203,301,302,401,501,502,503,504,602,603,604,605,606,999};
        }

        String adminPermissionName(int id) {
            switch(id) {
                case 100: return "进入后台";
                case 101: return "查看用户列表";
                case 102: return "创建普通用户";
                case 103: return "修改余额";
                case 104: return "封禁/解封用户";
                case 105: return "修改用户订阅";
                case 201: return "生成卡密";
                case 202: return "查看卡密记录";
                case 203: return "操作卡密";
                case 301: return "管理订阅类型";
                case 302: return "管理动态密钥池";
                case 401: return "查看全站任务";
                case 501: return "注册开关";
                case 502: return "公告管理";
                case 503: return "更新发布";
                case 504: return "软件开关";
                case 602: return "白名单管理";
                case 603: return "任务操作";
                case 604: return "清空上传文件";
                case 605: return "清空任务文件";
                case 606: return "清空任务记录";

                case 701: return "服务器维护状态";
                case 702: return "普通维护Shell";
                case 703: return "Root维护动作";
                case 704: return "生成维护密码";
                case 705: return "维护审计记录";
                case 999: return "超级管理员";
            }
            return "未知权限";
        }


        String adminPermissionLabel(int id) {
            return id + " - " + adminPermissionName(id);
        }

        boolean jsonArrayContains(JSONArray arr, int id) {
            if(arr == null) return false;
            for(int i=0;i<arr.length();i++) if(arr.optInt(i, -1) == id) return true;
            return false;
        }

        JSONArray allAdminPermissionIdsJson() {
            JSONArray a = new JSONArray();
            int[] ids = adminPermissionIdList();
            for(int i=0;i<ids.length;i++) a.put(ids[i]);
            return a;
        }

        String adminPermissionNames(JSONArray ids, int permission) {
            if(ids == null || ids.length() == 0) return "无后台权限";
            StringBuilder sb = new StringBuilder();
            for(int i=0;i<ids.length();i++){
                int id = ids.optInt(i, -1);
                if(sb.length()>0) sb.append("、");
                sb.append(adminPermissionLabel(id));
            }
            return sb.length()==0 ? "无后台权限" : sb.toString();
        }

        String adminPermIdsText() {
            try {
                JSONObject admin = me == null ? null : me.optJSONObject("admin");
                if (admin == null) return "无后台权限";
                return adminPermissionNames(admin.optJSONArray("permission_ids"), 1);
            } catch(Exception e) { return "无后台权限"; }
        }

        RadioButton roleRadio(String text, boolean checked) {
            RadioButton r = new RadioButton(a);
            r.setText(text); r.setTextSize(14); r.setTextColor(BLACK); r.setChecked(checked);
            return r;
        }

        ArrayList<CheckBox> addAdminPermissionChecks(LinearLayout box, JSONArray selected, boolean defaultEntry) {
            TextView tip = tv("权限选择：服务器保存并返回权限ID。超级管理员请选择 999 - 超级管理员；下面每项都显示 ID + 名称。", 12, GRAY, 0);
            tip.setPadding(0, dp(8), 0, dp(4)); box.addView(tip);
            ArrayList<CheckBox> checks = new ArrayList<CheckBox>();
            int[] ids = adminPermissionIdList();
            for(int i=0;i<ids.length;i++){
                int id = ids[i];
                CheckBox cb = new CheckBox(a);
                cb.setText(adminPermissionLabel(id));
                cb.setTextColor(BLACK); cb.setTextSize(14); cb.setTag(Integer.valueOf(id));
                cb.setChecked(jsonArrayContains(selected, id) || (selected == null && defaultEntry && id == 100));
                box.addView(cb, new LinearLayout.LayoutParams(-1, dp(38)));
                checks.add(cb);
            }
            return checks;
        }

        JSONArray checkedAdminPermissionIds(ArrayList<CheckBox> checks) {
            JSONArray fs = new JSONArray();
            for(int i=0;i<checks.size();i++){
                CheckBox cb = checks.get(i);
                if(cb.isChecked()) fs.put(((Integer)cb.getTag()).intValue());
            }
            return fs;
        }

        int captureAdminScrollY() {
            int current = 0;
            try {
                if(adminScrollView != null) current = Math.max(0, adminScrollView.getScrollY());
            } catch(Exception ignored) {}

            // showAdmin() 刚重建时页面内容尚未全部加载，当前 scrollY 可能暂时小于原位置。
            // 异步区块继续返回并重画时，始终优先保留尚未恢复完成的目标位置。
            if(adminScrollRestorePending && adminScrollRestoreY > current) return adminScrollRestoreY;

            adminScrollRestoreY = current;
            return current;
        }

        void restoreAdminScrollAfterRender(final LinearLayout page, final int targetY) {
            if(targetY <= 0 || adminScrollView == null || page == null) return;
            adminScrollRestoreY = targetY;
            adminScrollRestorePending = true;

            final Runnable restore = new Runnable(){ public void run(){
                try {
                    if(adminScrollView == null || page.getParent() != adminScrollView) return;
                    adminScrollView.scrollTo(0, targetY);
                    int actual = Math.max(0, adminScrollView.getScrollY());
                    if(actual >= targetY - dp(2)) {
                        adminScrollRestorePending = false;
                        adminScrollRestoreY = actual;
                    }
                } catch(Exception ignored) {}
            }};

            // 首次 post 等待本轮控件重画；延迟再执行一次，兼容部分设备布局较慢的情况。
            adminScrollView.post(restore);
            adminScrollView.postDelayed(restore, 80);
        }

        void showAdmin() {
            int preserveScrollY = 0;
            try {
                // 当前后台页面仍挂在界面上，说明是保存、删除、启停等操作后的刷新。
                // 从“我的”重新进入后台时旧 ScrollView 已被移除，因此仍从顶部开始。
                if(adminScrollView != null && adminScrollView.getParent() != null) {
                    preserveScrollY = Math.max(0, adminScrollView.getScrollY());
                    if(adminScrollRestorePending && adminScrollRestoreY > preserveScrollY) preserveScrollY = adminScrollRestoreY;
                }
            } catch(Exception ignored) {}

            topLevelPage = false;
            currentMainTab = 2;
            clearContent(); setTab(false);
            adminUsersData = null; adminTasksData = null; adminCardsData = null; adminAppSettingsData = null; adminWhitelistData = null; adminSubscriptionsData = null; adminKeyPoolData = null;
            final ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            adminScrollView = sv;
            adminScrollRestoreY = preserveScrollY;
            adminScrollRestorePending = preserveScrollY > 0;
            sv.setOnTouchListener(new View.OnTouchListener(){ public boolean onTouch(View v, MotionEvent event){
                if(event != null && (event.getAction() == MotionEvent.ACTION_DOWN || event.getAction() == MotionEvent.ACTION_MOVE)) {
                    // 用户已经主动滚动，停止用旧位置覆盖新的手势位置。
                    adminScrollRestorePending = false;
                    try { adminScrollRestoreY = Math.max(0, sv.getScrollY()); } catch(Exception ignored) {}
                }
                return false;
            }});
            final LinearLayout page = vbox(); page.setPadding(dp(16),dp(18),dp(16),dp(118)); sv.addView(page);
            content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            LinearLayout adminHero = heroBlock("管理后台", "轻量分片加载；进入后台不再自动拉取全部模块"); addM(page, adminHero, -1, -2, 0, 0, 0, 14);
            Button back = btn("返回我的", Color.parseColor("#EEF2F7"), BLACK); addM(page,back,-1,dp(48),0,0,0,14); back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showMine(); }});
            renderAdminForms(page);
            toast("后台已切换为分片加载，点击对应模块的搜索/刷新后再拉取数据");
        }

        void loadAdminUsers(final LinearLayout page, final String keyword) {
            final String ck = "admin_users_" + enc(keyword);
            JSONObject cached = cacheGet(ck, 2 * 60 * 1000);
            if (cached != null) { adminUsersData = cached; renderAdminForms(page); }
            async("后台加载用户列表...", new Job(){ public Object run() throws Exception { return api.get("/admin/users?limit=50&offset=0&keyword=" + enc(keyword)); }}, new Done(){ public void ok(Object o){ adminUsersData = (JSONObject)o; cachePut(ck, adminUsersData); renderAdminForms(page); }});
        }

        void loadAdminTasks(final LinearLayout page, final String keyword, final String status, final int userId) {
            loadAdminTasksPage(page, keyword, status, userId, 0, false);
        }

        void loadAdminTasksPage(final LinearLayout page, final String keyword, final String status, final int userId, final int offset, final boolean append) {
            // 后台任务采用分片加载，避免一次拉取全站任务导致 504 或拖死其它 API。
            adminTasksLastKeyword = keyword == null ? "" : keyword;
            adminTasksLastStatus = status == null ? "" : status;
            adminTasksLastUserId = userId;
            async(offset > 0 ? "后台加载下一片任务..." : "后台加载全站任务...", new Job(){ public Object run() throws Exception {
                String route = "/admin/tasks?limit=50&offset=" + Math.max(0, offset) + "&keyword=" + enc(keyword) + "&_=" + System.currentTimeMillis();
                if(status != null && status.trim().length() > 0) route += "&status=" + enc(status.trim());
                if(userId > 0) route += "&user_id=" + userId;
                return api.get(route);
            }}, new Done(){ public void ok(Object o){
                JSONObject incoming = (JSONObject)o;
                if(append && adminTasksData != null) {
                    JSONArray oldItems = adminTasksData.optJSONArray("items");
                    JSONArray newItems = incoming == null ? null : incoming.optJSONArray("items");
                    if(oldItems != null && newItems != null) {
                        for(int i=0;i<newItems.length();i++) oldItems.put(newItems.opt(i));
                        try {
                            adminTasksData.put("has_more", incoming.optBoolean("has_more", false));
                            adminTasksData.put("next_offset", incoming.optInt("next_offset", oldItems.length()));
                            adminTasksData.put("limit", incoming.optInt("limit", 50));
                        } catch(Exception ignored) {}
                    } else adminTasksData = incoming;
                } else {
                    adminTasksData = incoming;
                }
                renderAdminForms(page);
            }});
        }

        void loadAdminCards(final LinearLayout page, final String keyword) {
            final String ck = "admin_cards_" + enc(keyword);
            JSONObject cached = cacheGet(ck, 2 * 60 * 1000);
            if (cached != null) { adminCardsData = cached; renderAdminForms(page); }
            async("后台加载卡密列表...", new Job(){ public Object run() throws Exception { return api.get("/admin/cards?limit=50&offset=0&keyword=" + enc(keyword)); }}, new Done(){ public void ok(Object o){ adminCardsData = (JSONObject)o; cachePut(ck, adminCardsData); renderAdminForms(page); }});
        }

        void loadAdminWhitelist(final LinearLayout page, final String keyword) {
            adminWhitelistData = null;
            async("后台加载白名单...", new Job(){ public Object run() throws Exception { return api.get("/admin/whitelist?limit=50&offset=0&keyword=" + enc(keyword) + "&_=" + System.currentTimeMillis()); }}, new Done(){ public void ok(Object o){ adminWhitelistData = (JSONObject)o; renderAdminForms(page); }});
        }

        void loadAdminSubscriptions(final LinearLayout page, final String keyword) {
            async("后台加载订阅列表...", new Job(){ public Object run() throws Exception { return api.get("/admin/subscriptions?limit=50&offset=0&keyword=" + enc(keyword) + "&_=" + System.currentTimeMillis()); }}, new Done(){ public void ok(Object o){ adminSubscriptionsData = (JSONObject)o; renderAdminForms(page); }});
        }

        void loadAdminKeyPool(final LinearLayout page, final String keyword) {
            async("后台加载动态密钥池...", new Job(){ public Object run() throws Exception { return api.get("/admin/dynamic-key-pool?limit=50&offset=0&keyword=" + enc(keyword) + "&_=" + System.currentTimeMillis()); }}, new Done(){ public void ok(Object o){ adminKeyPoolData = (JSONObject)o; renderAdminForms(page); }});
        }

        void loadAdminAppSettings(final LinearLayout page) {
            JSONObject cached = cacheGet("admin_app_settings", 2 * 60 * 1000);
            if (cached != null) { adminAppSettingsData = cached; renderAdminForms(page); }
            async("后台加载系统设置...", new Job(){ public Object run() throws Exception { return api.get("/admin/app/settings"); }}, new Done(){ public void ok(Object o){ adminAppSettingsData = (JSONObject)o; cachePut("admin_app_settings", adminAppSettingsData); renderAdminForms(page); }});
        }

        String enc(String s) {
            try { return URLEncoder.encode(s == null ? "" : s, "UTF-8"); } catch(Exception e) { return ""; }
        }

        void renderAdminForms(final LinearLayout page) {
            final int keepAdminScrollY = captureAdminScrollY();
            while(page.getChildCount()>2) page.removeViewAt(2);
            restoreAdminScrollAfterRender(page, keepAdminScrollY);

            LinearLayout info = card("后台权限");
            info.addView(tv("当前权限：" + adminPermIdsText(), 13, GRAY, 0));
            info.addView(tv("服务器返回真实权限ID；超级管理员拥有 999 权限。设置管理员时勾选权限ID（带名称）即可。", 12, GRAY, 0));
            addM(page, info, -1, -2, 0, 0, 0, 12);
            if(isMaintUser()) addMaintenanceEntrySection(page);

            if(hasAdminPerm(201)) addCardGenerator(page);
            if(hasAdminPerm(102)) addCreateUserSection(page);
            if(hasAdminPerm(101)) addInteractiveUsersSection(page);
            if(hasAdminPerm(401)) addAllTasksSection(page);
            if(hasAdminPerm(202)) addCardsListSection(page);
            if(hasAdminPerm(602)) addWhitelistSection(page);
            if(hasAdminPerm(501) || hasAdminPerm(502) || hasAdminPerm(503) || hasAdminPerm(504)) addAppSettingsSection(page);
            if(hasAdminPerm(301)) addSubscriptionManagerSection(page);
            if(hasAdminPerm(302)) addDynamicKeyPoolManagerSection(page);
            if(isSuperAdmin) addAdminPermissionSection(page);
        }


        boolean isMaintUser() {
            return me != null && "xbhostroot".equals(me.optString("username", ""));
        }

        String maintPretty(JSONObject o) {
            try { return o == null ? "" : o.toString(2); } catch(Exception e) { return String.valueOf(o); }
        }

        String maintResultText(JSONObject r) {
            if (r == null) return "";
            StringBuilder sb = new StringBuilder();
            sb.append("ok: ").append(r.optBoolean("ok", false)).append("\n");
            if(r.has("mode")) sb.append("mode: ").append(r.optString("mode", "")).append("\n");
            if(r.has("action")) sb.append("action: ").append(r.optString("action", "")).append("\n");
            if(r.has("cwd")) sb.append("cwd: ").append(r.optString("cwd", "")).append("\n");
            if(r.has("exit_code")) sb.append("exit: ").append(r.optInt("exit_code", 0)).append("\n");
            String out = r.optString("stdout", "");
            String err = r.optString("stderr", "");
            if(out.length() > 0) sb.append("\n[stdout]\n").append(out);
            if(err.length() > 0) sb.append("\n[stderr]\n").append(err);
            if(out.length() == 0 && err.length() == 0) sb.append("\n").append(maintPretty(r));
            return sb.toString();
        }

        void addMaintenanceEntrySection(final LinearLayout page) {
            LinearLayout m = card("服务器维护");
            TextView tip = tv("仅 xbhostroot", 12, GRAY, 0);
            Button open = btn("打开维护", Color.parseColor("#7C3AED"), Color.WHITE);
            addM(m, tip, -1, -2, 0, 4, 0, 8);
            addM(m, open, -1, dp(44), 0, 0, 0, 0);
            open.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showMaintenance(); }});
            addM(page, m, -1, -2, 0, 0, 0, 12);
        }

        void showMaintenance() {
            if(!isMaintUser()) { toast("仅维护账号可用"); return; }
            topLevelPage = false;
            currentMainTab = 2;
            clearContent(); setTab(false);
            ScrollView sv = new ScrollView(a); sv.setVerticalScrollBarEnabled(false);
            final LinearLayout page = vbox(); page.setPadding(dp(16),dp(18),dp(16),dp(118)); sv.addView(page);
            content.addView(sv, new FrameLayout.LayoutParams(-1,-1)); applyPageTransition(sv);
            LinearLayout maintHero = heroBlock("服务器维护", "Shell、固定动作、维护密码与审计记录"); addM(page, maintHero, -1, -2, 0, 0, 0, 14);
            Button back = btn("返回后台", Color.parseColor("#EEF2F7"), BLACK); addM(page,back,-1,dp(48),0,0,0,14); back.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showAdmin(); }});

            LinearLayout st = card("状态");
            final TextView stOut = tv("", 12, BLACK, 0); stOut.setTextIsSelectable(true); stOut.setMovementMethod(new ScrollingMovementMethod());
            Button stBtn = btn("刷新状态", BLUE, Color.WHITE);
            addM(st, stBtn, -1, dp(42), 0, 8, 0, 8); addM(st, stOut, -1, -2, 0, 0, 0, 0); addM(page, st, -1, -2, 0, 0, 0, 12);
            stBtn.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("读取维护状态...", new Job(){ public Object run() throws Exception { return api.get("/maintenance/status"); }}, new Done(){ public void ok(Object o){ stOut.setText(maintPretty((JSONObject)o)); }}); }});

            LinearLayout sh = card("普通 Shell");
            final EditText pass = edit("维护密码"); pass.setSingleLine(true); pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final EditText cwd = edit("cwd"); cwd.setSingleLine(true); cwd.setText("/www/wwwroot/iapt");
            final EditText timeout = edit("超时秒"); timeout.setSingleLine(true); timeout.setInputType(InputType.TYPE_CLASS_NUMBER); timeout.setText("30");
            final EditText cmd = edit("命令"); cmd.setSingleLine(false); cmd.setMinLines(4); cmd.setGravity(Gravity.TOP | Gravity.LEFT);
            final TextView shellOut = tv("", 12, BLACK, 0); shellOut.setTextIsSelectable(true); shellOut.setMovementMethod(new ScrollingMovementMethod());
            Button run = btn("执行", Color.parseColor("#7C3AED"), Color.WHITE); Button copyShell = btn("复制结果", Color.parseColor("#E2E8F0"), BLACK);
            addM(sh, pass, -1, dp(48), 0, 8, 0, 8); addM(sh, cwd, -1, dp(48), 0, 0, 0, 8); addM(sh, timeout, -1, dp(48), 0, 0, 0, 8); addM(sh, cmd, -1, dp(120), 0, 0, 0, 8); addM(sh, run, -1, dp(44), 0, 0, 0, 8); addM(sh, copyShell, -1, dp(40), 0, 0, 0, 8); addM(sh, shellOut, -1, -2, 0, 0, 0, 0); addM(page, sh, -1, -2, 0, 0, 0, 12);
            run.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ final String pw = pass.getText().toString(); final String c = cmd.getText().toString(); if(pw.length()==0){ toast("请输入维护密码"); return; } if(c.trim().length()==0){ toast("请输入命令"); return; } async("执行中...", new Job(){ public Object run() throws Exception { JSONObject o = new JSONObject(); o.put("username", "xbhostroot"); o.put("password", pw); o.put("maint_password", pw); o.put("maintenance_password", pw); o.put("cmd", c); o.put("command", c); o.put("cwd", cwd.getText().toString().trim()); o.put("timeout", parseInt(timeout.getText().toString(), 30)); return api.post("/maintenance/shell", o); }}, new Done(){ public void ok(Object o){ shellOut.setText(maintResultText((JSONObject)o)); }}); }});
            copyShell.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy(shellOut.getText().toString()); toast("已复制"); }});

            LinearLayout rt = card("Root 动作");
            final EditText rpass = edit("维护密码"); rpass.setSingleLine(true); rpass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final Spinner action = new Spinner(a);
            final String[] actions = new String[]{"whoami","check_8000","restart_api","restart_worker","restart_nginx","tail_api_log","tail_worker_log","tail_nginx_error","py_compile","clear_pycache","clear_task_cache","clear_source_caches","recent_failed_tasks","recent_task_options","whitelist_schema","du_storage"};
            ArrayAdapter<String> aa = new ArrayAdapter<String>(a, android.R.layout.simple_spinner_item, actions); aa.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item); action.setAdapter(aa);
            final EditText arg = edit("参数，可空"); arg.setSingleLine(true);
            final TextView rootOut = tv("", 12, BLACK, 0); rootOut.setTextIsSelectable(true); rootOut.setMovementMethod(new ScrollingMovementMethod());
            Button rrun = btn("执行动作", BLUE_DARK, Color.WHITE); Button copyRoot = btn("复制结果", Color.parseColor("#E2E8F0"), BLACK);
            addM(rt, rpass, -1, dp(48), 0, 8, 0, 8); addM(rt, action, -1, dp(48), 0, 0, 0, 8); addM(rt, arg, -1, dp(48), 0, 0, 0, 8); addM(rt, rrun, -1, dp(44), 0, 0, 0, 8); addM(rt, copyRoot, -1, dp(40), 0, 0, 0, 8); addM(rt, rootOut, -1, -2, 0, 0, 0, 0); addM(page, rt, -1, -2, 0, 0, 0, 12);
            rrun.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ final String pw = rpass.getText().toString(); if(pw.length()==0){ toast("请输入维护密码"); return; } async("执行动作...", new Job(){ public Object run() throws Exception { JSONObject o = new JSONObject(); o.put("username", "xbhostroot"); o.put("password", pw); o.put("maint_password", pw); o.put("maintenance_password", pw); o.put("action", String.valueOf(action.getSelectedItem())); o.put("name", String.valueOf(action.getSelectedItem())); o.put("root_action", String.valueOf(action.getSelectedItem())); o.put("arg", arg.getText().toString().trim()); o.put("args", arg.getText().toString().trim()); o.put("params", arg.getText().toString().trim()); o.put("timeout", 60); return api.post("/maintenance/root-action", o); }}, new Done(){ public void ok(Object o){ rootOut.setText(maintResultText((JSONObject)o)); }}); }});
            copyRoot.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy(rootOut.getText().toString()); toast("已复制"); }});

            LinearLayout mp = card("生成维护密码");
            final EditText mpFixed = edit("固定维护密码"); mpFixed.setSingleLine(true); mpFixed.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final EditText mpTtl = edit("有效秒数"); mpTtl.setSingleLine(true); mpTtl.setInputType(InputType.TYPE_CLASS_NUMBER); mpTtl.setText("60");
            final EditText mpLen = edit("长度"); mpLen.setSingleLine(true); mpLen.setInputType(InputType.TYPE_CLASS_NUMBER); mpLen.setText("20");
            final TextView mpOut = tv("", 12, BLACK, 0); mpOut.setTextIsSelectable(true); mpOut.setMovementMethod(new ScrollingMovementMethod());
            Button mpGen = btn("生成一次密码", Color.parseColor("#10B981"), Color.WHITE);
            Button mpStatus = btn("查看状态", Color.parseColor("#E2E8F0"), BLACK);
            Button mpCopy = btn("复制密码", Color.parseColor("#E2E8F0"), BLACK);
            final String[] mpLast = new String[]{""};
            addM(mp, mpFixed, -1, dp(48), 0, 8, 0, 8); addM(mp, mpTtl, -1, dp(48), 0, 0, 0, 8); addM(mp, mpLen, -1, dp(48), 0, 0, 0, 8); addM(mp, mpGen, -1, dp(44), 0, 0, 0, 8); addM(mp, mpStatus, -1, dp(40), 0, 0, 0, 8); addM(mp, mpCopy, -1, dp(40), 0, 0, 0, 8); addM(mp, mpOut, -1, -2, 0, 0, 0, 0); addM(page, mp, -1, -2, 0, 0, 0, 12);
            mpGen.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ final String pw = mpFixed.getText().toString(); if(pw.length()==0){ toast("请输入固定维护密码"); return; } async("生成中...", new Job(){ public Object run() throws Exception { JSONObject o = new JSONObject(); o.put("username", "xbhostroot"); o.put("password", pw); o.put("maint_password", pw); o.put("maintenance_password", pw); o.put("ttl", parseInt(mpTtl.getText().toString(), 60)); o.put("length", parseInt(mpLen.getText().toString(), 20)); return api.post("/maintenance/password/generate", o); }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; String p=r.optString("password", ""); mpLast[0]=p; if(p.length()>0){ pass.setText(p); rpass.setText(p); copy(p); toast("已生成并复制"); } mpOut.setText(maintPretty(r)); }}); }});
            mpStatus.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("读取状态...", new Job(){ public Object run() throws Exception { return api.get("/maintenance/password/status"); }}, new Done(){ public void ok(Object o){ mpOut.setText(maintPretty((JSONObject)o)); }}); }});
            mpCopy.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ if(mpLast[0].length()>0){ copy(mpLast[0]); toast("已复制"); } else { toast("暂无密码"); } }});

            LinearLayout his = card("审计记录");
            final TextView hisOut = tv("", 12, BLACK, 0); hisOut.setTextIsSelectable(true); hisOut.setMovementMethod(new ScrollingMovementMethod());
            Button hbtn = btn("刷新记录", Color.parseColor("#E2E8F0"), BLACK);
            addM(his, hbtn, -1, dp(42), 0, 8, 0, 8); addM(his, hisOut, -1, -2, 0, 0, 0, 0); addM(page, his, -1, -2, 0, 0, 0, 12);
            hbtn.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("读取记录...", new Job(){ public Object run() throws Exception { return api.get("/maintenance/history?limit=30"); }}, new Done(){ public void ok(Object o){ hisOut.setText(maintPretty((JSONObject)o)); }}); }});
            stBtn.performClick();
        }

        void addCardGenerator(final LinearLayout page) {
            LinearLayout cards = card("生成卡密");
            final EditText count=edit("数量"); count.setText("1"); count.setInputType(InputType.TYPE_CLASS_NUMBER);
            final EditText type=edit("类型：balance 或 subscription"); type.setText("balance");
            final EditText value=edit("balance填余额数量；subscription填订阅ID"); value.setText("10");
            final EditText days=edit("订阅天数：留空/0/null=永久");
            final TextView out=tv("",13,BLACK,0); Button gen=btn("生成卡密", BLUE, Color.WHITE);
            addM(cards,count,-1,dp(48),0,8,0,8); addM(cards,type,-1,dp(48),0,0,0,8); addM(cards,value,-1,dp(48),0,0,0,8); addM(cards,days,-1,dp(48),0,0,0,8); addM(cards,gen,-1,dp(48),0,0,0,8); cards.addView(out);
            gen.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("正在生成卡密...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); String ty=type.getText().toString().trim(); o.put("type", ty); o.put("count", parseInt(count.getText().toString(),1)); if("subscription".equals(ty)){ o.put("sub_id", parseInt(value.getText().toString(),0)); String d=days.getText().toString().trim(); if(d.length()==0 || "null".equalsIgnoreCase(d)) o.put("amount", 0); else o.put("amount", parseInt(d,0)); } else { o.put("amount", parseInt(value.getText().toString(),10)); } return api.post("/admin/cards/create", o); }}, new Done(){ public void ok(Object o){ JSONArray arr=((JSONObject)o).optJSONArray("items"); StringBuilder sb=new StringBuilder(); if(arr!=null) for(int i=0;i<arr.length();i++) sb.append(arr.optString(i)).append("\n"); out.setText(sb.toString()); copy(sb.toString()); toast("已生成并复制"); }}); }});
            addM(page,cards,-1,-2,0,0,0,12);
        }

        void addCreateUserSection(final LinearLayout page) {
            LinearLayout addUserCard = card("添加用户");
            String tips = "非超级管理员只能创建普通用户。初始余额需要 103 权限，初始订阅需要 105 权限；管理员账号和权限只能超级管理员创建。超级管理员创建管理员时请选择权限ID，999 表示超级管理员。";
            TextView addUserTips = tv(tips, 12, GRAY, 0); addUserTips.setPadding(0, 0, 0, dp(8)); addUserCard.addView(addUserTips);
            final EditText newName = edit("昵称/姓名（留空则使用用户名）"); newName.setSingleLine(true);
            final EditText newUsername = edit("用户名 *"); newUsername.setSingleLine(true);
            final EditText newPassword = edit("初始密码 *"); newPassword.setSingleLine(true); newPassword.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            final EditText newBalance = edit("初始余额（需要 103 权限）"); newBalance.setText("0"); newBalance.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED);
            final EditText newSubId = edit("初始订阅ID（需要 105 权限）"); newSubId.setText("0"); newSubId.setInputType(InputType.TYPE_CLASS_NUMBER);
            final EditText newSubDays = edit("初始订阅天数（0/空/null=永久）"); newSubDays.setText("0"); newSubDays.setInputType(InputType.TYPE_CLASS_NUMBER);
            final RadioButton newRoleNormal = roleRadio("普通用户", true);
            final RadioButton newRoleAdmin = roleRadio("管理员", false);
            final RadioGroup newRoleGroup = new RadioGroup(a); newRoleGroup.setOrientation(RadioGroup.VERTICAL);
            newRoleGroup.addView(newRoleNormal); newRoleGroup.addView(newRoleAdmin);
            final ArrayList<CheckBox> newPermChecks;
            Button createUser = btn("添加用户", BLUE, Color.WHITE);
            addM(addUserCard,newName,-1,dp(48),0,8,0,8); addM(addUserCard,newUsername,-1,dp(48),0,0,0,8); addM(addUserCard,newPassword,-1,dp(48),0,0,0,8);
            if(hasAdminPerm(103)) addM(addUserCard,newBalance,-1,dp(48),0,0,0,8);
            if(hasAdminPerm(105)){ addM(addUserCard,newSubId,-1,dp(48),0,0,0,8); addM(addUserCard,newSubDays,-1,dp(48),0,0,0,8); }
            if(isSuperAdmin){ addUserCard.addView(newRoleGroup); newPermChecks = addAdminPermissionChecks(addUserCard, null, true); } else { newPermChecks = new ArrayList<CheckBox>(); }
            addM(addUserCard,createUser,-1,dp(44),0,0,0,0);
            createUser.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final String username = newUsername.getText().toString().trim(); final String password = newPassword.getText().toString();
                if(username.length()==0){ toast("请输入用户名"); return; } if(password.length()==0){ toast("请输入初始密码"); return; }
                async("正在添加用户...", new Job(){ public Object run() throws Exception {
                    JSONObject o=new JSONObject(); String name = newName.getText().toString().trim(); if(name.length()==0) name = username;
                    o.put("name", name); o.put("username", username); o.put("password", password);
                    o.put("balance", hasAdminPerm(103) ? parseLong(newBalance.getText().toString(),0L) : 0);
                    o.put("subscription_id", hasAdminPerm(105) ? parseInt(newSubId.getText().toString(),0) : 0);
                    String sdText = newSubDays.getText().toString().trim(); if(hasAdminPerm(105)){ if(sdText.length()==0 || "null".equalsIgnoreCase(sdText)) o.put("subscription_days", 0); else o.put("subscription_days", parseInt(sdText,0)); }
                    JSONArray pids = isSuperAdmin && newRoleAdmin.isChecked() ? checkedAdminPermissionIds(newPermChecks) : new JSONArray();
                    int role = (isSuperAdmin && newRoleAdmin.isChecked()) ? 1 : 0;
                    o.put("permission", role);
                    if(isSuperAdmin){ o.put("admin_permission_ids", pids); }
                    return api.post("/admin/users/create", o);
                }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; toast("添加成功，用户ID：" + r.optInt("user_id",0)); showAdmin(); }});
            }});
            addM(page,addUserCard,-1,-2,0,0,0,12);
        }

        void addInteractiveUsersSection(final LinearLayout page) {
            LinearLayout um = card("用户列表 / 直接操作");
            final EditText keyword = edit("搜索用户ID / 用户名 / 昵称"); keyword.setSingleLine(true);
            Button search = btn("搜索/刷新用户", BLUE, Color.WHITE);
            addM(um, keyword, -1, dp(48), 0, 8, 0, 8); addM(um, search, -1, dp(44), 0, 0, 0, 8);
            search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminUsers(page, keyword.getText().toString().trim()); }});
            JSONArray arr = adminUsersData == null ? null : adminUsersData.optJSONArray("items");
            if(arr == null) um.addView(tv("用户列表未加载。点击“搜索/刷新用户”后只拉取前 50 条。", 12, GRAY, 0));
            else if(arr.length()==0) um.addView(tv("没有匹配用户", 12, GRAY, 0));
            else {
                for(int i=0;i<arr.length();i++){
                    final JSONObject u = arr.optJSONObject(i); if(u==null) continue;
                    LinearLayout row = vbox(); row.setPadding(dp(14), dp(12), dp(14), dp(12)); row.setBackground(bg(Color.WHITE, 18)); softElev(row, 1);
                    String permsText = adminPermissionNames(u.optJSONArray("permission_ids"), u.optInt("permission",0));
                    row.addView(tv("#"+u.optInt("id")+"  "+u.optString("username")+" / "+u.optString("name"), 14, BLACK, Typeface.BOLD));
                    row.addView(tv("余额:"+quotaText(u,"balance","0")+"  订阅:"+u.optInt("subscription_id",0)+"  到期:"+u.optString("subscription_expire","") , 12, GRAY, 0));
                    row.addView(tv("状态:"+(u.optInt("banned",0)==1?"已封禁":"正常")+"  权限:"+permsText+"  任务:"+u.optInt("task_count",0), 12, GRAY, 0));
                    Button op = btn("操作此用户", BLUE_DARK, Color.WHITE); addM(row, op, -1, dp(44), 0, 8, 0, 0);
                    op.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showAdminUserDialog(u); }});
                    addM(um, row, -1, -2, 0, 0, 0, 10);
                }
            }
            addM(page,um,-1,-2,0,0,0,12);
        }

        void showAdminUserDialog(final JSONObject u) {
            final int userId = u.optInt("id", 0);
            ScrollView sv = new ScrollView(a); LinearLayout box = vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4)); sv.addView(box);
            box.addView(tv("#"+userId+"  "+u.optString("username")+" / "+u.optString("name"), 16, BLACK, Typeface.BOLD));
            box.addView(tv("余额:"+quotaText(u,"balance","0")+"  订阅:"+u.optInt("subscription_id",0)+"  封禁:"+u.optInt("banned",0), 13, GRAY, 0));
            if(hasAdminPerm(103)){
                final EditText bal = edit("设置余额"); bal.setText(quotaText(u,"balance","0")); bal.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED);
                Button b = btn("保存余额", BLUE, Color.WHITE); addM(box, bal, -1, dp(48), 0, 12, 0, 8); addM(box, b, -1, dp(42), 0, 0, 0, 8);
                b.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminUserUpdateById(userId, "balance", parseLong(bal.getText().toString(),0L)); }});
            }
            if(hasAdminPerm(104)){
                LinearLayout br = hbox(); Button ban = btn("封禁", Color.parseColor("#EF4444"), Color.WHITE); Button unban = btn("解封", Color.parseColor("#22C55E"), Color.WHITE);
                br.addView(ban, new LinearLayout.LayoutParams(0, dp(42), 1)); Space spc = new Space(a); br.addView(spc, new LinearLayout.LayoutParams(dp(8), 1)); br.addView(unban, new LinearLayout.LayoutParams(0, dp(42), 1)); addM(box, br, -1, dp(42), 0, 4, 0, 8);
                ban.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminUserUpdateById(userId, "banned", 1); }});
                unban.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminUserUpdateById(userId, "banned", 0); }});
            }
            if(hasAdminPerm(105)){
                final EditText subid=edit("添加订阅ID"); subid.setInputType(InputType.TYPE_CLASS_NUMBER); subid.setText(String.valueOf(u.optInt("subscription_id",0)));
                final EditText subdays=edit("订阅天数：0/空/null=永久；不填默认30天"); subdays.setInputType(InputType.TYPE_CLASS_NUMBER);
                Button addSub=btn("保存订阅", BLUE_DARK, Color.WHITE); addM(box, subid, -1, dp(48), 0, 8, 0, 8); addM(box, subdays, -1, dp(48), 0, 0, 0, 8); addM(box, addSub, -1, dp(42), 0, 0, 0, 8);
                addSub.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("正在保存订阅...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("user_id",userId); o.put("subscription_id",parseInt(subid.getText().toString(),0)); String d=subdays.getText().toString().trim(); if(d.length()==0 || "null".equalsIgnoreCase(d)) o.put("subscription_days",0); else o.put("subscription_days",parseInt(d,30)); return api.post("/admin/user/update", o); }}, new Done(){ public void ok(Object o){ toast("订阅已保存"); showAdmin(); }}); }});
            }
            if(isSuperAdmin){
                final boolean curAdmin = u.optInt("permission",0) > 0 || (u.optJSONArray("permission_ids") != null && u.optJSONArray("permission_ids").length() > 0);
                final RadioButton roleNormal = roleRadio("普通用户", !curAdmin);
                final RadioButton roleAdmin = roleRadio("管理员", curAdmin);
                RadioGroup rg = new RadioGroup(a); rg.setOrientation(RadioGroup.VERTICAL); rg.addView(roleNormal); rg.addView(roleAdmin);
                box.addView(rg);
                final ArrayList<CheckBox> permChecks = addAdminPermissionChecks(box, u.optJSONArray("permission_ids"), false);
                Button setp=btn("保存管理员权限", BLUE_DARK, Color.WHITE); addM(box, setp, -1, dp(42), 0, 8, 0, 8);
                setp.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("正在设置权限...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); int role = roleAdmin.isChecked() ? 1 : 0; o.put("user_id", userId); o.put("permission", role); o.put("permission_ids", role == 1 ? checkedAdminPermissionIds(permChecks) : new JSONArray()); return api.post("/admin/user/permissions", o); }}, new Done(){ public void ok(Object o){ toast("权限已更新"); showAdmin(); }}); }});
            }
            if(hasAdminPerm(401)){
                Button userTasks = btn("查看此用户任务", Color.parseColor("#E2E8F0"), BLACK); addM(box, userTasks, -1, dp(42), 0, 8, 0, 0);
                userTasks.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminTasks(nullSafeAdminPage(), "", "", userId); }});
            }
            AlertDialog dlg = mdDialog("用户操作", sv).setNegativeButton("关闭", null).create();
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
            dlg.show();
        }

        LinearLayout nullSafeAdminPage() {
            // 对话框中触发时，重新打开后台并用全局数据刷新，避免持有已关闭页面引用。
            showAdmin();
            return (LinearLayout)((ScrollView)content.getChildAt(0)).getChildAt(0);
        }

        void addAllTasksSection(final LinearLayout page) {
            LinearLayout tm = card("全站任务（401）");
            final EditText keyword = edit("搜索任务号 / APK / 包名 / 用户"); keyword.setSingleLine(true);
            final EditText status = edit("状态过滤：queued/running/done/failed/cancelled，可留空"); status.setSingleLine(true);
            Button search = btn("搜索/刷新全站任务", BLUE, Color.WHITE);
            addM(tm, keyword, -1, dp(48), 0, 8, 0, 8); addM(tm, status, -1, dp(48), 0, 0, 0, 8); addM(tm, search, -1, dp(44), 0, 0, 0, 8);
            if(hasAdminPerm(603)){
                Button stopAll = btn("停止全部排队/运行任务", Color.parseColor("#DC2626"), Color.WHITE);
                addM(tm, stopAll, -1, dp(44), 0, 0, 0, 8);
                stopAll.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminStopAllTasks(); }});
            }
            if(hasAdminPerm(604) || hasAdminPerm(605)){
                LinearLayout cr = hbox();
                if(hasAdminPerm(604)){ Button cu = btn("清空上传文件", Color.parseColor("#EF4444"), Color.WHITE); cr.addView(cu, new LinearLayout.LayoutParams(0, dp(42), 1)); cu.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminClearStorage("uploads"); }}); }
                if(hasAdminPerm(604) && hasAdminPerm(605)){ Space spc = new Space(a); cr.addView(spc, new LinearLayout.LayoutParams(dp(8), 1)); }
                if(hasAdminPerm(605)){ Button ct = btn("清空任务文件", Color.parseColor("#F97316"), Color.WHITE); cr.addView(ct, new LinearLayout.LayoutParams(0, dp(42), 1)); ct.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminClearStorage("tasks"); }}); }
                addM(tm, cr, -1, dp(42), 0, 0, 0, 8);
            }
            if(hasAdminPerm(606)){
                Button clearRecords = btn("清空任务记录（不删文件，ID重置为1）", Color.parseColor("#DC2626"), Color.WHITE);
                addM(tm, clearRecords, -1, dp(42), 0, 0, 0, 8);
                clearRecords.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminClearTaskRecords(); }});
            }
            search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminTasks(page, keyword.getText().toString().trim(), status.getText().toString().trim(), 0); }});
            JSONArray arr = adminTasksData == null ? null : adminTasksData.optJSONArray("items");
            if(arr == null) tm.addView(tv("全站任务未加载。点击“搜索/刷新全站任务”后按 50 条一片加载。", 12, GRAY, 0));
            else if(arr.length()==0) tm.addView(tv("没有匹配任务", 12, GRAY, 0));
            else {
                for(int i=0;i<arr.length();i++){
                    final JSONObject t = arr.optJSONObject(i); if(t==null) continue;
                    LinearLayout row = vbox(); row.setPadding(dp(14), dp(12), dp(14), dp(12)); row.setBackground(bg(Color.WHITE, 18)); softElev(row, 1);
                    row.addView(tv("#"+t.optInt("id")+"  "+t.optString("apk_name")+"  ["+t.optString("status")+"]  "+taskRunnerName(t), 13, BLACK, Typeface.BOLD));
                    row.addView(tv("用户:"+t.optString("username")+"(#"+t.optInt("user_id")+")  包名:"+t.optString("package_name"), 12, GRAY, 0));
                    row.addView(tv("文件:"+t.optInt("file_count")+" 可下:"+t.optInt("downloadable_file_count")+" 已扣:"+quotaText(t,"decrypt_quota_deducted","0")+" 创建:"+t.optString("created_at"), 12, GRAY, 0));
                    row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showAdminTaskDialog(t); }});
                    addM(tm, row, -1, -2, 0, 0, 0, 10);
                }
                if(adminTasksData != null && adminTasksData.optBoolean("has_more", false)) {
                    final int nextOffset = adminTasksData.optInt("next_offset", arr.length());
                    Button more = btn("加载下一片任务（50条）", Color.parseColor("#E2E8F0"), BLACK);
                    addM(tm, more, -1, dp(42), 0, 0, 0, 8);
                    more.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminTasksPage(page, adminTasksLastKeyword, adminTasksLastStatus, adminTasksLastUserId, nextOffset, true); }});
                }
            }
            addM(page, tm, -1, -2, 0, 0, 0, 12);
        }

        boolean adminTaskIsActive(JSONObject t) {
            String status = t == null ? "" : t.optString("status", "").trim().toLowerCase(Locale.US);
            return "queued".equals(status) || "running".equals(status);
        }

        void showAdminTaskDialog(final JSONObject t){
            LinearLayout box=vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4));
            box.addView(tv("任务ID："+t.optInt("id")+" / "+t.optString("task_no"), 13, BLACK, Typeface.BOLD));
            box.addView(tv("用户："+t.optString("username")+" (#"+t.optInt("user_id")+")", 13, GRAY, 0));
            box.addView(tv("APK："+t.optString("apk_name"), 13, GRAY, 0));
            box.addView(tv("类型："+taskRunnerName(t), 13, GRAY, 0));
            box.addView(tv("状态："+t.optString("status")+"  文件："+t.optInt("file_count")+"  可下载："+t.optInt("downloadable_file_count"), 13, GRAY, 0));
            box.addView(tv("错误："+t.optString("error_text", ""), 13, Color.parseColor("#EF4444"), 0));
            if(hasAdminPerm(603)){
                if(adminTaskIsActive(t)){
                    Button stop = btn("停止此任务", Color.parseColor("#DC2626"), Color.WHITE);
                    addM(box, stop, -1, dp(42), 0, 12, 0, 8);
                    stop.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminStopTask(t.optInt("id",0)); }});
                }
                Button dl = btn("下载任务源码", BLUE, Color.WHITE);
                Button del = btn("删除任务", Color.parseColor("#EF4444"), Color.WHITE);
                addM(box, dl, -1, dp(42), 0, adminTaskIsActive(t) ? 0 : 12, 0, 8);
                addM(box, del, -1, dp(42), 0, 0, 0, 0);
                dl.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminDownloadTaskSource(t); }});
                del.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminDeleteTask(t.optInt("id",0)); }});
            }
            AlertDialog dlg=mdDialog("全站任务详情", box).setNegativeButton("关闭", null).create();
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20)); dlg.show();
        }

        void adminStopTask(final int taskId) {
            if(taskId <= 0) { toast("任务ID无效"); return; }
            new AlertDialog.Builder(a)
                .setTitle("停止单独任务")
                .setMessage("确定停止任务 #"+taskId+"？只停止这个任务及其解密子进程，不影响其他任务。")
                .setNegativeButton("取消", null)
                .setPositiveButton("停止", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                    async("正在停止任务...", new Job(){ public Object run() throws Exception {
                        return api.post("/admin/task-control/"+taskId+"/stop", new JSONObject());
                    }}, new Done(){ public void ok(Object o){
                        JSONObject r=(JSONObject)o;
                        toast(r.optString("message", "任务已停止"));
                        showAdmin();
                    }});
                }}).show();
        }

        void adminStopAllTasks() {
            new AlertDialog.Builder(a)
                .setTitle("停止全部任务")
                .setMessage("确定停止全站所有 queued/running 任务？会结束每个正在运行任务的解密进程组，并取消所有排队任务；已经完成的任务不受影响。")
                .setNegativeButton("取消", null)
                .setPositiveButton("全部停止", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                    async("正在停止全部任务...", new Job(){ public Object run() throws Exception {
                        return api.post("/admin/task-control/stop-all", new JSONObject());
                    }}, new Done(){ public void ok(Object o){
                        JSONObject r=(JSONObject)o;
                        JSONObject summary=r.optJSONObject("summary");
                        int stopped=summary==null ? 0 : summary.optInt("stopped",0);
                        int failed=summary==null ? 0 : summary.optInt("failed",0);
                        toast("已停止 "+stopped+" 个任务"+(failed>0 ? "，失败 "+failed+" 个" : ""));
                        showAdmin();
                    }});
                }}).show();
        }

        void adminDownloadTaskSource(final JSONObject task) {
            if (!ensureStorageReady()) return;
            async("正在下载任务源码...", new Job(){ public Object run() throws Exception {
                File dir = new File(Environment.getExternalStorageDirectory(), "iApt");
                if (!dir.exists()) dir.mkdirs();
                if (!dir.exists() || !dir.canWrite()) {
                    File alt = a.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                    dir = new File(alt == null ? a.getFilesDir() : alt, "iApt");
                    if (!dir.exists()) dir.mkdirs();
                }
                return api.downloadAdminTaskSource(task.optInt("id",0), dir, safe(task.optString("apk_name", "task")));
            }}, new Done(){ public void ok(Object o){ final File f=(File)o; toast("已保存："+f.getAbsolutePath()); }});
        }

        void adminDeleteTask(final int taskId) {
            new AlertDialog.Builder(a).setTitle("删除任务").setMessage("确定删除任务 #"+taskId+"？会同时清理上传文件和任务输出文件。")
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                    async("正在删除任务...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); return api.post("/admin/tasks/"+taskId+"/delete", o); }}, new Done(){ public void ok(Object o){ toast("已删除任务"); showAdmin(); }});
                }}).show();
        }

        void adminClearStorage(final String kind) {
            String title = "uploads".equals(kind) ? "清空上传文件" : "清空任务文件";
            String msg = "uploads".equals(kind) ? "确定清空 storage/uploads 下的上传包？不删除任务记录。" : "确定清空 storage/tasks/zips 下的任务输出文件？不删除任务记录。";
            new AlertDialog.Builder(a).setTitle(title).setMessage(msg)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                    final String route = "uploads".equals(kind) ? "/admin/storage/clear-uploads" : "/admin/storage/clear-tasks";
                    async("正在清理...", new Job(){ public Object run() throws Exception { return api.post(route, new JSONObject()); }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; toast("已清理："+r.optInt("deleted",0)+" 项"); showAdmin(); }});
                }}).show();
        }

        void adminClearTaskRecords() {
            String msg = "确定清空全部任务记录？此操作只删除数据库任务记录和关联记录，不删除上传文件、源码目录或 ZIP，并会把任务ID计数器重置为1。";
            new AlertDialog.Builder(a).setTitle("清空任务记录").setMessage(msg)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定清空", new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d, int w){
                    async("正在清空任务记录...", new Job(){ public Object run() throws Exception { return api.post("/admin/tasks/clear-records", new JSONObject()); }}, new Done(){ public void ok(Object o){ toast("任务记录已清空，ID已重置"); showAdmin(); }});
                }}).show();
        }

        void addCardsListSection(final LinearLayout page) {
            LinearLayout cm = card("卡密记录（202，点击卡片可操作）");
            final EditText keyword = edit("搜索卡密 / 类型 / 使用者"); keyword.setSingleLine(true);
            Button search = btn("搜索/刷新卡密", BLUE, Color.WHITE);
            addM(cm, keyword, -1, dp(48), 0, 8, 0, 8); addM(cm, search, -1, dp(44), 0, 0, 0, 8);
            search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminCards(page, keyword.getText().toString().trim()); }});
            JSONArray arr = adminCardsData == null ? null : adminCardsData.optJSONArray("items");
            if(arr == null) cm.addView(tv("卡密记录未加载。点击“搜索/刷新卡密”后只拉取前 50 条。", 12, GRAY, 0));
            else if(arr.length()==0) cm.addView(tv("没有卡密记录", 12, GRAY, 0));
            else for(int i=0;i<arr.length();i++){
                final JSONObject c=arr.optJSONObject(i); if(c==null) continue;
                LinearLayout row = vbox(); row.setPadding(dp(12), dp(10), dp(12), dp(10)); row.setBackground(bg(Color.WHITE, 18)); softElev(row, 1);
                String status = c.optInt("disabled",0)==1 ? "已作废" : (c.optInt("used_by",0)>0 ? "已使用" : "未使用");
                row.addView(tv("#"+c.optInt("id")+"  "+c.optString("code"), 13, BLACK, Typeface.BOLD));
                row.addView(tv(c.optString("type")+" sub="+c.optInt("sub_id",0)+" amount="+c.optInt("amount",0)+"  状态:"+status, 12, GRAY, 0));
                row.addView(tv("使用者:"+c.optString("used_username", "-")+"  创建:"+c.optString("created_at", ""), 12, GRAY, 0));
                row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showAdminCardDialog(c); }});
                addM(cm, row, -1, -2, 0, 0, 0, 10);
            }
            addM(page, cm, -1, -2, 0, 0, 0, 12);
        }

        void showAdminCardDialog(final JSONObject c){
            LinearLayout box=vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4));
            box.addView(tv("卡密："+c.optString("code"), 13, BLACK, Typeface.BOLD));
            box.addView(tv("类型："+c.optString("type")+"  订阅ID:"+c.optInt("sub_id",0)+"  数量/天数:"+c.optInt("amount",0), 13, GRAY, 0));
            box.addView(tv("状态："+(c.optInt("disabled",0)==1?"已作废":(c.optInt("used_by",0)>0?"已使用":"未使用")), 13, GRAY, 0));
            box.addView(tv("使用者："+c.optString("used_username", "-")+"  使用时间:"+c.optString("used_at", ""), 13, GRAY, 0));
            Button copyBtn=btn("复制卡密", Color.parseColor("#E2E8F0"), BLACK); addM(box,copyBtn,-1,dp(42),0,12,0,8);
            copyBtn.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy(c.optString("code")); toast("已复制"); }});
            if(hasAdminPerm(203)){
                Button dis=btn(c.optInt("disabled",0)==1?"恢复卡密":"作废卡密", Color.parseColor("#F59E0B"), Color.WHITE);
                Button clear=btn("清除使用记录", Color.parseColor("#64748B"), Color.WHITE);
                Button del=btn("删除卡密", Color.parseColor("#EF4444"), Color.WHITE);
                addM(box,dis,-1,dp(42),0,0,0,8); addM(box,clear,-1,dp(42),0,0,0,8); addM(box,del,-1,dp(42),0,0,0,0);
                dis.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminCardUpdate(c.optInt("id"), "disabled", c.optInt("disabled",0)==1?0:1); }});
                clear.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminCardUpdate(c.optInt("id"), "clear_used", 1); }});
                del.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ adminCardUpdate(c.optInt("id"), "delete", 1); }});
            }
            AlertDialog dlg=mdDialog("卡密操作", box).setNegativeButton("关闭", null).create(); if (dlg.getWindow()!=null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE,20)); dlg.show();
        }

        void adminCardUpdate(final int cardId, final String key, final int val){
            async("正在操作卡密...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("card_id", cardId); if("disabled".equals(key)) o.put("disabled", val); if("clear_used".equals(key)) o.put("clear_used", true); if("delete".equals(key)) o.put("delete", true); return api.post("/admin/card/update", o); }}, new Done(){ public void ok(Object o){ toast("卡密操作成功"); showAdmin(); }});
        }

        String wlOpt(JSONObject o, String... keys) {
            if(o == null || keys == null) return "";
            for(String k: keys) {
                if(k == null) continue;
                try {
                    if(o.has(k) && !o.isNull(k)) {
                        String v = String.valueOf(o.opt(k)).trim();
                        if(v.length() > 0 && !"null".equalsIgnoreCase(v)) return v;
                    }
                } catch(Exception e) {}
            }
            return "";
        }

        long wlTime(String s) {
            if(s == null) return 0;
            s = s.trim();
            if(s.length() == 0 || "永久".equals(s) || "never".equalsIgnoreCase(s) || "null".equalsIgnoreCase(s)) return 0;
            s = s.replace('T', ' ').replace("Z", "");
            int dot = s.indexOf('.'); if(dot > 0) s = s.substring(0, dot);
            if(s.length() >= 19) s = s.substring(0, 19);
            String[] fmts = new String[]{"yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd"};
            for(String f: fmts) {
                try { return new SimpleDateFormat(f, Locale.US).parse(s).getTime(); } catch(Exception e) {}
            }
            return 0;
        }

        String whitelistStatus(JSONObject it) {
            String s = wlOpt(it, "status_text", "statusText", "status", "state_text", "state", "status_label", "active_text", "activeText");
            if(s.length() > 0 && !"0".equals(s) && !"1".equals(s) && !"true".equalsIgnoreCase(s) && !"false".equalsIgnoreCase(s)) return s;
            String exp = wlOpt(it, "expire_at", "expireAt", "expire_time", "expireTime", "expires_at", "expiresAt", "expiry", "end_time");
            long t = wlTime(exp);
            if(exp.length() == 0 || "永久".equals(exp) || "never".equalsIgnoreCase(exp) || "null".equalsIgnoreCase(exp)) return "永久";
            if(t > 0) return t > System.currentTimeMillis() ? "生效" : "过期";
            try {
                if(it != null && it.has("expired")) {
                    Object x = it.opt("expired");
                    if(x instanceof Boolean) return ((Boolean)x).booleanValue() ? "过期" : "生效";
                    String xs = String.valueOf(x);
                    if("true".equalsIgnoreCase(xs) || "1".equals(xs)) return "过期";
                    if("false".equalsIgnoreCase(xs) || "0".equals(xs)) return "生效";
                }
                if(it != null && it.has("is_expired")) {
                    Object x = it.opt("is_expired");
                    if(x instanceof Boolean) return ((Boolean)x).booleanValue() ? "过期" : "生效";
                    String xs = String.valueOf(x);
                    if("true".equalsIgnoreCase(xs) || "1".equals(xs)) return "过期";
                    if("false".equalsIgnoreCase(xs) || "0".equals(xs)) return "生效";
                }
                if(it != null && (it.optInt("active", -1) == 1 || it.optInt("valid", -1) == 1 || it.optInt("is_valid", -1) == 1)) return "生效";
            } catch(Exception e) {}
            return "过期";
        }

        String whitelistPublicKey(JSONObject it) {
            return wlOpt(it,
                    "public_key", "publicKey",
                    "whitelist_public_key", "whitelistPublicKey",
                    "whitelist_key", "signature", "signature_base64");
        }

        String whitelistPublicKeyPreview(JSONObject it) {
            String value = whitelistPublicKey(it);
            if(value.length() == 0) return "未生成";
            if(value.length() <= 44) return value;
            return value.substring(0, 22) + "..." + value.substring(value.length() - 18);
        }

        void addWhitelistSection(final LinearLayout page) {
            LinearLayout wm = card("解密白名单（602）");
            final EditText keyword = edit("搜索包名"); keyword.setSingleLine(true);
            Button search = btn("搜索/刷新白名单", BLUE, Color.WHITE);
            Button add = btn("添加白名单", BLUE_DARK, Color.WHITE);
            addM(wm, keyword, -1, dp(48), 0, 8, 0, 8);
            addM(wm, search, -1, dp(42), 0, 0, 0, 8);
            addM(wm, add, -1, dp(42), 0, 0, 0, 8);
            wm.addView(tv("后台只需填写包名和到期时间；保存后由服务端生成可嵌入 mian.iyu 任意位置的 Base64 白名单公钥。", 12, GRAY, 0));
            search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminWhitelist(page, keyword.getText().toString().trim()); }});
            add.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showWhitelistDialog(null); }});
            JSONArray arr = adminWhitelistData == null ? null : adminWhitelistData.optJSONArray("items");
            if(arr == null) wm.addView(tv("白名单未加载。点击“搜索/刷新白名单”后只拉取前 50 条。", 12, GRAY, 0));
            else if(arr.length()==0) wm.addView(tv("没有白名单", 12, GRAY, 0));
            else for(int i=0;i<arr.length();i++){
                final JSONObject it = arr.optJSONObject(i); if(it==null) continue;
                LinearLayout row = vbox(); row.setPadding(dp(12), dp(10), dp(12), dp(10)); row.setBackground(bg(Color.WHITE, 18)); softElev(row, 1);
                row.addView(tv("#"+it.optInt("id")+"  "+it.optString("package_name"), 13, BLACK, Typeface.BOLD));
                row.addView(tv("公钥:"+whitelistPublicKeyPreview(it), 11, GRAY, 0));
                row.addView(tv("到期:"+wlOpt(it, "expire_at", "expireAt", "expire_time", "expires_at", "expiry")+"  状态:"+whitelistStatus(it), 12, GRAY, 0));
                row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showWhitelistDialog(it); }});
                addM(wm, row, -1, -2, 0, 0, 0, 10);
            }
            addM(page, wm, -1, -2, 0, 0, 0, 12);
        }

        void showWhitelistPublicKeyResult(String packageName, String expireAt, String publicKey) {
            ScrollView sv = new ScrollView(a); LinearLayout box = vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4)); sv.addView(box);
            box.addView(tv("包名：" + packageName, 13, BLACK, Typeface.BOLD));
            box.addView(tv("到期：" + (expireAt.length()==0 ? "永久" : expireAt), 12, GRAY, 0));
            box.addView(tv("把下面完整 Base64 公钥原样放入 mian.iyu 的任意位置。不要截断、改字符或二次编码。", 12, GRAY, 0));
            final EditText keyView = edit("白名单公钥");
            keyView.setText(publicKey);
            keyView.setMinLines(5);
            keyView.setGravity(Gravity.TOP);
            keyView.setTextIsSelectable(true);
            keyView.setFocusable(false);
            keyView.setLongClickable(true);
            Button copyKey = btn("复制公钥", BLUE, Color.WHITE);
            addM(box, keyView, -1, dp(150), 0, 10, 0, 8);
            addM(box, copyKey, -1, dp(42), 0, 0, 0, 0);
            final AlertDialog resultDialog = mdDialog("白名单公钥", sv).setNegativeButton("关闭", null).create();
            copyKey.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy(keyView.getText().toString()); toast("公钥已复制"); }});
            resultDialog.show();
            if (resultDialog.getWindow() != null) resultDialog.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
        }

        void showWhitelistDialog(final JSONObject item) {
            ScrollView sv = new ScrollView(a); LinearLayout box = vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4)); sv.addView(box);
            final int wid = item == null ? 0 : item.optInt("id", 0);
            final EditText pkg = edit("包名"); pkg.setSingleLine(true); if(item!=null) pkg.setText(item.optString("package_name", ""));
            final EditText exp = edit("到期时间，空=永久"); exp.setSingleLine(true); if(item!=null) exp.setText(item.optString("expire_at", ""));
            final String existingKey = item == null ? "" : whitelistPublicKey(item);
            box.addView(tv("只填写包名和到期时间。服务端会根据包名、服务端盐、到期毫秒时间戳和 RSA 私钥生成确定性的 Base64 公钥。", 12, GRAY, 0));
            addM(box, pkg, -1, dp(48), 0, 8, 0, 8);
            addM(box, exp, -1, dp(48), 0, 0, 0, 8);
            if(existingKey.length() > 0) {
                final EditText currentKey = edit("当前白名单公钥");
                currentKey.setText(existingKey);
                currentKey.setMinLines(4);
                currentKey.setGravity(Gravity.TOP);
                currentKey.setTextIsSelectable(true);
                currentKey.setFocusable(false);
                Button copyCurrent = btn("复制当前公钥", Color.parseColor("#E2E8F0"), BLACK);
                addM(box, currentKey, -1, dp(130), 0, 0, 0, 8);
                addM(box, copyCurrent, -1, dp(42), 0, 0, 0, 8);
                copyCurrent.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy(currentKey.getText().toString()); toast("公钥已复制"); }});
            }
            Button save = btn(wid>0?"保存并重新生成公钥":"保存并生成公钥", BLUE, Color.WHITE);
            addM(box, save, -1, dp(42), 0, 0, 0, 8);
            if(wid > 0){ Button del = btn("删除", Color.parseColor("#EF4444"), Color.WHITE); addM(box, del, -1, dp(42), 0, 0, 0, 0); del.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ deleteWhitelist(wid); }}); }
            final AlertDialog dlg = mdDialog(wid>0?"编辑白名单":"添加白名单", sv).setNegativeButton("关闭", null).create();
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final String p = pkg.getText().toString().trim().toLowerCase(Locale.US);
                final String e = exp.getText().toString().trim();
                if(p.length()==0){ toast("请输入包名"); return; }
                async("正在生成白名单公钥...", new Job(){ public Object run() throws Exception {
                    JSONObject o = new JSONObject();
                    o.put("id", wid);
                    o.put("package_name", p);
                    o.put("expire_at", e);
                    return api.post("/admin/whitelist/save", o);
                }}, new Done(){ public void ok(Object o){
                    JSONObject r = (JSONObject)o;
                    String key = whitelistPublicKey(r);
                    JSONObject saved = r.optJSONObject("item");
                    if(key.length()==0 && saved!=null) key = whitelistPublicKey(saved);
                    String savedExpire = e;
                    if(saved!=null) {
                        String x = wlOpt(saved, "expire_at", "expireAt", "expire_time", "expires_at");
                        if(x.length()>0) savedExpire = x;
                    }
                    if(key.length()==0) { toast("已保存，但服务端没有返回公钥，请确认已部署白名单签名接口"); return; }
                    copy(key);
                    dlg.dismiss();
                    showAdmin();
                    String savedPackage = p;
                    if(saved!=null) {
                        String x = wlOpt(saved, "package_name", "package", "pkg", "packageName");
                        if(x.length()>0) savedPackage = x.toLowerCase(Locale.US);
                    }
                    showWhitelistPublicKeyResult(savedPackage, savedExpire, key);
                    toast("已保存并复制公钥");
                }});
            }});
            dlg.show();
            if (dlg.getWindow() != null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE, 20));
        }

        void deleteWhitelist(final int id) {
            async("正在删除白名单...", new Job(){ public Object run() throws Exception { JSONObject o = new JSONObject(); o.put("id", id); return api.post("/admin/whitelist/delete", o); }}, new Done(){ public void ok(Object o){ toast("已删除"); showAdmin(); }});
        }

        void addAppSettingsSection(final LinearLayout page) {
            LinearLayout sm = card("系统设置（注册/公告/更新/软件开关）");
            JSONObject cfg = adminAppSettingsData==null?null:adminAppSettingsData.optJSONObject("settings");
            if(cfg == null) {
                sm.addView(tv("系统设置未加载。点击按钮后再读取，避免进入后台时同时请求全部模块。", 12, GRAY, 0));
                Button loadSettings = btn("读取系统设置", BLUE, Color.WHITE);
                addM(sm, loadSettings, -1, dp(42), 0, 8, 0, 0);
                loadSettings.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminAppSettings(page); }});
                addM(page,sm,-1,-2,0,0,0,12); return;
            }
            final CheckBox reg = new CheckBox(a); reg.setText("开放注册（501）"); reg.setTextColor(BLACK); reg.setChecked(cfg.optBoolean("register_enabled", false)); reg.setEnabled(hasAdminPerm(501));
            final CheckBox appOn = new CheckBox(a); appOn.setText("软件开启，客户端默认先向服务器确认开启才进入（504）"); appOn.setTextColor(BLACK); appOn.setChecked(cfg.optBoolean("app_enabled", true)); appOn.setEnabled(hasAdminPerm(504));
            final EditText closeMsg = edit("关闭软件时提示"); closeMsg.setText(cfg.optString("app_closed_message", "")); closeMsg.setEnabled(hasAdminPerm(504));
            JSONObject ann = cfg.optJSONObject("announcement"); if(ann==null) ann=new JSONObject();
            final CheckBox annOn = new CheckBox(a); annOn.setText("显示公告（502）"); annOn.setTextColor(BLACK); annOn.setChecked(ann.optBoolean("enabled", false)); annOn.setEnabled(hasAdminPerm(502));
            final EditText annTitle=edit("公告标题"); annTitle.setText(ann.optString("title", "公告")); annTitle.setEnabled(hasAdminPerm(502));
            final EditText annText=edit("公告内容"); annText.setText(ann.optString("text", "")); annText.setMinLines(3); annText.setGravity(Gravity.TOP); annText.setEnabled(hasAdminPerm(502));
            JSONObject up = cfg.optJSONObject("update"); if(up==null) up=new JSONObject();
            final EditText verCode=edit("最新版本号 version_code（503）"); verCode.setText(String.valueOf(up.optInt("version_code", APP_VERSION_CODE))); verCode.setInputType(InputType.TYPE_CLASS_NUMBER); verCode.setEnabled(hasAdminPerm(503));
            final EditText verName=edit("最新版本名"); verName.setText(up.optString("version_name", APP_VERSION_NAME)); verName.setEnabled(hasAdminPerm(503));
            final EditText url=edit("更新下载链接"); url.setText(up.optString("url", "")); url.setEnabled(hasAdminPerm(503));
            final EditText log=edit("更新说明"); log.setText(up.optString("log", "")); log.setMinLines(3); log.setGravity(Gravity.TOP); log.setEnabled(hasAdminPerm(503));
            final CheckBox force = new CheckBox(a); force.setText("强制更新（503）"); force.setTextColor(BLACK); force.setChecked(up.optBoolean("force", false)); force.setEnabled(hasAdminPerm(503));
            Button save=btn("保存系统设置", BLUE, Color.WHITE);
            sm.addView(reg); sm.addView(appOn); addM(sm,closeMsg,-1,dp(48),0,4,0,8); sm.addView(annOn); addM(sm,annTitle,-1,dp(48),0,4,0,8); addM(sm,annText,-1,dp(92),0,0,0,8); addM(sm,verCode,-1,dp(48),0,4,0,8); addM(sm,verName,-1,dp(48),0,0,0,8); addM(sm,url,-1,dp(48),0,0,0,8); addM(sm,log,-1,dp(92),0,0,0,8); sm.addView(force); addM(sm,save,-1,dp(44),0,8,0,0);
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("正在保存系统设置...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); if(hasAdminPerm(501)) o.put("register_enabled", reg.isChecked()); if(hasAdminPerm(504)){ o.put("app_enabled", appOn.isChecked()); o.put("app_closed_message", closeMsg.getText().toString()); } if(hasAdminPerm(502)){ o.put("announcement_enabled", annOn.isChecked()); o.put("announcement_title", annTitle.getText().toString()); o.put("announcement_text", annText.getText().toString()); } if(hasAdminPerm(503)){ o.put("update_version_code", parseInt(verCode.getText().toString(), APP_VERSION_CODE)); o.put("update_version_name", verName.getText().toString()); o.put("update_url", url.getText().toString()); o.put("update_log", log.getText().toString()); o.put("force_update", force.isChecked()); } return api.post("/admin/app/settings", o); }}, new Done(){ public void ok(Object o){ toast("系统设置已保存"); showAdmin(); }}); }});
            addM(page,sm,-1,-2,0,0,0,12);
        }

        void addSubscriptionManagerSection(final LinearLayout page) {
            LinearLayout sm = card("订阅类型管理（301）");
            sm.addView(tv("上方可新增订阅；下方列表点击任意订阅即可直接修改。", 12, GRAY, 0));
            final EditText sid=edit("订阅ID sub_id"); sid.setInputType(InputType.TYPE_CLASS_NUMBER);
            final EditText sname=edit("订阅名称");
            final EditText daily=edit("日额度"); daily.setInputType(InputType.TYPE_CLASS_NUMBER);
            final EditText feats=edit("功能列表");
            Button save=btn("新增/保存订阅类型", BLUE, Color.WHITE);
            addM(sm,sid,-1,dp(48),0,8,0,8); addM(sm,sname,-1,dp(48),0,0,0,8); addM(sm,daily,-1,dp(48),0,0,0,8); addM(sm,feats,-1,dp(48),0,0,0,8); addM(sm,save,-1,dp(44),0,0,0,8);
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final int subId=parseInt(sid.getText().toString(),0);
                final String subName=sname.getText().toString().trim();
                if(subId<=0){ toast("请输入正确的订阅ID"); return; }
                if(subName.length()==0){ toast("请输入订阅名称"); return; }
                async("正在保存订阅...", new Job(){ public Object run() throws Exception {
                    JSONObject o=new JSONObject(); o.put("sub_id", subId); o.put("sub_name", subName);
                    o.put("daily_quota", parseLong(daily.getText().toString(),50L));
                    o.put("features", parseFeatureIds(feats.getText().toString()));
                    return api.post("/admin/subscriptions/save", o);
                }}, new Done(){ public void ok(Object o){ toast("订阅类型已保存"); showAdmin(); }});
            }});

            final EditText keyword=edit("搜索订阅ID / 名称 / 功能ID"); keyword.setSingleLine(true);
            Button refresh=btn("搜索/刷新订阅列表", Color.parseColor("#E2E8F0"), BLACK);
            addM(sm,keyword,-1,dp(48),0,8,0,8); addM(sm,refresh,-1,dp(42),0,0,0,8);
            refresh.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminSubscriptions(page, keyword.getText().toString().trim()); }});

            JSONArray arr=adminSubscriptionsData==null?null:adminSubscriptionsData.optJSONArray("items");
            if(arr==null) sm.addView(tv("订阅列表未加载。点击刷新后只拉取前 50 条。",12,GRAY,0));
            else if(arr.length()==0) sm.addView(tv("暂无订阅类型",12,GRAY,0));
            else for(int i=0;i<arr.length();i++){
                final JSONObject sub=arr.optJSONObject(i); if(sub==null) continue;
                LinearLayout row=vbox(); row.setPadding(dp(12),dp(10),dp(12),dp(10)); row.setBackground(bg(Color.WHITE,18)); softElev(row,1);
                row.addView(tv("#"+sub.optInt("sub_id")+"  "+sub.optString("sub_name","订阅"),14,BLACK,Typeface.BOLD));
                row.addView(tv("日额度:"+quotaText(sub,"daily_quota","0")+"  功能:"+joinIntArray(sub.optJSONArray("features")),12,GRAY,0));
                row.addView(tv("当前用户:"+sub.optInt("current_user_count",0)+"  有效订阅记录:"+sub.optInt("active_record_count",0),12,GRAY,0));
                row.addView(tv("点击直接修改",11,BLUE,Typeface.BOLD));
                row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showSubscriptionEditDialog(sub); }});
                addM(sm,row,-1,-2,0,0,0,10);
            }
            addM(page,sm,-1,-2,0,0,0,12);
        }

        JSONArray parseFeatureIds(String text) {
            JSONArray fs=new JSONArray(); HashSet<Integer> seen=new HashSet<Integer>();
            String[] parts=String.valueOf(text==null?"":text).split(",");
            for(int i=0;i<parts.length;i++){
                String p=parts[i].trim(); if(p.length()==0) continue;
                int id=parseInt(p,-1); if(id<0 || seen.contains(Integer.valueOf(id))) continue;
                seen.add(Integer.valueOf(id)); fs.put(id);
            }
            return fs;
        }

        String joinIntArray(JSONArray arr) {
            if(arr==null || arr.length()==0) return "无";
            StringBuilder sb=new StringBuilder();
            for(int i=0;i<arr.length();i++){ if(sb.length()>0) sb.append(","); sb.append(arr.optInt(i)); }
            return sb.toString();
        }

        void showSubscriptionEditDialog(final JSONObject sub) {
            ScrollView sv=new ScrollView(a); LinearLayout box=vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4)); sv.addView(box);
            final int subId=sub.optInt("sub_id",0);
            final EditText sid=edit("订阅ID"); sid.setText(String.valueOf(subId)); sid.setInputType(InputType.TYPE_CLASS_NUMBER); sid.setEnabled(false);
            final EditText name=edit("订阅名称"); name.setText(sub.optString("sub_name",""));
            final EditText daily=edit("日额度"); daily.setText(quotaText(sub,"daily_quota","0")); daily.setInputType(InputType.TYPE_CLASS_NUMBER);
            final EditText feats=edit("功能列表，逗号分隔"); feats.setText(joinIntArray(sub.optJSONArray("features")));
            Button save=btn("保存修改",BLUE,Color.WHITE);
            addM(box,sid,-1,dp(48),0,8,0,8); addM(box,name,-1,dp(48),0,0,0,8); addM(box,daily,-1,dp(48),0,0,0,8); addM(box,feats,-1,dp(48),0,0,0,8); addM(box,save,-1,dp(42),0,0,0,0);
            final AlertDialog dlg=mdDialog("修改订阅 #"+subId,sv).setNegativeButton("关闭",null).create();
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final String subName=name.getText().toString().trim(); if(subName.length()==0){ toast("请输入订阅名称"); return; }
                async("正在修改订阅...",new Job(){ public Object run() throws Exception {
                    JSONObject o=new JSONObject(); o.put("sub_id",subId); o.put("sub_name",subName);
                    o.put("daily_quota",parseLong(daily.getText().toString(),0L)); o.put("features",parseFeatureIds(feats.getText().toString()));
                    return api.post("/admin/subscriptions/save",o);
                }},new Done(){ public void ok(Object o){ toast("订阅已修改"); dlg.dismiss(); showAdmin(); }});
            }});
            if(dlg.getWindow()!=null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE,20)); dlg.show();
        }

        void addDynamicKeyPoolManagerSection(final LinearLayout page) {
            LinearLayout km=card("动态密钥池管理（302）");
            km.addView(tv("可查看、添加、修改、启停、标记验证或删除密钥。密钥在数据库中仍为加密存储。",12,GRAY,0));
            LinearLayout actions=hbox(); Button add=btn("添加密钥",BLUE_DARK,Color.WHITE); Button refresh=btn("刷新列表",Color.parseColor("#E2E8F0"),BLACK);
            actions.addView(add,new LinearLayout.LayoutParams(0,dp(42),1)); Space gap=new Space(a); actions.addView(gap,new LinearLayout.LayoutParams(dp(8),1)); actions.addView(refresh,new LinearLayout.LayoutParams(0,dp(42),1)); addM(km,actions,-1,dp(42),0,8,0,8);
            final EditText keyword=edit("搜索ID / 引用 / 来源 / 文件名 / 来源或方案指纹SHA256"); keyword.setSingleLine(true); Button search=btn("搜索密钥池",BLUE,Color.WHITE);
            addM(km,keyword,-1,dp(48),0,0,0,8); addM(km,search,-1,dp(42),0,0,0,8);
            add.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showDynamicKeyPoolDialog(null); }});
            refresh.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminKeyPool(page,""); }});
            search.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ loadAdminKeyPool(page,keyword.getText().toString().trim()); }});
            JSONArray arr=adminKeyPoolData==null?null:adminKeyPoolData.optJSONArray("items");
            if(arr==null) km.addView(tv("密钥池未加载。点击刷新后只拉取前 50 条。",12,GRAY,0));
            else if(arr.length()==0) km.addView(tv("密钥池暂无记录",12,GRAY,0));
            else for(int i=0;i<arr.length();i++){
                final JSONObject key=arr.optJSONObject(i); if(key==null) continue;
                LinearLayout row=vbox(); row.setPadding(dp(12),dp(10),dp(12),dp(10)); row.setBackground(bg(Color.WHITE,18)); softElev(row,1);
                String status=(key.optBoolean("enabled",false)?"启用":"停用")+" / "+(key.optBoolean("verified",false)?"已验证":"未验证");
                row.addView(tv("#"+key.optInt("id")+"  "+key.optString("public_id",key.optString("ref","")),13,BLACK,Typeface.BOLD));
                row.addView(tv("post: "+shortKey(key.optString("post_key","")),12,GRAY,0));
                row.addView(tv("xor : "+shortKey(key.optString("xor_key","")),12,GRAY,0));
                row.addView(tv("状态:"+status+"  成功:"+key.optInt("success_count",0)+"  使用:"+key.optInt("use_count",0),12,GRAY,0));
                JSONObject rowFeatures=key.optJSONObject("features");
                StringBuilder featureNames=new StringBuilder();
                String[] featureOrder=new String[]{"arm64-v8a","armeabi-v7a","armeabi","x86_64","x86"};
                if(rowFeatures!=null) for(int fi=0;fi<featureOrder.length;fi++){
                    String abi=featureOrder[fi];
                    if(rowFeatures.optString(abi,"").trim().length()>0){ if(featureNames.length()>0) featureNames.append("、"); featureNames.append(abi); }
                }
                row.addView(tv("指纹:"+(featureNames.length()>0?featureNames.toString():"未设置")+"（"+key.optInt("feature_count",0)+"）",12,GRAY,0));
                row.addView(tv("来源:"+key.optString("source_type","unknown")+" / "+key.optString("source_name",""),12,GRAY,0));
                if(key.optString("decrypt_error","").length()>0) row.addView(tv("密钥解密错误:"+key.optString("decrypt_error"),11,Color.parseColor("#EF4444"),0));
                row.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ showDynamicKeyPoolDialog(key); }});
                addM(km,row,-1,-2,0,0,0,10);
            }
            addM(page,km,-1,-2,0,0,0,12);
        }

        String shortKey(String value) {
            String s=String.valueOf(value==null?"":value).trim();
            if(s.length()<=24) return s;
            return s.substring(0,12)+"..."+s.substring(s.length()-8);
        }

        boolean evenHex(String value) {
            String s=String.valueOf(value==null?"":value).trim();
            return s.length()>0 && (s.length()%2==0) && s.matches("^[0-9a-fA-F]+$");
        }

        boolean emptyOrSha256(String value) {
            String s=String.valueOf(value==null?"":value).trim();
            return s.length()==0 || s.matches("^[0-9a-fA-F]{64}$");
        }

        void showDynamicKeyPoolDialog(final JSONObject item) {
            ScrollView sv=new ScrollView(a); LinearLayout box=vbox(); box.setPadding(dp(4),dp(4),dp(4),dp(4)); sv.addView(box);
            final int keyId=item==null?0:item.optInt("id",0);
            if(item!=null){
                box.addView(tv("引用："+item.optString("public_id",item.optString("ref","")),12,GRAY,0));
                box.addView(tv("成功次数："+item.optInt("success_count",0)+"　使用次数："+item.optInt("use_count",0),12,GRAY,0));
            }
            final EditText post=edit("post_key（十六进制）"); post.setSingleLine(true); if(item!=null) post.setText(item.optString("post_key",""));
            final EditText xor=edit("xor_key（十六进制）"); xor.setSingleLine(true); if(item!=null) xor.setText(item.optString("xor_key",""));
            final EditText sourceType=edit("来源类型，例如 admin/custom_success/auto_extract"); sourceType.setSingleLine(true); sourceType.setText(item==null?"admin":item.optString("source_type","admin"));
            final EditText sourceName=edit("来源文件名/备注"); sourceName.setSingleLine(true); if(item!=null) sourceName.setText(item.optString("source_name",""));
            final EditText sourceSha=edit("来源 SHA256，可留空"); sourceSha.setSingleLine(true); if(item!=null) sourceSha.setText(item.optString("source_sha256",""));
            JSONObject itemFeatures=item==null?null:item.optJSONObject("features");
            final EditText fpArm64=edit("arm64-v8a 指纹（64位SHA256，可留空）"); fpArm64.setSingleLine(true); if(itemFeatures!=null) fpArm64.setText(itemFeatures.optString("arm64-v8a",""));
            final EditText fpArmv7=edit("armeabi-v7a 指纹（64位SHA256，可留空）"); fpArmv7.setSingleLine(true); if(itemFeatures!=null) fpArmv7.setText(itemFeatures.optString("armeabi-v7a",""));
            final EditText fpArmeabi=edit("armeabi 指纹（64位SHA256，可留空）"); fpArmeabi.setSingleLine(true); if(itemFeatures!=null) fpArmeabi.setText(itemFeatures.optString("armeabi",""));
            final EditText fpX64=edit("x86_64 指纹（64位SHA256，可留空）"); fpX64.setSingleLine(true); if(itemFeatures!=null) fpX64.setText(itemFeatures.optString("x86_64",""));
            final EditText fpX86=edit("x86 指纹（64位SHA256，可留空）"); fpX86.setSingleLine(true); if(itemFeatures!=null) fpX86.setText(itemFeatures.optString("x86",""));
            final EditText firstUid=edit("首次用户ID，可留空"); firstUid.setSingleLine(true); firstUid.setInputType(InputType.TYPE_CLASS_NUMBER); if(item!=null && item.optInt("first_user_id",0)>0) firstUid.setText(String.valueOf(item.optInt("first_user_id")));
            final CheckBox verified=new CheckBox(a); verified.setText("已验证：允许普通密钥池接口使用"); verified.setTextColor(BLACK); verified.setChecked(item==null || item.optBoolean("verified",false));
            final CheckBox enabled=new CheckBox(a); enabled.setText("启用"); enabled.setTextColor(BLACK); enabled.setChecked(item==null || item.optBoolean("enabled",false));
            Button copyPair=btn("复制两项密钥",Color.parseColor("#E2E8F0"),BLACK); Button save=btn(keyId>0?"保存修改":"添加到密钥池",BLUE,Color.WHITE);
            addM(box,post,-1,dp(48),0,8,0,8); addM(box,xor,-1,dp(48),0,0,0,8); addM(box,sourceType,-1,dp(48),0,0,0,8); addM(box,sourceName,-1,dp(48),0,0,0,8); addM(box,sourceSha,-1,dp(48),0,0,0,8);
            box.addView(tv("方案指纹（留空可删除对应架构指纹）",12,GRAY,Typeface.BOLD));
            addM(box,fpArm64,-1,dp(48),0,6,0,6); addM(box,fpArmv7,-1,dp(48),0,0,0,6); addM(box,fpArmeabi,-1,dp(48),0,0,0,6); addM(box,fpX64,-1,dp(48),0,0,0,6); addM(box,fpX86,-1,dp(48),0,0,0,8);
            addM(box,firstUid,-1,dp(48),0,0,0,8); box.addView(verified); box.addView(enabled); addM(box,copyPair,-1,dp(42),0,8,0,8); addM(box,save,-1,dp(42),0,0,0,8);
            final Button del=keyId>0?btn("永久删除此密钥",Color.parseColor("#EF4444"),Color.WHITE):null; if(del!=null) addM(box,del,-1,dp(42),0,0,0,0);
            final AlertDialog dlg=mdDialog(keyId>0?"编辑动态密钥 #"+keyId:"添加动态密钥",sv).setNegativeButton("关闭",null).create();
            copyPair.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ copy("post_key="+post.getText().toString().trim()+"\nxor_key="+xor.getText().toString().trim()); toast("已复制"); }});
            save.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                final String postText=post.getText().toString().trim(); final String xorText=xor.getText().toString().trim();
                if(!evenHex(postText)){ toast("post_key 必须是偶数长度十六进制"); return; }
                if(!evenHex(xorText)){ toast("xor_key 必须是偶数长度十六进制"); return; }
                String[] fpValues=new String[]{fpArm64.getText().toString().trim(),fpArmv7.getText().toString().trim(),fpArmeabi.getText().toString().trim(),fpX64.getText().toString().trim(),fpX86.getText().toString().trim()};
                String[] fpAbis=new String[]{"arm64-v8a","armeabi-v7a","armeabi","x86_64","x86"};
                final JSONObject featureMap=new JSONObject();
                for(int fi=0;fi<fpValues.length;fi++){
                    if(!emptyOrSha256(fpValues[fi])){ toast(fpAbis[fi]+" 指纹必须是64位十六进制或留空"); return; }
                    if(fpValues[fi].length()>0) try{ featureMap.put(fpAbis[fi],fpValues[fi].toLowerCase(Locale.US)); }catch(Exception ignored){}
                }
                async("正在保存密钥...",new Job(){ public Object run() throws Exception {
                    JSONObject o=new JSONObject(); o.put("id",keyId); o.put("post_key",postText); o.put("xor_key",xorText);
                    o.put("source_type",sourceType.getText().toString().trim()); o.put("source_name",sourceName.getText().toString().trim()); o.put("source_sha256",sourceSha.getText().toString().trim());
                    String uid=firstUid.getText().toString().trim(); if(uid.length()>0) o.put("first_user_id",parseInt(uid,0));
                    o.put("verified",verified.isChecked()); o.put("enabled",enabled.isChecked());
                    o.put("features",featureMap); o.put("normalizer_version",Api.DYNAMIC_SO_FEATURE_VERSION);
                    return api.post("/admin/dynamic-key-pool/save",o);
                }},new Done(){ public void ok(Object o){ toast("密钥及指纹已保存"); dlg.dismiss(); showAdmin(); }});
            }});
            if(del!=null) del.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){
                new AlertDialog.Builder(a).setTitle("删除密钥").setMessage("确定永久删除密钥 #"+keyId+"？此操作无法恢复。")
                    .setNegativeButton("取消",null).setPositiveButton("删除",new DialogInterface.OnClickListener(){ public void onClick(DialogInterface d,int which){
                        async("正在删除密钥...",new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("id",keyId); return api.post("/admin/dynamic-key-pool/delete",o); }},new Done(){ public void ok(Object o){ toast("密钥已删除"); dlg.dismiss(); showAdmin(); }});
                    }}).show();
            }});
            if(dlg.getWindow()!=null) dlg.getWindow().setBackgroundDrawable(bg(Color.WHITE,20)); dlg.show();
        }

        void addAdminPermissionSection(final LinearLayout page){
            LinearLayout am = card("管理员权限（超级管理员）");
            final EditText auid=edit("用户ID"); auid.setInputType(InputType.TYPE_CLASS_NUMBER);
            final RadioButton roleNormal = roleRadio("普通用户", false);
            final RadioButton roleAdmin = roleRadio("管理员（勾选权限ID；999=超级管理员）", true);
            RadioGroup rg = new RadioGroup(a); rg.setOrientation(RadioGroup.VERTICAL); rg.addView(roleNormal); rg.addView(roleAdmin);
            Button loadUser=btn("先读取此用户当前权限", Color.parseColor("#E2E8F0"), BLACK);
            Button setp=btn("设置管理员权限", BLUE_DARK, Color.WHITE);
            addM(am,auid,-1,dp(48),0,8,0,8); addM(am,loadUser,-1,dp(42),0,0,0,8); am.addView(rg);
            final ArrayList<CheckBox> permChecks = addAdminPermissionChecks(am, null, true);
            addM(am,setp,-1,dp(44),0,8,0,0);
            loadUser.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ final int uid = parseInt(auid.getText().toString(),0); if(uid<=0){ toast("请输入用户ID"); return; } async("正在读取用户...", new Job(){ public Object run() throws Exception { return api.get("/admin/users/" + uid); }}, new Done(){ public void ok(Object o){ JSONObject r=(JSONObject)o; JSONObject u=r.optJSONObject("user"); if(u==null){ toast("未找到用户"); return; } JSONArray ids=u.optJSONArray("permission_ids"); boolean curAdmin = u.optInt("permission",0) > 0 || (ids != null && ids.length() > 0); roleNormal.setChecked(!curAdmin); roleAdmin.setChecked(curAdmin); for(int i=0;i<permChecks.size();i++){ CheckBox cb=permChecks.get(i); int pid=((Integer)cb.getTag()).intValue(); cb.setChecked(jsonArrayContains(ids,pid)); } toast("已读取当前权限"); }}); }});
            setp.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ async("正在设置权限...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); int role = roleAdmin.isChecked() ? 1 : 0; o.put("user_id", parseInt(auid.getText().toString(),0)); o.put("permission", role); o.put("permission_ids", role == 1 ? checkedAdminPermissionIds(permChecks) : new JSONArray()); return api.post("/admin/user/permissions", o); }}, new Done(){ public void ok(Object o){ toast("权限已更新"); showAdmin(); }}); }});
            addM(page,am,-1,-2,0,0,0,12);
        }

        void adminUserUpdateById(final int userId, final String key, final Object val) {
            async("正在更新用户...", new Job(){ public Object run() throws Exception { JSONObject o=new JSONObject(); o.put("user_id", userId); if(val instanceof Long) o.put(key, ((Long)val).longValue()); else if(val instanceof Integer) o.put(key, ((Integer)val).intValue()); else o.put(key, val); return api.post("/admin/user/update", o); }}, new Done(){ public void ok(Object o){ toast("更新成功"); showAdmin(); }});
        }
        void copy(String s){ try{ ((android.content.ClipboardManager)a.getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("iapt", s)); }catch(Exception e){} }

        String relativeTime(String s) {
            long ts = parseTime(s);
            if (ts <= 0) return "";
            long diff = System.currentTimeMillis() - ts;
            if (diff < 0) diff = 0;
            if (diff < 10000) return "刚刚";
            if (diff < 60000) return (Math.max(1, diff / 1000)) + "秒前";
            if (diff < 3600000) return (Math.max(1, diff / 60000)) + "分钟前";
            if (diff < 86400000) return (Math.max(1, diff / 3600000)) + "小时前";
            if (diff < 2592000000L) return (Math.max(1, diff / 86400000)) + "天前";
            try { return new java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.US).format(new java.util.Date(ts)); } catch(Exception e) { return ""; }
        }

        long parseTime(String s) {
            if (s == null || s.length() == 0 || "null".equals(s)) return 0;
            s = s.trim();
            try {
                if (s.matches("^[0-9]+$")) {
                    long v = Long.parseLong(s);
                    return v < 10000000000L ? v * 1000 : v;
                }
            } catch (Exception e) {}
            String raw = s;
            boolean hasTz = raw.endsWith("Z") || raw.matches(".*[+-][0-9]{2}:?[0-9]{2}$");
            String[] ps = {"yyyy-MM-dd'T'HH:mm:ss.SSS", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"};
            for (int i = 0; i < ps.length; i++) {
                try {
                    String x = raw;
                    java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(ps[i], java.util.Locale.US);
                    // 只有带 Z/时区偏移的时间才按 UTC 解析；MySQL/后端本地时间按手机本地时区解析。
                    if (hasTz) {
                        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
                        x = x.replace("Z", "");
                        x = x.replaceAll("[+-][0-9]{2}:?[0-9]{2}$", "");
                    }
                    return sdf.parse(x).getTime();
                } catch (Exception e) {}
            }
            return 0;
        }
    }

    static class Api {
        String base, appId, secret; SharedPreferences sp; SecureRandom rnd = new SecureRandom();
        static final Object IAPT_UPLOAD_SERIAL_LOCK = new Object();
        static final int IAPT_LINEAR_UPLOAD_CHUNK = 512 * 1024;
        Api(String base, String appId, String secret, SharedPreferences sp) { this.base=trimSlash(base); this.appId=appId; this.secret=secret; this.sp=sp; }
        static String trimSlash(String s){ while(s.endsWith("/")) s=s.substring(0,s.length()-1); return s; }
        String token(){ return sp.getString("token", ""); }

        JSONObject get(String route) throws Exception { return request("GET", route, null, token()); }
        // 下拉刷新使用单次短超时请求，避免普通 GET 的 5 次重试把刷新拖得很久。
        JSONObject getFast(String route) throws Exception { return requestOnceWithTimeouts("GET", route, null, token(), 3000, 6500); }
        JSONObject getPublic(String route) throws Exception { return request("GET", route, null, ""); }
        JSONObject post(String route, JSONObject body) throws Exception { return post(route, body, token()); }
        JSONObject post(String route, JSONObject body, String tk) throws Exception { return request("POST", route, body, tk==null?"":tk); }

        JSONObject request(String method, String route, JSONObject body, String tk) throws Exception {
            Exception last = null;
            int tries = "GET".equals(method) ? 5 : 2;
            for (int i = 0; i < tries; i++) {
                try {
                    return requestOnce(method, route, body, tk);
                } catch (java.io.IOException e) {
                    last = e;
                    String msg = e.getMessage() == null ? String.valueOf(e) : e.getMessage();
                    boolean retry = msg.indexOf("Software caused connection abort") >= 0 || msg.indexOf("Connection reset") >= 0 || msg.indexOf("timeout") >= 0 || msg.indexOf("unexpected end") >= 0;
                    if (!retry || i + 1 >= tries) throw e;
                    try { Thread.sleep(400L * (i + 1)); } catch(Exception ignored) {}
                }
            }
            throw last == null ? new IOException("network failed") : last;
        }

        JSONObject requestOnce(String method, String route, JSONObject body, String tk) throws Exception {
            return requestOnceWithTimeouts(method, route, body, tk, 25000, 180000);
        }

        JSONObject requestOnceWithTimeouts(String method, String route, JSONObject body, String tk,
                                           int connectTimeoutMs, int readTimeoutMs) throws Exception {
            if(!route.startsWith("/")) route = "/" + route;
            String full = base + route;
            URL url = new URL(full);
            String path = url.getPath() + (url.getQuery()==null?"":"?"+url.getQuery());
            String salt = hex(randomBytes(12));
            String ts = String.valueOf(System.currentTimeMillis()/1000L);
            String nonce = hex(randomBytes(12));
            byte[] outBytes = null;
            String bodyHash;
            if("POST".equals(method)) {
                if(body==null) body = new JSONObject();
                Enc enc = encrypt(body.toString(), salt);
                JSONObject wrap = new JSONObject(); wrap.put("data", enc.data); wrap.put("iv", enc.iv);
                bodyHash = sha256Hex(enc.data.getBytes("UTF-8"));
                outBytes = wrap.toString().getBytes("UTF-8");
            } else {
                bodyHash = sha256Hex(new byte[0]);
            }
            String sign = sign(method, path, ts, nonce, salt, bodyHash, tk);
            HttpURLConnection c = (HttpURLConnection)url.openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(connectTimeoutMs > 0 ? connectTimeoutMs : 25000);
            c.setReadTimeout(readTimeoutMs > 0 ? readTimeoutMs : 180000);
            c.setUseCaches(false);
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign);
            if(tk!=null && tk.length()>0) c.setRequestProperty("Authorization", "Bearer " + tk);
            if("POST".equals(method)) { c.setDoOutput(true); c.setRequestProperty("Content-Type", "application/json; charset=utf-8"); OutputStream os=c.getOutputStream(); os.write(outBytes); os.close(); }
            int code = c.getResponseCode(); String text = read(code>=200&&code<300?c.getInputStream():c.getErrorStream());
            if(code == 401) throw new AuthException(errorText(text, code));
            if(code<200 || code>=300) throw new Exception(errorText(text, code));
            if(text==null || text.trim().length()==0) return new JSONObject();
            return new JSONObject(text);
        }

        JSONObject uploadTask(File apk, JSONObject options) throws Exception {
            // V3 轻量上传：普通V3/dex密钥/动态key均不上传 classes*.dex；仅“动态修复”开启时上传 DEX。
            // V3 解密任务仍使用轻量 APK；“单独提取动态 Key”只上传 libygsiyu.so，多 ABI 时上传小型 SO ZIP。
            // multipart 文件名仍使用原始 APK 名，任务列表标题不被改成软件名。
            if (options == null) options = new JSONObject();
            options.put("sample_name", apk.getName());
            options.put("client_original_apk_name", apk.getName());
            if (!options.has("client_request_id") || options.optString("client_request_id", "").trim().length() == 0) {
                options.put("client_request_id", java.util.UUID.randomUUID().toString());
            }
            File up = prepareV3CompactUpload(apk, options);
            try {
                boolean ancientEndpoint = "ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))
                        || optBool(options, "legacy_iapp") || optBool(options, "old_iapp");
                if (ancientEndpoint) {
                    options.put("v3_upload_mode", "ancient_minimal_arsc_libso_client_params");
                    options.put("client_route_lock", "ancient-shared-v126");
                    options.put("client_submission_path", "decrypt");
                } else {
                    options.put("v3_upload_mode", optBool(options, "client_full_apk_uploaded")
                            ? "full_apk_static_resource_parameter"
                            : (optBool(options, "client_upload_one_abi")
                            ? "light_one_abi_conditional_dex" : "light_all_abi_conditional_dex"));
                    options.put("client_submission_path", "decrypt");
                }
                options.put("upload_icon", false);
                // V126：远古也走共享 /tasks/decrypt，靠 payload 中 decrypt_scheme=ancient 路由。
                // 避免 /tasks/{task_id} 动态路由截获 /tasks/decrypt-ancient，并避免路径改写导致签名/登录失效。
                return uploadTaskTo("/tasks/decrypt", up, options, apk.getName());
            } finally {
                if (up != null && !up.getAbsolutePath().equals(apk.getAbsolutePath()) && up.getName().startsWith("iapt_v3_apk_")) {
                    try { up.delete(); } catch(Exception e) {}
                }
            }
        }
        JSONObject extractDynamicKeyTask(File sourceFile, String originalName) throws Exception {
            if (sourceFile == null || !sourceFile.exists() || !sourceFile.isFile()) throw new Exception("请选择 APK、SO 包或 libygsiyu.so");
            JSONObject options = new JSONObject();
            options.put("feature_id", 4);
            options.put("dynamic_key_extract", true);
            options.put("original_filename", originalName == null ? sourceFile.getName() : originalName);
            DynamicSoFingerprintInfo info = inspectDynamicSoSource(sourceFile);
            if (info != null && info.hasLibraries()) {
                options.put("dynamic_key_features", info.features);
                options.put("dynamic_key_feature_version", DYNAMIC_SO_FEATURE_VERSION);
                options.put("dynamic_key_sample_entry", info.firstEntry);
                options.put("dynamic_key_sample_abi", info.firstAbi);
            }

            File upload = prepareDynamicKeySoUpload(sourceFile, options);
            boolean temporary = upload != null
                    && !upload.getAbsolutePath().equals(sourceFile.getAbsolutePath())
                    && (upload.getName().startsWith("iapt_dynamic_one_") || upload.getName().startsWith("iapt_dynamic_multi_"));
            try {
                String low = upload.getName().toLowerCase(Locale.US);
                String mime = low.endsWith(".zip") ? "application/zip" : "application/octet-stream";
                String uploadName = low.endsWith(".zip") ? "dynamic_key_libs.zip" : "libygsiyu.so";
                return uploadFileForJson("/dynamic-keys/extract", "sample", upload, options, uploadName, mime);
            } finally {
                if (temporary) {
                    try { upload.delete(); } catch(Exception ignored) {}
                }
            }
        }

        JSONObject extractServerSoKeyTask(File sourceFile, String originalName) throws Exception {
            if (sourceFile == null || !sourceFile.exists() || !sourceFile.isFile()) throw new Exception("请选择 APK、SO 包或 libygsiyu.so");
            JSONObject options = new JSONObject();
            options.put("feature_id", 15);
            options.put("task_kind", "server_sokey_extract");
            options.put("server_sokey_extract", true);
            options.put("server_sokey", true);
            options.put("decrypt_version", "sokey");
            options.put("task_version", "sokey");
            options.put("original_filename", originalName == null ? sourceFile.getName() : originalName);

            // 与单独提取动态 Key 相同：APK/ZIP/APKS 只打包其中全部 ABI 的 libygsiyu.so。
            File upload = prepareDynamicKeySoUpload(sourceFile, options);
            boolean temporary = upload != null
                    && !upload.getAbsolutePath().equals(sourceFile.getAbsolutePath())
                    && (upload.getName().startsWith("iapt_dynamic_one_") || upload.getName().startsWith("iapt_dynamic_multi_"));
            try {
                String low = upload.getName().toLowerCase(Locale.US);
                String mime = low.endsWith(".zip") ? "application/zip" : "application/octet-stream";
                String uploadName = low.endsWith(".zip") ? "server_sokey_libs.zip" : "libygsiyu.so";
                return uploadFileForJson("/server-sokey/extract", "sample", upload, options, uploadName, mime);
            } finally {
                if (temporary) {
                    try { upload.delete(); } catch(Exception ignored) {}
                }
            }
        }

        JSONObject uploadTaskV6(File apk, JSONObject options) throws Exception {
            File up = prepareV6DexOnlyUpload(apk);
            try {
                // V6 只上传 DEX 内容；服务端统一使用 /tasks/decrypt，靠 decrypt_version/feature_id 区分 V6。
                options.put("decrypt_version", "v6");
                options.put("feature_id", 6);
                options.put("v6_upload_mode", "dex_only");
                return uploadTaskTo("/tasks/decrypt", up, options, apk.getName());
            } finally {
                if (up != null && !up.getAbsolutePath().equals(apk.getAbsolutePath()) && up.getName().startsWith("iapt_v6_dex_")) {
                    try { up.delete(); } catch(Exception e) {}
                }
            }
        }

        JSONObject uploadSourceRestoreTask(File srcZip, String baseName, JSONObject extraOptions) throws Exception {
            JSONObject options = new JSONObject();
            options.put("feature_id", 8);
            options.put("source_restore", true);
            if (extraOptions != null) {
                Iterator<String> it = extraOptions.keys();
                while (it.hasNext()) {
                    String k = it.next();
                    options.put(k, extraOptions.opt(k));
                }
            }
            String fn = clean(baseName);
            if (fn.length() == 0) fn = "src";
            if (!fn.endsWith(".zip")) fn = fn + "_src.zip";
            return uploadFileForJson("/source/restore", "src", srcZip, options, fn, "application/zip");
        }


        JSONObject uploadStaticDexSourceRestoreTask(File srcZip, File dexFile, String baseName, JSONObject extraOptions) throws Exception {
            JSONObject options = new JSONObject();
            options.put("feature_id", 8);
            options.put("source_restore", true);
            options.put("dex_static_restore", true);
            options.put("decrypt_version", "dex_restore");
            options.put("scan_source_apk_lib", true);
            if (extraOptions != null) {
                Iterator<String> it = extraOptions.keys();
                while (it.hasNext()) {
                    String k = it.next();
                    options.put(k, extraOptions.opt(k));
                }
            }
            String fn = clean(baseName);
            if (fn.length() == 0) fn = "src";
            if (!fn.endsWith(".zip")) fn = fn + "_dex_restore.zip";
            if (dexFile == null) {
                return uploadFileForJson("/source/dex-restore", "src", srcZip, options, fn, "application/zip");
            }
            return uploadTwoFilesForJson("/source/dex-restore", "src", srcZip, fn, "application/zip", "dex", dexFile, dexFile.getName(), "application/octet-stream", options);
        }

        JSONObject uploadNumericSourceRestoreTask(File srcZip, File dexFile, String baseName) throws Exception {
            return uploadNumericSourceRestoreTask(srcZip, dexFile, baseName, null);
        }

        JSONObject uploadNumericSourceRestoreTask(File srcZip, File dexFile, String baseName, JSONObject extraOptions) throws Exception {
            JSONObject options = new JSONObject();
            options.put("feature_id", 5);
            options.put("numeric_source_restore", true);
            boolean iact = extraOptions != null && optBool(extraOptions, "iact_dynamic_decrypt");
            options.put("decrypt_version", iact ? "iact_restore" : "fn_restore");
            if (extraOptions != null) {
                Iterator<String> it = extraOptions.keys();
                while (it.hasNext()) {
                    String key = it.next();
                    options.put(key, extraOptions.opt(key));
                }
            }
            String fn = clean(baseName);
            if (fn.length() == 0) fn = "src";
            if (!fn.endsWith(".zip")) fn = fn + (iact ? "_iact.zip" : "_src.zip");
            if (iact || dexFile == null) {
                options.put("iact_dynamic_decrypt", true);
                options.put("skip_dex_upload", true);
                options.put("no_dex_upload", true);
                options.put("decrypt_version", "iact_restore");
                return uploadFileForJson("/source/numeric-restore", "src", srcZip, options, fn, "application/zip");
            }
            // V13：保留原始 DEX/APK/ZIP/JAR 上传。服务端会自行提取 classes*.dex，
            // 同时还能读取 libDestruction.so 等 iAPEC 配置，供动态修复和反自毁共用。
            String low = dexFile.getName().toLowerCase(Locale.US);
            options.put("dynamic_restore_input_type", low.endsWith(".dex") ? "dex" : (low.endsWith(".apk") ? "apk" : (low.endsWith(".jar") ? "jar" : "zip")));
            options.put("dynamic_restore_upload_name", dexFile.getName());
            return uploadTwoFilesForJson("/source/numeric-restore",
                    "src", srcZip, fn, "application/zip",
                    "dex", dexFile, dexFile.getName(), "application/octet-stream", options);
        }

        JSONObject uploadNativeCompileSourceRestoreTask(File srcZip, File dexFile, String baseName, JSONObject extraOptions) throws Exception {
            if (dexFile == null || !dexFile.isFile()) throw new IOException("DEX/APK/ZIP/JAR 文件不存在");
            JSONObject options = new JSONObject();
            options.put("feature_id", 5);
            options.put("native_compile_source_restore", true);
            options.put("native_compile_restore", true);
            options.put("require_dex_upload", true);
            options.put("decrypt_version", "native_compile_restore");
            options.put("task_version", "native_compile_restore");
            if (extraOptions != null) {
                Iterator<String> it = extraOptions.keys();
                while (it.hasNext()) {
                    String key = it.next();
                    options.put(key, extraOptions.opt(key));
                }
            }
            String fn = clean(baseName);
            if (fn.length() == 0) fn = "src";
            if (!fn.endsWith(".zip")) fn = fn + "_native_compile.zip";
            return uploadTwoFilesForJson("/source/native-compile-restore",
                    "src", srcZip, fn, "application/zip",
                    "dex", dexFile, dexFile.getName(), "application/octet-stream", options);
        }

        static File prepareDynamicRestoreDexUpload(File source, JSONObject options) throws Exception {
            if (source == null || !source.isFile()) throw new IOException("DEX/APK/ZIP/JAR 文件不存在");
            String low = source.getName().toLowerCase(Locale.US);
            if (low.endsWith(".dex")) {
                if (options != null) {
                    options.put("dynamic_restore_input_type", "dex");
                    options.put("dynamic_restore_upload_name", source.getName());
                }
                return source;
            }

            DynamicRestoreProbe probe = detectDynamicRestore(source);
            ZipFile z = null;
            try {
                z = new ZipFile(source);
                String selected = probe == null ? "" : probe.dexEntry;
                ZipEntry dexEntry = selected.length() > 0 ? z.getEntry(selected) : null;
                if (dexEntry == null || dexEntry.isDirectory()) {
                    ArrayList<String> dexNames = new ArrayList<String>();
                    Enumeration<? extends ZipEntry> en = z.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        if (e == null || e.isDirectory()) continue;
                        String simple = e.getName().replace('\\', '/');
                        int slash = simple.lastIndexOf('/');
                        if (slash >= 0) simple = simple.substring(slash + 1);
                        if (isDexFileName(simple)) dexNames.add(e.getName());
                    }
                    Collections.sort(dexNames, new Comparator<String>() {
                        public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }
                    });
                    if (dexNames.size() > 0) {
                        selected = dexNames.get(0);
                        dexEntry = z.getEntry(selected);
                    }
                }
                if (dexEntry == null || dexEntry.isDirectory()) throw new IOException("文件中没有找到 classes.dex");
                if (dexEntry.getSize() > 128L * 1024L * 1024L) throw new IOException("DEX 超过 128MB");

                String simpleName = selected.replace('\\', '/');
                int slash = simpleName.lastIndexOf('/');
                if (slash >= 0) simpleName = simpleName.substring(slash + 1);
                if (!isDexFileName(simpleName)) simpleName = "classes.dex";

                File tmp = File.createTempFile("iapt_dynamic_restore_", ".dex");
                InputStream in = new BufferedInputStream(z.getInputStream(dexEntry), 1024 * 1024);
                OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024);
                byte[] buf = new byte[1024 * 1024];
                try { copyStream(in, out, buf); }
                finally {
                    try { in.close(); } catch(Exception ignored) {}
                    try { out.close(); } catch(Exception ignored) {}
                }
                if (options != null) {
                    options.put("dynamic_restore_input_type", low.endsWith(".apk") ? "apk" : "archive");
                    options.put("dynamic_restore_original_file", source.getName());
                    options.put("dynamic_restore_extracted_dex_entry", selected);
                    options.put("dynamic_restore_upload_name", simpleName);
                }
                return tmp;
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
        }

        JSONObject uploadTaskTo(String route, File apk, JSONObject options) throws Exception { return uploadTaskTo(route, apk, options, apk.getName()); }
        JSONObject uploadTaskTo(String route, File apk, JSONObject options, String uploadFileName) throws Exception {
            normalizeDexKeyFields(options);
            URL url = new URL(base + route); String path = url.getPath();
            String salt = hex(randomBytes(12)); String ts = String.valueOf(System.currentTimeMillis()/1000L); String nonce = hex(randomBytes(12));
            Enc enc = encrypt(options.toString(), salt); String payload = enc.data; String bodyHash = sha256Hex(payload.getBytes("UTF-8")); String tk = token();
            String sign = sign("POST", path, ts, nonce, salt, bodyHash, tk);
            String boundary = "----IAPT" + hex(randomBytes(8));
            HttpURLConnection c = (HttpURLConnection)url.openConnection();
            c.setRequestMethod("POST"); c.setConnectTimeout(30000); c.setReadTimeout(1800000); c.setUseCaches(false); c.setDoOutput(true);
            try { c.setChunkedStreamingMode(IAPT_LINEAR_UPLOAD_CHUNK); } catch(Exception e) {}
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-IAPT-Upload-Mode", "compact-linear-512k-v121");
            c.setRequestProperty("Authorization", "Bearer " + tk); c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign); c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            OutputStream os = new BufferedOutputStream(c.getOutputStream(), IAPT_LINEAR_UPLOAD_CHUNK);
            String fn = uploadFileName == null || uploadFileName.length() == 0 ? apk.getName() : uploadFileName;
            writeForm(os, boundary, "payload", payload); writeForm(os, boundary, "iv", enc.iv); writeFile(os, boundary, "apk", fn, apk); os.write(("--"+boundary+"--\r\n").getBytes("UTF-8")); os.flush(); os.close();
            int code = c.getResponseCode(); String text = read(code>=200&&code<300?c.getInputStream():c.getErrorStream()); if(code==401) throw new AuthException(errorText(text, code)); if(code<200||code>=300) throw new Exception(errorText(text, code)); return new JSONObject(text);
        }

        byte[] uploadFileForBytes(String route, String fieldName, File file, JSONObject options, String uploadFileName, String contentType) throws Exception {
            synchronized (IAPT_UPLOAD_SERIAL_LOCK) {
            if (options == null) options = new JSONObject();
            URL url = new URL(base + route); String path = url.getPath();
            String salt = hex(randomBytes(12)); String ts = String.valueOf(System.currentTimeMillis()/1000L); String nonce = hex(randomBytes(12));
            Enc enc = encrypt(options.toString(), salt); String payload = enc.data; String bodyHash = sha256Hex(payload.getBytes("UTF-8")); String tk = token();
            String sign = sign("POST", path, ts, nonce, salt, bodyHash, tk);
            String boundary = "----IAPT" + hex(randomBytes(8));
            HttpURLConnection c = (HttpURLConnection)url.openConnection();
            c.setRequestMethod("POST"); c.setConnectTimeout(30000); c.setReadTimeout(1800000); c.setUseCaches(false); c.setDoOutput(true);
            try { c.setChunkedStreamingMode(IAPT_LINEAR_UPLOAD_CHUNK); } catch(Exception e) {}
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-IAPT-Upload-Mode", "serial-linear-v100");
            c.setRequestProperty("Authorization", "Bearer " + tk); c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign); c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            OutputStream os = new BufferedOutputStream(c.getOutputStream(), IAPT_LINEAR_UPLOAD_CHUNK);
            String fn = uploadFileName == null || uploadFileName.length() == 0 ? file.getName() : uploadFileName;
            writeForm(os, boundary, "payload", payload); writeForm(os, boundary, "iv", enc.iv); writeFileTyped(os, boundary, fieldName, fn, file, contentType); os.write(("--"+boundary+"--\r\n").getBytes("UTF-8")); os.flush(); os.close();
            int code = c.getResponseCode();
            if(code<200||code>=300){ String err=read(c.getErrorStream()); if(code==401) throw new AuthException(errorText(err, code)); throw new Exception(errorText(err, code)); }
            return readBytes(c.getInputStream());
        
            }
        }

        JSONObject uploadFileForJson(String route, String fieldName, File file, JSONObject options, String uploadFileName, String contentType) throws Exception {
            synchronized (IAPT_UPLOAD_SERIAL_LOCK) {
            if (options == null) options = new JSONObject();
            URL url = new URL(base + route); String path = url.getPath();
            String salt = hex(randomBytes(12)); String ts = String.valueOf(System.currentTimeMillis()/1000L); String nonce = hex(randomBytes(12));
            Enc enc = encrypt(options.toString(), salt); String payload = enc.data; String bodyHash = sha256Hex(payload.getBytes("UTF-8")); String tk = token();
            String sign = sign("POST", path, ts, nonce, salt, bodyHash, tk);
            String boundary = "----IAPT" + hex(randomBytes(8));
            HttpURLConnection c = (HttpURLConnection)url.openConnection();
            c.setRequestMethod("POST"); c.setConnectTimeout(30000); c.setReadTimeout(1800000); c.setUseCaches(false); c.setDoOutput(true);
            try { c.setChunkedStreamingMode(IAPT_LINEAR_UPLOAD_CHUNK); } catch(Exception e) {}
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-IAPT-Upload-Mode", "serial-linear-v100");
            c.setRequestProperty("Authorization", "Bearer " + tk); c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign); c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            OutputStream os = new BufferedOutputStream(c.getOutputStream(), IAPT_LINEAR_UPLOAD_CHUNK);
            String fn = uploadFileName == null || uploadFileName.length() == 0 ? file.getName() : uploadFileName;
            writeForm(os, boundary, "payload", payload); writeForm(os, boundary, "iv", enc.iv); writeFileTyped(os, boundary, fieldName, fn, file, contentType); os.write(("--"+boundary+"--\r\n").getBytes("UTF-8")); os.flush(); os.close();
            int code = c.getResponseCode(); String text = read(code>=200&&code<300?c.getInputStream():c.getErrorStream()); if(code==401) throw new AuthException(errorText(text, code)); if(code<200||code>=300) throw new Exception(errorText(text, code)); return new JSONObject(text);
        
            }
        }

        JSONObject uploadTwoFilesForJson(String route, String field1, File file1, String name1, String type1, String field2, File file2, String name2, String type2, JSONObject options) throws Exception {
            synchronized (IAPT_UPLOAD_SERIAL_LOCK) {
            if (options == null) options = new JSONObject();
            URL url = new URL(base + route); String path = url.getPath();
            String salt = hex(randomBytes(12)); String ts = String.valueOf(System.currentTimeMillis()/1000L); String nonce = hex(randomBytes(12));
            Enc enc = encrypt(options.toString(), salt); String payload = enc.data; String bodyHash = sha256Hex(payload.getBytes("UTF-8")); String tk = token();
            String sign = sign("POST", path, ts, nonce, salt, bodyHash, tk);
            String boundary = "----IAPT" + hex(randomBytes(8));
            HttpURLConnection c = (HttpURLConnection)url.openConnection();
            c.setRequestMethod("POST"); c.setConnectTimeout(30000); c.setReadTimeout(1800000); c.setUseCaches(false); c.setDoOutput(true);
            try { c.setChunkedStreamingMode(IAPT_LINEAR_UPLOAD_CHUNK); } catch(Exception e) {}
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-IAPT-Upload-Mode", "serial-linear-v100");
            c.setRequestProperty("Authorization", "Bearer " + tk); c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign); c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            OutputStream os = new BufferedOutputStream(c.getOutputStream(), IAPT_LINEAR_UPLOAD_CHUNK);
            writeForm(os, boundary, "payload", payload); writeForm(os, boundary, "iv", enc.iv);
            writeFileTyped(os, boundary, field1, name1 == null || name1.length() == 0 ? file1.getName() : name1, file1, type1);
            writeFileTyped(os, boundary, field2, name2 == null || name2.length() == 0 ? file2.getName() : name2, file2, type2);
            os.write(("--"+boundary+"--\r\n").getBytes("UTF-8")); os.flush(); os.close();
            int code = c.getResponseCode(); String text = read(code>=200&&code<300?c.getInputStream():c.getErrorStream()); if(code==401) throw new AuthException(errorText(text, code)); if(code<200||code>=300) throw new Exception(errorText(text, code)); return new JSONObject(text);
        
            }
        }


        static void normalizeDexKeyFields(JSONObject options) {
            if (options == null) return;
            String[] keys = new String[]{"fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"};
            for (int i = 0; i < keys.length; i++) {
                try {
                    if (options.has(keys[i])) options.put(keys[i], normalizeDexKeyNumber(options.optString(keys[i], "")));
                } catch(Exception e) {}
            }
        }

        static String normalizeDexKeyNumber(String raw) {
            if (raw == null) return "";
            String s = raw.trim();
            if (s.length() == 0) return "";
            s = s.replace("_", "").replace(" ", "");
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("[-+]?0[xX][0-9a-fA-F]+|[-+]?\\d+").matcher(s);
                if (m.find()) s = m.group();
                boolean neg = s.startsWith("-");
                if (s.startsWith("+") || s.startsWith("-")) s = s.substring(1);
                if (s.startsWith("0x") || s.startsWith("0X")) {
                    java.math.BigInteger bi = new java.math.BigInteger(s.substring(2), 16);
                    if (neg) bi = bi.negate();
                    return bi.toString(10);
                }
                if (s.matches("\\d+")) return (neg ? "-" : "") + new java.math.BigInteger(s, 10).toString(10);
            } catch(Exception e) {}
            return raw.trim();
        }


        static boolean hasV1SignatureCert(File src) {
            try {
                ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(src)));
                try {
                    ZipEntry e;
                    while ((e = zis.getNextEntry()) != null) {
                        String n = e.getName().toUpperCase(Locale.US);
                        if (n.startsWith("META-INF/") && (n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC") || n.endsWith(".CER") || n.endsWith(".CRT"))) return true;
                        zis.closeEntry();
                    }
                } finally { try { zis.close(); } catch(Exception ex) {} }
            } catch(Exception e) {}
            return false;
        }

        static File prepareDynamicKeySoUpload(File src, JSONObject options) throws Exception {
            if (src == null || !src.exists() || !src.isFile()) throw new Exception("请选择 APK、SO 包或 libygsiyu.so");
            String lower = src.getName().toLowerCase(Locale.US);
            if (lower.endsWith(".so")) {
                InputStream in = new BufferedInputStream(new FileInputStream(src));
                try {
                    byte[] head = new byte[4];
                    if (in.read(head) != 4 || head[0] != 0x7f || head[1] != 'E' || head[2] != 'L' || head[3] != 'F') throw new Exception("选择的 SO 不是有效 ELF 文件");
                } finally { try { in.close(); } catch(Exception e) {} }
                if (options != null) {
                    options.put("client_so_only_upload", true);
                    options.put("client_uploaded_so_count", 1);
                    options.put("client_source_archive_bytes", src.length());
                    options.put("client_uploaded_so_bytes", src.length());
                    options.put("client_upload_all_abis", false);
                    options.put("dynamic_key_parser", "dataflow-v3");
                }
                return src;
            }
            if (!(lower.endsWith(".apk") || lower.endsWith(".zip") || lower.endsWith(".apks"))) throw new Exception("请选择 APK、SO ZIP、APKS 或 libygsiyu.so");

            ZipFile z = new ZipFile(src);
            File out = File.createTempFile("iapt_dynamic_multi_", ".zip");
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out), 1024 * 1024));
            boolean ok = false;
            int count = 0;
            long total = 0;
            HashSet<String> added = new HashSet<String>();
            byte[] buf = new byte[1024 * 1024];
            try {
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String original = e.getName().replace('\\','/');
                    String simple = original;
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    if (!"libygsiyu.so".equalsIgnoreCase(simple)) continue;
                    if (e.getSize() > 128L * 1024L * 1024L) throw new Exception(original + " 超过 128MB");

                    String abi = "unknown";
                    String[] parts = original.split("/");
                    for (int i = 0; i < parts.length; i++) {
                        String p = parts[i].toLowerCase(Locale.US);
                        if ("arm64-v8a".equals(p) || "armeabi-v7a".equals(p) || "armeabi".equals(p) || "x86".equals(p) || "x86_64".equals(p)) {
                            abi = p; break;
                        }
                    }
                    String entryName = "lib/" + abi + "/libygsiyu.so";
                    if (!added.add(entryName)) continue;

                    InputStream in = new BufferedInputStream(z.getInputStream(e), 1024 * 1024);
                    ByteArrayOutputStream one = new ByteArrayOutputStream((int)Math.min(Math.max(4096L, e.getSize()), 8L * 1024L * 1024L));
                    long oneTotal = 0;
                    try {
                        int n;
                        while ((n = in.read(buf)) > 0) {
                            oneTotal += n;
                            total += n;
                            if (oneTotal > 128L * 1024L * 1024L) throw new Exception(original + " 超过 128MB");
                            if (total > 256L * 1024L * 1024L) throw new Exception("全部 libygsiyu.so 合计超过 256MB");
                            one.write(buf, 0, n);
                        }
                    } finally { try { in.close(); } catch(Exception ignored) {} }
                    byte[] so = one.toByteArray();
                    if (so.length < 4 || so[0] != 0x7f || so[1] != 'E' || so[2] != 'L' || so[3] != 'F') throw new Exception(original + " 不是有效 ELF 文件");
                    ZipEntry dst = new ZipEntry(entryName);
                    dst.setTime(0L);
                    zos.putNextEntry(dst);
                    zos.write(so);
                    zos.closeEntry();
                    count++;
                }
                if (count <= 0) throw new Exception("压缩包中没有找到 libygsiyu.so");
                zos.finish();
                zos.flush();
                if (options != null) {
                    options.put("client_so_only_upload", true);
                    options.put("client_uploaded_so_count", count);
                    options.put("client_source_archive_bytes", src.length());
                    options.put("client_uploaded_so_bytes", total);
                    options.put("client_upload_all_abis", true);
                    options.put("dynamic_key_parser", "dataflow-v3");
                    options.put("dynamic_key_multiabi_consensus", true);
                }
                ok = true;
                return out;
            } finally {
                try { zos.close(); } catch(Exception ignored) {}
                try { z.close(); } catch(Exception ignored) {}
                if (!ok) try { out.delete(); } catch(Exception ignored) {}
            }
        }


        // IAPT_OBFUSCATED_CONTAINER_V279_BEGIN
        static boolean isLikelyObfuscatedContainerEntry(ZipEntry e, String name) {
            if (e == null || e.isDirectory() || name == null) return false;
            long size = e.getSize();
            if (size < 64L * 1024L || size > 512L * 1024L * 1024L) return false;

            String normalized = name.replace('\\', '/');
            String low = normalized.toLowerCase(Locale.US);
            String base = low;
            int slash = base.lastIndexOf('/');
            if (slash >= 0) base = base.substring(slash + 1);

            if ("androidmanifest.xml".equals(base) || "resources.arsc".equals(base)) return false;
            if (base.matches("classes[0-9]*\\.dex")) return false;
            if (low.startsWith("meta-inf/") || low.startsWith("res/") || low.startsWith("bsh/")) return false;
            if (low.startsWith("lib/") && low.endsWith(".so")) return false;

            String[] excluded = new String[]{
                ".dex", ".arsc", ".xml", ".html", ".htm", ".js", ".css", ".json",
                ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico",
                ".mp3", ".wav", ".ogg", ".m4a", ".mp4", ".mkv", ".avi", ".webm",
                ".ttf", ".otf", ".woff", ".woff2", ".so", ".jar", ".zip", ".apk",
                ".properties", ".mf", ".sf", ".rsa", ".dsa", ".ec",
                ".iyu", ".myu", ".mjava", ".mlua", ".mjs", ".ijs", ".ilua", ".ijava"
            };
            for (int i = 0; i < excluded.length; i++) {
                if (base.endsWith(excluded[i])) return false;
            }
            return true;
        }

        static int obfuscatedContainerScore(
                ZipFile z, ArrayList<String> names, String name) {
            try {
                ZipEntry e = z.getEntry(name);
                if (!isLikelyObfuscatedContainerEntry(e, name)) return Integer.MIN_VALUE;

                String normalized = name.replace('\\', '/');
                String low = normalized.toLowerCase(Locale.US);
                int score = 0;

                if (low.startsWith("assets/")) score += 25;
                int length = normalized.length();
                if (length >= 256) score += 35;
                if (length >= 1024) score += 55;
                if (length >= 3000) score += 70;

                int depth = 0;
                int nonAscii = 0;
                for (int i = 0; i < normalized.length(); i++) {
                    char c = normalized.charAt(i);
                    if (c == '/') depth++;
                    if (c > 127) nonAscii++;
                }
                if (depth >= 16) score += 25;
                if (depth >= 64) score += 35;
                if (nonAscii >= 16) score += 25;
                if (nonAscii >= Math.max(32, length / 2)) score += 25;

                long size = e.getSize();
                if (size >= 1024L * 1024L) score += 25;
                if (size >= 4L * 1024L * 1024L) score += 20;

                long compressed = e.getCompressedSize();
                if (size > 0 && compressed > 0) {
                    double ratio = (double)compressed / (double)size;
                    if (ratio >= 0.80d) score += 15;
                    else if (ratio >= 0.60d) score += 7;
                }

                String base = normalized;
                int slash = base.lastIndexOf('/');
                if (slash >= 0) base = base.substring(slash + 1);
                if (base.indexOf('.') < 0) score += 15;

                for (int i = 0; i < names.size(); i++) {
                    String otherName = names.get(i);
                    if (name.equals(otherName)) continue;
                    int extra = otherName.length() - name.length();
                    if (extra < 1 || extra > 32 || !otherName.startsWith(name)) continue;
                    ZipEntry other = z.getEntry(otherName);
                    if (other != null && !other.isDirectory()
                            && other.getSize() >= 0 && other.getSize() <= 8192) {
                        score += 85;
                        break;
                    }
                }
                return score;
            } catch(Exception ignored) {
                return Integer.MIN_VALUE;
            }
        }

        static String selectObfuscatedIappContainer(
                ZipFile z, ArrayList<String> names) {
            String best = null;
            int bestScore = Integer.MIN_VALUE;
            long bestSize = -1L;

            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                int score = obfuscatedContainerScore(z, names, name);
                if (score < 90) continue;
                ZipEntry e = z.getEntry(name);
                long size = e == null ? -1L : e.getSize();
                if (best == null || score > bestScore
                        || (score == bestScore && size > bestSize)
                        || (score == bestScore && size == bestSize
                            && name.compareTo(best) < 0)) {
                    best = name;
                    bestScore = score;
                    bestSize = size;
                }
            }
            return best;
        }

        static int copyObfuscatedContainerSidecars(
                ZipFile z, ZipOutputStream zos, ArrayList<String> names,
                String containerName, byte[] buf, HashSet<String> added,
                JSONArray copiedNames) throws Exception {
            if (containerName == null) return 0;
            int count = 0;
            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                if (containerName.equals(name)) continue;
                int extra = name.length() - containerName.length();
                if (extra < 1 || extra > 32 || !name.startsWith(containerName)) continue;
                ZipEntry e = z.getEntry(name);
                if (e == null || e.isDirectory() || e.getSize() < 0 || e.getSize() > 8192) continue;
                copyZipEntry(z, zos, name, buf, added);
                if (copiedNames != null) copiedNames.put(name);
                count++;
            }
            return count;
        }
        // IAPT_OBFUSCATED_CONTAINER_V279_END

        // IAPT_V116_CLIENT_HIDDEN_COMPACT_BEGIN
        static String findObfuscatedContainerSidecar(
                ZipFile z, ArrayList<String> names, String containerName) {
            if (containerName == null) return null;
            String best = null;
            long bestSize = Long.MAX_VALUE;
            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                if (containerName.equals(name)) continue;
                int extra = name.length() - containerName.length();
                if (extra < 1 || extra > 32 || !name.startsWith(containerName)) continue;
                ZipEntry e = z.getEntry(name);
                if (e == null || e.isDirectory() || e.getSize() <= 0 || e.getSize() > 8192) continue;
                if (e.getSize() < bestSize) {
                    best = name;
                    bestSize = e.getSize();
                }
            }
            return best;
        }

        static byte[] restoreObfuscatedDesInnerZip(
                ZipFile z, ArrayList<String> names, String containerName,
                JSONObject options) throws Exception {
            if (containerName == null) throw new Exception("没有找到隐藏容器");
            ZipEntry cipherEntry = z.getEntry(containerName);
            if (cipherEntry == null || cipherEntry.isDirectory()) throw new Exception("隐藏容器不存在");
            String sidecarName = findObfuscatedContainerSidecar(z, names, containerName);
            if (sidecarName == null) throw new Exception("隐藏容器缺少密钥 sidecar");
            ZipEntry sidecarEntry = z.getEntry(sidecarName);
            byte[] sidecar = readZipEntryBytes(z, sidecarEntry, 8192);
            String text = new String(sidecar, "UTF-8");
            if (text.length() <= 34) throw new Exception("隐藏容器 sidecar 太短");
            String transformed = text.substring(0, text.length() - 33) + text.substring(text.length() - 1);
            char digitChar = transformed.charAt(transformed.length() - 1);
            if (digitChar < '0' || digitChar > '9') throw new Exception("隐藏容器 sidecar 位置位数无效");
            int positionDigits = digitChar - '0';
            if (positionDigits < 1 || positionDigits > 9 || transformed.length() < positionDigits + 2)
                throw new Exception("隐藏容器 sidecar 位置字段无效");
            String positionText = transformed.substring(
                    transformed.length() - 1 - positionDigits, transformed.length() - 1);
            if (!positionText.matches("[0-9]+")) throw new Exception("隐藏容器 sidecar 位置不是数字");
            int position = Integer.parseInt(positionText);
            if (position < 0 || position + 8 > transformed.length())
                throw new Exception("隐藏容器 sidecar 密钥位置越界");
            byte[] keyBytes = transformed.substring(position, position + 8).getBytes("UTF-8");
            if (keyBytes.length < 8) throw new Exception("隐藏容器 DES 密钥不足8字节");
            if (keyBytes.length != 8) keyBytes = Arrays.copyOf(keyBytes, 8);
            byte[] ciphertext = readZipEntryBytes(z, cipherEntry, 256 * 1024 * 1024);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
            byte[] inner = cipher.doFinal(ciphertext);
            if (inner.length < 4 || inner[0] != 'P' || inner[1] != 'K')
                throw new Exception("隐藏容器解密结果不是ZIP");
            boolean hasLib = false;
            ZipInputStream zin = new ZipInputStream(new BufferedInputStream(new ByteArrayInputStream(inner), 256 * 1024));
            try {
                ZipEntry e;
                while ((e = zin.getNextEntry()) != null) {
                    String n = e.getName() == null ? "" : e.getName().replace('\\', '/').toLowerCase(Locale.US);
                    if (!e.isDirectory() && "assets/lib.so".equals(n)) { hasLib = true; break; }
                }
            } finally { try { zin.close(); } catch(Exception ignored) {} }
            if (!hasLib) throw new Exception("隐藏容器内没有 assets/lib.so");
            if (options != null) {
                options.put("client_hidden_local_restore", "des-ecb-pkcs5-v116");
                options.put("client_hidden_cipher_entry", containerName);
                options.put("client_hidden_sidecar_entry", sidecarName);
                options.put("client_hidden_inner_bytes", inner.length);
            }
            return inner;
        }

        static boolean safeCompactZipName(String name) {
            if (name == null) return false;
            String n = name.replace('\\', '/');
            if (n.length() == 0 || n.startsWith("/") || n.indexOf('\0') >= 0) return false;
            String[] parts = n.split("/");
            for (int i = 0; i < parts.length; i++) if ("..".equals(parts[i])) return false;
            return true;
        }

        static JSONObject copyHiddenInnerCompactEntries(
                byte[] inner, ZipOutputStream zos, HashSet<String> added,
                boolean includeResources) throws Exception {
            JSONObject report = new JSONObject();
            int copied = 0, resourceCount = 0;
            long copiedBytes = 0L, resourceBytes = 0L;
            boolean manifest = false, arsc = false, lib = false;
            ZipInputStream zin = new ZipInputStream(new BufferedInputStream(new ByteArrayInputStream(inner), 256 * 1024));
            byte[] buf = new byte[256 * 1024];
            try {
                ZipEntry e;
                while ((e = zin.getNextEntry()) != null) {
                    if (e.isDirectory()) continue;
                    String name = e.getName() == null ? "" : e.getName().replace('\\', '/');
                    String low = name.toLowerCase(Locale.US);
                    boolean resource = low.startsWith("assets/res/");
                    boolean required = "androidmanifest.xml".equals(low)
                            || "resources.arsc".equals(low)
                            || "assets/lib.so".equals(low)
                            || "assets/userencryption.xml".equals(low)
                            || "assets/extra_conf1g.xml".equals(low)
                            || "assets/.jgapp".equals(low)
                            || "assets/jgapp".equals(low);
                    if (!required && !(includeResources && resource)) continue;
                    if (!safeCompactZipName(name) || added.contains(name)) continue;
                    ZipEntry out = new ZipEntry(name);
                    out.setTime(0L);
                    zos.putNextEntry(out);
                    long written = 0L;
                    int n;
                    while ((n = zin.read(buf)) > 0) {
                        zos.write(buf, 0, n);
                        written += n;
                    }
                    zos.closeEntry();
                    added.add(name);
                    copied++;
                    copiedBytes += written;
                    if (resource) { resourceCount++; resourceBytes += written; }
                    if ("androidmanifest.xml".equals(low)) manifest = true;
                    else if ("resources.arsc".equals(low)) arsc = true;
                    else if ("assets/lib.so".equals(low)) lib = true;
                }
            } finally { try { zin.close(); } catch(Exception ignored) {} }
            if (!manifest || !arsc || !lib) throw new Exception("本地精简隐藏容器缺少 Manifest、resources.arsc 或 assets/lib.so");
            report.put("copied_entries", copied);
            report.put("copied_bytes", copiedBytes);
            report.put("resource_entries", resourceCount);
            report.put("resource_bytes", resourceBytes);
            report.put("manifest", manifest);
            report.put("arsc", arsc);
            report.put("lib_so", lib);
            return report;
        }
        // IAPT_V116_CLIENT_HIDDEN_COMPACT_END

        static File prepareV3CompactUpload(File src, JSONObject options) throws Exception {
            String lower = src.getName().toLowerCase(Locale.US);
            if (!lower.endsWith(".apk")) throw new Exception("V3 请选择完整 APK");
            if (options == null) options = new JSONObject();
            // 提交前再次同步识别，避免 UI 异步探针尚未完成时漏传方案参数。
            LegacyIappProbe uploadLegacyProbe = null;
            AntiQiushuiProbe uploadAntiProbe = null;
            try { uploadLegacyProbe = detectLegacyIapp(src); } catch(Exception ignored) {}
            try { uploadAntiProbe = detectAntiQiushuiProbe(src); } catch(Exception ignored) {}
            boolean requestedAncient = "ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))
                    || optBool(options, "legacy_iapp")
                    || optBool(options, "old_iapp")
                    || "ancient".equalsIgnoreCase(options.optString("decrypt_version", ""))
                    || "ancient".equalsIgnoreCase(options.optString("task_version", ""));
            // V117：最终上传方案以客户端明确提交参数为准；探针只可补充开启，
            // 不能把 requestedAncient 覆盖回 V3。
            boolean strictOldUpload = requestedAncient || (uploadLegacyProbe != null && uploadLegacyProbe.oldIapp);
            if (strictOldUpload) {
                options.put("decrypt_scheme", "ancient");
                options.put("decrypt_version", "ancient");
                options.put("task_version", "ancient");
                options.put("client_final_scheme", "ancient");
                options.put("client_scheme_explicit", true);
                options.put("client_route_lock", "ancient-shared-v126");
                options.put("legacy_iapp", true);
                options.put("old_iapp", true);
                options.put("old_iapp_auto_detected", uploadLegacyProbe != null && uploadLegacyProbe.oldIapp);
                String legacySokey = uploadLegacyProbe == null || uploadLegacyProbe.sokey == null ? "" : uploadLegacyProbe.sokey.trim();
                String existingSokey = options.optString("old_sokey", "").trim();
                if (!existingSokey.matches("[A-Za-z0-9]{4}")) existingSokey = options.optString("sokey", "").trim();
                if (!existingSokey.matches("[A-Za-z0-9]{4}")) existingSokey = options.optString("hidden", "").trim();
                if (!existingSokey.matches("[A-Za-z0-9]{4}")) existingSokey = options.optString("client_sokey", "").trim();
                options.remove("hidden");
                options.remove("client_sokey");
                if (!optBool(options, "server_sokey") && !optBool(options, "sokey_enum")) {
                    String oldKey = legacySokey.matches("[A-Za-z0-9]{4}") ? legacySokey : existingSokey;
                    if (oldKey.matches("[A-Za-z0-9]{4}")) {
                        options.put("sokey", oldKey);
                        options.put("old_sokey", oldKey);
                    } else {
                        options.put("client_old_plaintext_sokey_auto", true);
                    }
                }
                String oldDexKey = options.optString("fb", "").trim();
                if (oldDexKey.length() == 0) oldDexKey = options.optString("dexkey", "").trim();
                if (oldDexKey.length() == 0) oldDexKey = options.optString("client_dexkey", "").trim();
                if (oldDexKey.length() == 0 && !optBool(options, "dexkey_enum") && !optBool(options, "dex_enum")) {
                    // 远古缺少 dexkey 时不自动枚举。正常 UI 会要求填写“dexkey参数”。
                    options.remove("client_old_dexkey_enum_auto");
                    options.put("client_old_dexkey_parameter_required", true);
                }
            } else {
                options.put("decrypt_scheme", "v3");
                options.put("decrypt_version", "v3");
                options.put("task_version", "v3");
                // V114：探针只记录样本特征，不能在提交阶段把用户已经关闭的
                // “反加密样本”重新开启。服务端严格使用最终提交的参数。
                if (uploadAntiProbe != null && uploadAntiProbe.qiushuiLike) {
                    options.put("client_hidden_resource_detected", true);
                }
            }
            boolean ancientForUpload = "ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))
                    || optBool(options, "legacy_iapp") || optBool(options, "old_iapp");
            boolean staticAnalysisUpload = !ancientForUpload && (
                    optBool(options, "anti_encrypted_sample")
                    || optBool(options, "anti_qiushui")
                    || optBool(options, "hidden_resource_restore")
                    || optBool(options, "static_resource_analysis")
                    || optBool(options, "static_parameter_analysis"));
            if (staticAnalysisUpload) {
                // A compact APK cannot be generic here: hidden resource paths may
                // be outside assets/, and parameter normalization may live in any
                // classes*.dex or auxiliary ABI SO.  Upload an exact temporary copy
                // so the server can analyse the whole package without mutating the
                // user's original file.
                File full = File.createTempFile("iapt_v3_apk_", ".apk");
                InputStream in = new BufferedInputStream(new FileInputStream(src), 1024 * 1024);
                OutputStream out = new BufferedOutputStream(new FileOutputStream(full), 1024 * 1024);
                try { copyStream(in, out, new byte[1024 * 1024]); }
                finally {
                    try { in.close(); } catch(Exception ignored) {}
                    try { out.close(); } catch(Exception ignored) {}
                }
                options.put("client_full_apk_uploaded", true);
                options.put("client_upload_mode", "full-apk-static-resource-parameter-v1");
                options.put("client_all_dex_uploaded", true);
                options.put("client_all_native_so_uploaded", true);
                options.put("client_all_resource_entries_uploaded", true);
                options.put("require_dex_upload", true);
                return full;
            }
            boolean includeDex = shouldUploadDexForV3(options);
            // v68：resources.arsc 固定上传，用于服务端/客户端按资源表解析应用名；不要只用 manifest XML。
            boolean includeArsc = true;
            File tmp = File.createTempFile("iapt_v3_apk_", ".apk");
            ZipFile z = new ZipFile(src);
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024));
            byte[] buf = new byte[1024 * 1024];
            boolean foundDex = false, foundManifest = false, foundYgs = false;
            HashSet<String> added = new HashSet<String>();
            try {
                HashMap<String, String> lowerToName = new HashMap<String, String>();
                ArrayList<String> names = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String name = e.getName();
                    names.add(name);
                    lowerToName.put(name.toLowerCase(Locale.US), name);
                }
                Collections.sort(names);
                boolean antiRequestedForUpload = optBool(options, "anti_encrypted_sample")
                        || optBool(options, "anti_qiushui")
                        || optBool(options, "hidden_resource_restore");
                boolean skipAntiResourceFiles = optBool(options, "no_decrypt_resource_files")
                        || optBool(options, "skip_anti_resources");
                // IAPT_CLIENT_ANTI_ASSETS_V118_BEGIN
                // Keep original assets bytes. Local hidden-container restoration is
                // intentionally disabled: a failed restore used to discard the
                // ciphertext/sidecar and leave only an empty assets/lib.so.
                options.remove("client_hidden_local_restore_failed");
                options.remove("client_hidden_local_restore_error");
                options.remove("client_hidden_compact_normalized");
                options.remove("client_hidden_compact_report");
                if (!ancientForUpload && antiRequestedForUpload) {
                    options.put("client_hidden_local_restore_skipped", true);
                    options.put("client_hidden_upload_mode", "full-assets-original-v118");
                }
                String manifestName = lowerToName.get("androidmanifest.xml");
                if (manifestName != null) {
                    copyZipEntry(z, zos, manifestName, buf, added);
                    foundManifest = true;
                }
                if (includeArsc) {
                    String arscName = lowerToName.get("resources.arsc");
                    if (arscName != null) {
                        copyZipEntry(z, zos, arscName, buf, added);
                        options.put("client_arsc_uploaded", true);
                    } else {
                        options.put("client_arsc_uploaded", false);
                        options.put("client_arsc_missing", true);
                    }
                }
                // IAPT_CLIENT_ANTI_ASSETS_V118_END
                if (!ancientForUpload) {
                    for (int i = 0; i < names.size(); i++) {
                        String name = names.get(i);
                        String nl = name.toLowerCase(Locale.US);
                        if (nl.startsWith("meta-inf/")) copyZipEntry(z, zos, name, buf, added);
                    }
                } else {
                    options.put("client_ancient_signature_from_param", true);
                    options.put("client_ancient_minimal_upload", true);
                }
                if ("ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))) {
                    String schemeMarker = "META-INF/iapt/decrypt_scheme_ancient";
                    if (!added.contains(schemeMarker)) {
                        ZipEntry marker = new ZipEntry(schemeMarker);
                        marker.setTime(0L);
                        zos.putNextEntry(marker);
                        zos.closeEntry();
                        added.add(schemeMarker);
                    }
                }
                if (optBool(options, "anti_encrypted_sample")
                        || optBool(options, "anti_qiushui")
                        || optBool(options, "hidden_resource_restore")) {
                    String antiMarker = "META-INF/iapt/anti_encrypted_sample";
                    if (!added.contains(antiMarker)) {
                        ZipEntry marker = new ZipEntry(antiMarker);
                        marker.setTime(0L);
                        zos.putNextEntry(marker);
                        zos.closeEntry();
                        added.add(antiMarker);
                    }
                    options.put("client_anti_probe", "marker-v10");
                    if (skipAntiResourceFiles) {
                        String skipMarker = "META-INF/iapt/no_decrypt_resource_files";
                        if (!added.contains(skipMarker)) {
                            ZipEntry marker = new ZipEntry(skipMarker);
                            marker.setTime(0L);
                            zos.putNextEntry(marker);
                            zos.closeEntry();
                            added.add(skipMarker);
                        }
                        options.put("client_no_decrypt_resource_files_marker", true);
                    }
                }
                // IAPT_CLIENT_ANTI_ASSETS_V118_UPLOAD_BEGIN
                int uploadedAssetCount = 0;
                long uploadedAssetBytes = 0L;
                if (!ancientForUpload && antiRequestedForUpload) {
                    // Opening anti-encrypted mode always uploads every original
                    // assets/** member. no_decrypt_resource_files controls server
                    // restoration/output only; it never removes upload evidence.
                    for (int i = 0; i < names.size(); i++) {
                        String n = names.get(i);
                        String low = n.replace('\\', '/').toLowerCase(Locale.US);
                        if (!low.startsWith("assets/")) continue;
                        ZipEntry entry = z.getEntry(n);
                        if (entry == null || entry.isDirectory()) continue;
                        boolean wasAdded = added.contains(n);
                        copyZipEntry(z, zos, n, buf, added);
                        if (!wasAdded) {
                            uploadedAssetCount++;
                            uploadedAssetBytes += Math.max(0L, entry.getSize());
                        }
                    }
                    options.put("client_assets_all_uploaded", true);
                    options.put("client_assets_uploaded_count", uploadedAssetCount);
                    options.put("client_assets_uploaded_bytes", uploadedAssetBytes);
                    options.put("client_resource_upload", true);
                    options.put("client_resource_decrypt_requested", !skipAntiResourceFiles);
                } else {
                    // Normal V3/ancient keeps the lightweight rule: only lib.so
                    // from assets; every other assets member is omitted.
                    String n = lowerToName.get("assets/lib.so");
                    if (n != null) copyZipEntry(z, zos, n, buf, added);
                    options.put("client_assets_all_uploaded", false);
                    options.put("client_resource_upload", false);
                }

                String canonicalCipher = lowerToName.get("assets/lib.so");
                ZipEntry canonicalEntry = canonicalCipher == null ? null : z.getEntry(canonicalCipher);
                boolean canonicalUsable = canonicalEntry != null
                        && !canonicalEntry.isDirectory()
                        && canonicalEntry.getSize() >= 64L;
                if (canonicalUsable) {
                    options.put("client_cipher_entry", canonicalCipher);
                    options.put("client_cipher_locator", "canonical-v118");
                    options.put("client_cipher_obfuscated", false);
                    options.put("client_cipher_size", canonicalEntry.getSize());
                    options.put("client_hidden_wrapper_uploaded", false);
                } else if (antiRequestedForUpload) {
                    String relocatedCipher = selectObfuscatedIappContainer(z, names);
                    if (relocatedCipher == null) {
                        if (canonicalEntry != null && canonicalEntry.getSize() < 64L) {
                            throw new Exception("assets/lib.so是空占位文件，且assets内没有可恢复的隐藏容器");
                        }
                        throw new Exception("没有找到lib.so文件或隐藏容器");
                    }
                    // assets/** is already present; these idempotent copies collect
                    // exact wrapper/sidecar metadata without changing the payload.
                    copyZipEntry(z, zos, relocatedCipher, buf, added);
                    ZipEntry ce = z.getEntry(relocatedCipher);
                    JSONArray sidecars = new JSONArray();
                    int sidecarCount = copyObfuscatedContainerSidecars(
                            z, zos, names, relocatedCipher, buf, added, sidecars);
                    options.put("client_cipher_entry", relocatedCipher);
                    options.put("client_cipher_locator", sidecarCount > 0
                            ? "long-path-sidecar-v118" : "long-path-wrapper-v118");
                    options.put("client_cipher_obfuscated", true);
                    options.put("client_cipher_sidecar_entries", sidecars);
                    options.put("client_cipher_sidecar_count", sidecarCount);
                    options.put("client_hidden_wrapper_uploaded", true);
                    if (ce != null) options.put("client_cipher_size", ce.getSize());
                } else if (canonicalEntry != null) {
                    throw new Exception("assets/lib.so为空或过短，请开启反加密样本");
                } else {
                    options.put("client_lib_so_missing", true);
                    throw new Exception("没有找到lib.so文件，请开启反加密样本");
                }
                // IAPT_CLIENT_ANTI_ASSETS_V118_UPLOAD_END

                // v2.8.5：server_sokey 不再只依赖任务 options。
                // 某些服务端版本会在参数白名单阶段丢掉 server_sokey，
                // 因此在轻量 APK 里写入一个零字节内部标记作为可靠传输信号。
                if (optBool(options, "server_sokey")) {
                    String markerName = "META-INF/iapt/server_sokey";
                    if (!added.contains(markerName)) {
                        ZipEntry markerEntry = new ZipEntry(markerName);
                        markerEntry.setTime(0L);
                        zos.putNextEntry(markerEntry);
                        zos.closeEntry();
                        added.add(markerName);
                    }
                    options.put("client_server_sokey_marker", true);
                }

                // sokey 枚举和“服务器获取 sokey”都依赖 /bsh/util/lib/ 的原始 ZIP mtime。
                // packed libygsiyu.so 中可能看不到明文 sokey，必须把时间戳条目一起上传。
                if (optBool(options, "sokey_enum") || optBool(options, "server_sokey")) {
                    int bshCount = 0;
                    for (int i = 0; i < names.size(); i++) {
                        String name = names.get(i);
                        String nl = name.toLowerCase(Locale.US).replace('\\', '/');
                        if (nl.indexOf("bsh/util/lib/") >= 0) {
                            copyZipEntry(z, zos, name, buf, added);
                            bshCount++;
                        }
                    }
                    options.put("client_bsh_mtime_entries", bshCount);
                    if (bshCount <= 0) {
                        if (optBool(options, "sokey_enum")) {
                            throw new Exception("APK缺少 /bsh/util/lib/ 时间戳条目，无法进行 so 密钥枚举");
                        }
                        options.put("client_server_sokey_without_mtime", true);
                    }
                }
                // IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_BEGIN
                // 普通解密在“服务器动态 Key”模式下也上传全部 ABI 的 libygsiyu.so。
                // 上传内容仍是轻量 APK：Manifest、resources.arsc、必要 assets、SO，
                // 不会因为动态 Key 而额外上传 DEX。
                int uploadedYgsCount = 0;
                boolean ancientUpload = "ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))
                        || optBool(options, "legacy_iapp")
                        || optBool(options, "old_iapp");
                boolean serverExtractSample = !ancientUpload
                        && optBool(options, "dynamic_key")
                        && !optBool(options, "custom_dynamic_key")
                        && options.optString("server_key_pool_mode", "").trim().length() == 0;

                ArrayList<String> allYgsEntries = new ArrayList<String>();
                for (int yi = 0; yi < names.size(); yi++) {
                    String yn = names.get(yi);
                    String yl = yn.replace('\\', '/').toLowerCase(Locale.US);
                    if ((yl.startsWith("lib/") && yl.endsWith("/libygsiyu.so"))
                            || "libygsiyu.so".equals(yl)) {
                        allYgsEntries.add(yn);
                    }
                }
                Collections.sort(allYgsEntries, new Comparator<String>() {
                    public int compare(String left, String right) {
                        int lp = ygsiyuUploadPriority(left);
                        int rp = ygsiyuUploadPriority(right);
                        if (lp != rp) return lp - rp;
                        return left.compareToIgnoreCase(right);
                    }
                });

                String requestedYgs = serverExtractSample
                        ? options.optString("dynamic_key_sample_entry", "").trim() : "";
                String ygs = null;
                if (requestedYgs.length() > 0 && z.getEntry(requestedYgs) != null) {
                    ygs = requestedYgs;
                }
                if (ygs == null) ygs = selectOneYgsiyuSo(names);

                JSONArray uploadedSoEntries = new JSONArray();
                if (ancientUpload) {
                    // V102：远古普通解密不再上传 libygsiyu.so。4位 sokey、dexkey、签名证书均由客户端从原 APK 提取并作为参数提交。
                    // 开启 sokey枚举时仅额外上传 /bsh/util/lib/ 时间戳目录文件；不上传全部 ABI SO。
                    foundYgs = true;
                    options.put("client_upload_one_abi", false);
                    options.put("client_upload_all_abis", false);
                    options.put("client_uploaded_so_entries", uploadedSoEntries);
                    options.put("client_uploaded_so_count", 0);
                    options.put("client_old_multiabi_sokey", false);
                    options.put("client_ancient_no_libygsiyu_upload", true);
                } else if (serverExtractSample) {
                    // 数据流解析以多 ABI 共识为准；仅复制 libygsiyu.so，不复制其它 ABI 的附属库。
                    for (int yi = 0; yi < allYgsEntries.size(); yi++) {
                        String entry = allYgsEntries.get(yi);
                        ZipEntry ye = z.getEntry(entry);
                        if (ye == null || ye.isDirectory()) continue;
                        copyZipEntry(z, zos, entry, buf, added);
                        uploadedSoEntries.put(entry);
                        uploadedYgsCount++;
                    }
                    foundYgs = uploadedYgsCount > 0;
                    options.put("client_upload_one_abi", false);
                    options.put("client_upload_all_abis", true);
                    options.put("dynamic_key_parser", "dataflow-v3");
                    options.put("dynamic_key_multiabi_consensus", true);
                    options.put("client_uploaded_so_entries", uploadedSoEntries);
                } else if (ygs != null) {
                    copyZipEntry(z, zos, ygs, buf, added);
                    uploadedSoEntries.put(ygs);
                    uploadedYgsCount = 1;
                    foundYgs = true;
                    options.put("client_upload_one_abi", true);
                    options.put("client_upload_all_abis", false);
                    options.put("client_uploaded_so_entries", uploadedSoEntries);
                } else {
                    options.put("client_upload_one_abi", true);
                    options.put("client_upload_all_abis", false);
                }

                if (!ancientUpload && ygs != null) {
                    options.put("client_uploaded_so", ygs);

                    // 附属 native 库仍只携带主 ABI，避免把普通解密上传体积放大。
                    String ygsNorm = ygs.replace('\\','/');
                    int ygsSlash = ygsNorm.lastIndexOf('/');
                    String abiPrefix = ygsSlash >= 0 ? ygsNorm.substring(0, ygsSlash + 1) : "";
                    JSONArray auxEntries = new JSONArray();
                    long auxBytes = 0L;
                    int auxCount = 0;
                    final HashMap<String,Integer> auxScores = new HashMap<String,Integer>();
                    final ZipFile zAuxFinal = z;
                    ArrayList<String> auxCandidates = new ArrayList<String>();
                    for (int ai = 0; ai < names.size(); ai++) {
                        String aux = names.get(ai);
                        String auxNorm = aux.replace('\\','/');
                        String auxLow = auxNorm.toLowerCase(Locale.US);
                        if (auxNorm.equals(ygsNorm) || !auxNorm.startsWith(abiPrefix) || !auxLow.endsWith(".so")) continue;
                        String base = auxLow.substring(auxLow.lastIndexOf('/') + 1);
                        if (isCommonRuntimeNativeLibrary(base)) continue;
                        ZipEntry ae = z.getEntry(aux);
                        if (ae == null || ae.isDirectory()) continue;
                        long sz = ae.getSize();
                        if (sz <= 0 || sz > 4L * 1024L * 1024L) continue;
                        if (!zipEntryIsElf(z, ae)) continue;
                        int score = nativeAuxRelevanceScore(z, ae, base);
                        auxCandidates.add(aux);
                        auxScores.put(aux, Integer.valueOf(score));
                    }
                    Collections.sort(auxCandidates, new Comparator<String>() {
                        public int compare(String a1, String b1) {
                            int sa = auxScores.containsKey(a1) ? auxScores.get(a1).intValue() : 0;
                            int sb = auxScores.containsKey(b1) ? auxScores.get(b1).intValue() : 0;
                            if (sa != sb) return sb - sa;
                            ZipEntry ea = zAuxFinal.getEntry(a1), eb = zAuxFinal.getEntry(b1);
                            long za = ea == null ? Long.MAX_VALUE : Math.max(0L, ea.getSize());
                            long zb = eb == null ? Long.MAX_VALUE : Math.max(0L, eb.getSize());
                            if (za != zb) return za < zb ? -1 : 1;
                            return a1.compareToIgnoreCase(b1);
                        }
                    });
                    for (int ai = 0; ai < auxCandidates.size() && auxCount < 6; ai++) {
                        String aux = auxCandidates.get(ai);
                        ZipEntry ae = z.getEntry(aux);
                        if (ae == null || ae.isDirectory()) continue;
                        long sz = ae.getSize();
                        if (sz <= 0 || auxBytes + sz > 8L * 1024L * 1024L) continue;
                        copyZipEntry(z, zos, aux, buf, added);
                        auxEntries.put(aux);
                        auxBytes += sz;
                        auxCount++;
                    }
                    options.put("client_aux_native_entries", auxEntries);
                    options.put("client_aux_native_count", auxCount);
                    options.put("client_aux_native_bytes", auxBytes);
                    options.put("client_aux_native_abi", Api.dynamicSoAbi(ygs, null));
                }
                options.put("client_uploaded_so_count", uploadedYgsCount);
                // IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_END
                if (includeDex) {
                    ArrayList<String> dexNames = new ArrayList<String>();
                    for (int i = 0; i < names.size(); i++) {
                        String name = names.get(i);
                        String simple = name;
                        int slash = simple.lastIndexOf('/');
                        if (slash >= 0) simple = simple.substring(slash + 1);
                        if (isDexFileName(simple)) dexNames.add(name);
                    }
                    Collections.sort(dexNames, new Comparator<String>() { public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }});
                    boolean onlyFbFallback = optBool(options, "client_fb_dex_fallback")
                            && !optBool(options, "force_upload_dex")
                            && !optBool(options, "require_dex_upload")
                            && "off".equals(options.optString("restore_fn_names", "off").trim().toLowerCase(Locale.US));
                    if (onlyFbFallback && dexNames.size() > 0) {
                        String selectedDex = null;
                        byte[] targetClass = "Lcom/iapp/app/f;".getBytes("UTF-8");
                        for (int i = 0; i < dexNames.size(); i++) {
                            if (zipEntryContains(z, dexNames.get(i), targetClass, 128L * 1024L * 1024L)) {
                                selectedDex = dexNames.get(i);
                                break;
                            }
                        }
                        if (selectedDex == null) selectedDex = dexNames.get(0);
                        copyZipEntry(z, zos, selectedDex, buf, added);
                        foundDex = true;
                        options.put("client_upload_dex_mode", "fb_fallback_one");
                        options.put("client_uploaded_dex", selectedDex);
                    } else {
                        for (int i = 0; i < dexNames.size(); i++) { copyZipEntry(z, zos, dexNames.get(i), buf, added); foundDex = true; }
                        options.put("client_upload_dex_mode", "all_required");
                    }
                }
                options.put("client_upload_dex", includeDex);
                options.put("client_upload_arsc", includeArsc);
                options.put("client_light_apk", true);
            } finally {
                try { z.close(); } catch(Exception ex) {}
                try { zos.close(); } catch(Exception ex) {}
            }
            if (!foundManifest) throw new Exception("APK缺少 AndroidManifest.xml");
            // 默认不再把 DEX 作为必需上传项；dex密钥/动态key均不需要 DEX；仅动态修复开启时才强制要求 DEX。
            if (includeDex && !foundDex && optBool(options, "require_dex_upload")) throw new Exception("当前功能需要上传 DEX，但 APK 缺少 classes.dex");
            boolean allowMissingYgs = false;
            String poolMode = options.optString("server_key_pool_mode", "").trim().toLowerCase(Locale.US);
            boolean ancientUploadFinal = "ancient".equalsIgnoreCase(options.optString("decrypt_scheme", ""))
                    || optBool(options, "legacy_iapp")
                    || optBool(options, "old_iapp");
            if ("enum".equals(poolMode) || "selected".equals(poolMode)) allowMissingYgs = true;
            if (optBool(options, "custom_dynamic_key") && options.optString("post_key", "").trim().length() > 0 && options.optString("xor_key", "").trim().length() > 0) allowMissingYgs = true;
            if (ancientUploadFinal) {
                // V102：远古不依赖服务端 libygsiyu.so 提取；客户端已经提交 sokey/dexkey/signature 参数。
                allowMissingYgs = true;
            }
            if (!foundYgs && !allowMissingYgs) throw new Exception("APK缺少 libygsiyu.so；可改用服务器动态 Key 池或自定义动态 Key");
            return tmp;
        }

        static boolean shouldUploadDexForV3(JSONObject options) {
            if (options == null) return false;
            if (optBool(options, "skip_dex_upload") || optBool(options, "no_dex_upload")) return false;
            // IAPT_CLIENT_DEX_UPLOAD_V118: upload classes*.dex only when
            // dynamic/numeric restoration is explicitly enabled.
            return optBool(options, "require_dex_upload")
                    || optBool(options, "static_resource_analysis")
                    || optBool(options, "static_parameter_analysis")
                    || optBool(options, "anti_encrypted_sample")
                    || optBool(options, "hidden_resource_restore")
                    || optBool(options, "dynamic_restore")
                    || optBool(options, "v3_dynamic_restore")
                    || optBool(options, "ancient_dynamic_restore")
                    || optBool(options, "numeric_restore")
                    || optBool(options, "iapec_numeric_dynamic_restore")
                    || optBool(options, "native_compile_restore")
                    || optBool(options, "v3_native_compile_restore")
                    || optBool(options, "ancient_native_compile_restore");
        }

        static boolean optBool(JSONObject o, String key) {
            try {
                Object v = o.opt(key);
                if (v instanceof Boolean) return ((Boolean)v).booleanValue();
                if (v instanceof Number) return ((Number)v).intValue() != 0;
                String s = o.optString(key, "").trim().toLowerCase(Locale.US);
                return "1".equals(s) || "true".equals(s) || "yes".equals(s) || "on".equals(s);
            } catch(Exception e) { return false; }
        }

        static File prepareSourceZip(File srcDir) throws Exception {
            if (srcDir == null || !srcDir.exists() || !srcDir.isDirectory()) throw new Exception("src 目录不存在");
            File tmp = File.createTempFile("iapt_src_", ".zip");
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024));
            int[] count = new int[]{0};
            try {
                zipSourceDir(srcDir, srcDir, zos, count);
            } finally {
                try { zos.close(); } catch(Exception e) {}
            }
            if (count[0] <= 0) {
                try { tmp.delete(); } catch(Exception e) {}
                throw new Exception("src 目录为空");
            }
            return tmp;
        }

        static File prepareSourceProjectZip(File projectDir, boolean includeRes) throws Exception {
            if (projectDir == null || !projectDir.exists() || !projectDir.isDirectory()) throw new Exception("项目目录不存在");
            File srcDir = new File(projectDir, "src");
            if (!srcDir.exists() || !srcDir.isDirectory()) throw new Exception("项目目录下没有 src");
            File resDir = new File(projectDir, "res");
            if (includeRes && (!resDir.exists() || !resDir.isDirectory())) throw new Exception("项目目录下没有 res");
            File tmp = File.createTempFile("iapt_project_", ".zip");
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024));
            int[] count = new int[]{0};
            try {
                zipDirWithPrefix(srcDir, srcDir, "src/", zos, count);
                if (includeRes) zipDirWithPrefix(resDir, resDir, "res/", zos, count);
            } finally {
                try { zos.close(); } catch(Exception e) {}
            }
            if (count[0] <= 0) {
                try { tmp.delete(); } catch(Exception e) {}
                throw new Exception("项目源码为空");
            }
            return tmp;
        }

        static File prepareNativeCompileProjectZip(File projectDir, boolean includeRes) throws Exception {
            if (projectDir == null || !projectDir.exists() || !projectDir.isDirectory()) throw new Exception("项目目录不存在");
            File srcDir = new File(projectDir, "src");
            if (!srcDir.exists() || !srcDir.isDirectory()) throw new Exception("项目目录下没有 src");
            File resDir = new File(projectDir, "res");
            File tmp = File.createTempFile("iapt_native_compile_", ".zip");
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp), 1024 * 1024));
            int[] count = new int[]{0};
            try {
                zipDirWithPrefix(srcDir, srcDir, "src/", zos, count);
                if (includeRes && resDir.exists() && resDir.isDirectory()) zipDirWithPrefix(resDir, resDir, "res/", zos, count);
                String[] metadataNames = new String[]{"old_iapp_report.json", "project_metadata.txt"};
                byte[] buf = new byte[1024 * 1024];
                for (int i = 0; i < metadataNames.length; i++) {
                    File meta = new File(projectDir, metadataNames[i]);
                    if (!meta.isFile()) continue;
                    ZipEntry ze = new ZipEntry(metadataNames[i]);
                    zos.putNextEntry(ze);
                    InputStream in = new BufferedInputStream(new FileInputStream(meta), 1024 * 1024);
                    try { copyStream(in, zos, buf); }
                    finally { try { in.close(); } catch(Exception ignored) {} }
                    zos.closeEntry();
                    count[0]++;
                }
            } finally {
                try { zos.close(); } catch(Exception e) {}
            }
            if (count[0] <= 0) {
                try { tmp.delete(); } catch(Exception e) {}
                throw new Exception("项目源码为空");
            }
            return tmp;
        }

        static File prepareDexRestoreProjectZip(File projectDir, boolean includeRes) throws Exception {
            DexReadableAlias.BuildResult result = DexReadableAlias.buildProjectZip(projectDir, includeRes);
            return result.zip;
        }


        static void zipSourceDir(File root, File cur, ZipOutputStream zos, int[] count) throws Exception {
            File[] arr = cur.listFiles();
            if (arr == null) return;
            byte[] buf = new byte[1024 * 1024];
            for (int i = 0; i < arr.length; i++) {
                File f = arr[i];
                if (f == null) continue;
                if (f.isDirectory()) {
                    zipSourceDir(root, f, zos, count);
                    continue;
                }
                String rel = root.toURI().relativize(f.toURI()).getPath();
                if (rel == null || rel.length() == 0) continue;
                ZipEntry ze = new ZipEntry(rel);
                try { ze.setTime(f.lastModified()); } catch(Exception e) {}
                zos.putNextEntry(ze);
                FileInputStream in = new FileInputStream(f);
                try { copyStream(in, zos, buf); }
                finally { try { in.close(); } catch(Exception e) {} }
                zos.closeEntry();
                count[0]++;
            }
        }

        static void zipDirWithPrefix(File sourceRoot, File cur, String prefix, ZipOutputStream zos, int[] count) throws Exception {
            if (sourceRoot == null || cur == null) return;
            File[] arr = cur.listFiles();
            if (arr == null) return;
            byte[] buf = new byte[1024 * 1024];
            String normalizedPrefix = prefix == null ? "" : prefix.replace('\\', '/');
            while (normalizedPrefix.startsWith("/")) normalizedPrefix = normalizedPrefix.substring(1);
            if (normalizedPrefix.length() > 0 && !normalizedPrefix.endsWith("/")) normalizedPrefix += "/";
            for (int i = 0; i < arr.length; i++) {
                File f = arr[i];
                if (f == null) continue;
                if (f.isDirectory()) {
                    zipDirWithPrefix(sourceRoot, f, normalizedPrefix, zos, count);
                    continue;
                }
                String childRel = sourceRoot.toURI().relativize(f.toURI()).getPath();
                if (childRel == null || childRel.length() == 0 || childRel.startsWith("/") || childRel.startsWith("../") || childRel.contains("/../")) continue;
                String rel = normalizedPrefix + childRel;
                if (rel.length() == 0 || rel.startsWith("/") || rel.startsWith("../") || rel.contains("/../")) continue;
                ZipEntry ze = new ZipEntry(rel);
                try { ze.setTime(f.lastModified()); } catch(Exception e) {}
                zos.putNextEntry(ze);
                FileInputStream in = new FileInputStream(f);
                try { copyStream(in, zos, buf); }
                finally { try { in.close(); } catch(Exception e) {} }
                zos.closeEntry();
                count[0]++;
            }
        }

        static int dexOrder(String name) {
            try {
                String simple = name;
                int slash = simple.lastIndexOf('/');
                if (slash >= 0) simple = simple.substring(slash + 1);
                if ("classes.dex".equals(simple)) return 1;
                String n = simple.replace("classes", "").replace(".dex", "");
                return Integer.parseInt(n);
            } catch(Exception e) { return 9999; }
        }

        static boolean isCommonRuntimeNativeLibrary(String baseLower) {
            if (baseLower == null) return true;
            String b = baseLower.toLowerCase(Locale.US);
            return "libygsiyu.so".equals(b)
                    || "libpl_droidsonroids_gif.so".equals(b)
                    || "libc++_shared.so".equals(b)
                    || "libgnustl_shared.so".equals(b)
                    || "libstlport_shared.so".equals(b)
                    || "libsqlite.so".equals(b)
                    || b.startsWith("libwebview")
                    || b.startsWith("libflutter")
                    || b.startsWith("libunity");
        }

        static int nativeAuxRelevanceScore(ZipFile z, ZipEntry e, String baseLower) {
            int score = 0;
            if (e == null) return score;
            long size = Math.max(0L, e.getSize());
            if (size > 0 && size <= 512L * 1024L) score += 8;
            else if (size <= 2L * 1024L * 1024L) score += 3;
            String b = baseLower == null ? "" : baseLower.toLowerCase(Locale.US);
            if (b.indexOf("vm") >= 0 || b.indexOf("guard") >= 0 || b.indexOf("protect") >= 0) score += 2;
            byte[][] markers = new byte[][]{
                "vmInterpret".getBytes(), "cacheInitial".getBytes(), "getCacheClass".getBytes(),
                "RegisterNatives".getBytes(), "JNI_OnLoad".getBytes(), "com/iapp/app/f".getBytes(),
                "LuaStateFactory".getBytes(), "lib.so".getBytes(), "AssetManager".getBytes(),
                "AES/CBC".getBytes(), "doFinal".getBytes()
            };
            try {
                for (int i = 0; i < markers.length; i++) {
                    if (zipEntryContains(z, e.getName(), markers[i], 4L * 1024L * 1024L)) score += (i < 5 ? 12 : 6);
                }
            } catch(Exception ignored) {}
            return score;
        }

        static boolean zipEntryIsElf(ZipFile z, ZipEntry e) {
            InputStream in = null;
            try {
                in = z.getInputStream(e);
                byte[] h = new byte[4];
                return in.read(h) == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F';
            } catch(Exception ignored) { return false; }
            finally { try { if (in != null) in.close(); } catch(Exception ignored) {} }
        }

        static int ygsiyuUploadPriority(String name) {
            String nl = name == null ? "" : name.replace('\\','/').toLowerCase(Locale.US);
            if (nl.equals("lib/x86/libygsiyu.so")) return 1;
            if (nl.equals("lib/x86_64/libygsiyu.so")) return 2;
            if (nl.equals("lib/armeabi-v7a/libygsiyu.so")) return 3;
            if (nl.equals("lib/arm64-v8a/libygsiyu.so")) return 4;
            if (nl.startsWith("lib/") && nl.endsWith("/libygsiyu.so")) return 20;
            if (nl.endsWith("/libygsiyu.so") || nl.equals("libygsiyu.so")) return 30;
            return 999;
        }

        static String selectOneYgsiyuSo(ArrayList<String> names) {
            // 精简上传只携带一个 SO，服务器不会执行该 SO，只做静态分析。
            // 当前 x86/x86_64 表布局最稳定，兼容长 post/xor 与 dexkey C 枚举；优先 x86，其次 x86_64。
            // 没有 x86/x86_64 时再尝试 armeabi-v7a，最后才使用 arm64-v8a。
            // 独立“动态 Key 提取”仍走 SO-only 多 ABI 打包路径，不受这里影响。
            String[] prefer = new String[]{"lib/x86/libygsiyu.so", "lib/x86_64/libygsiyu.so", "lib/armeabi-v7a/libygsiyu.so", "lib/arm64-v8a/libygsiyu.so"};
            for (int i = 0; i < prefer.length; i++) {
                for (int j = 0; j < names.size(); j++) if (prefer[i].equals(names.get(j).toLowerCase(Locale.US))) return names.get(j);
            }
            for (int j = 0; j < names.size(); j++) {
                String nl = names.get(j).replace('\\','/').toLowerCase(Locale.US);
                if (nl.startsWith("lib/") && nl.endsWith("/libygsiyu.so")) return names.get(j);
            }
            // 部分样本会把 SO 藏到非标准目录；最后按文件基名匹配。
            for (int j = 0; j < names.size(); j++) {
                String nl = names.get(j).replace('\\','/').toLowerCase(Locale.US);
                int slash = nl.lastIndexOf('/');
                String base = slash >= 0 ? nl.substring(slash + 1) : nl;
                if ("libygsiyu.so".equals(base)) return names.get(j);
            }
            return null;
        }

        static boolean zipEntryContains(ZipFile z, String name, byte[] needle, long maxBytes) {
            if (z == null || name == null || needle == null || needle.length == 0) return false;
            InputStream in = null;
            try {
                ZipEntry e = z.getEntry(name);
                if (e == null || e.isDirectory() || e.getSize() > maxBytes) return false;
                in = new BufferedInputStream(z.getInputStream(e), 64 * 1024);
                byte[] buf = new byte[64 * 1024];
                int matched = 0;
                long total = 0;
                for (;;) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    total += n;
                    if (total > maxBytes) return false;
                    for (int i = 0; i < n; i++) {
                        byte b = buf[i];
                        if (b == needle[matched]) {
                            matched++;
                            if (matched == needle.length) return true;
                        } else {
                            matched = (b == needle[0]) ? 1 : 0;
                        }
                    }
                }
            } catch(Exception ignored) {
            } finally {
                try { if (in != null) in.close(); } catch(Exception ignored) {}
            }
            return false;
        }

        static void copyZipEntry(ZipFile z, ZipOutputStream zos, String name, byte[] buf, HashSet<String> added) throws Exception {
            if (name == null || added.contains(name)) return;
            ZipEntry e = z.getEntry(name);
            if (e == null || e.isDirectory()) return;
            ZipEntry ne = new ZipEntry(name);
            try { ne.setTime(e.getTime()); } catch(Exception ex) {}
            zos.putNextEntry(ne);
            InputStream in = new BufferedInputStream(z.getInputStream(e), 1024 * 1024);
            try { copyStream(in, zos, buf); }
            finally { try { in.close(); } catch(Exception ex) {} }
            zos.closeEntry();
            added.add(name);
        }

        static final int NATIVE_COMPILE_RESTORE_DETECTOR_VERSION = 4;

        static class NativeCompileProbe {
            boolean nativeCompiled = false;
            String dexEntry = "";
            int eventMethodNameCount = 0;
            int sourceStringCount = 0;
            boolean aidYuCodeXPresent = false;
            String reason = "";
        }

        static NativeCompileProbe detectNativeCompile(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "native_compile_v7");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof NativeCompileProbe) return (NativeCompileProbe)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof NativeCompileProbe) return (NativeCompileProbe)cached;
                NativeCompileProbe value = detectNativeCompileUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static NativeCompileProbe detectNativeCompileUncached(File apk) throws Exception {
            NativeCompileProbe best = new NativeCompileProbe();
            if (apk == null || !apk.isFile()) return best;
            String lowFile = apk.getName().toLowerCase(Locale.US);
            if (lowFile.endsWith(".dex")) {
                NativeCompileProbe one = analyzeNativeCompileDex(
                        readFileBytes(apk, 128 * 1024 * 1024), apk.getName());
                return one == null ? best : one;
            }
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> dexNames = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String simple = e.getName().replace('\\', '/');
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    if (isDexFileName(simple)) dexNames.add(e.getName());
                }
                Collections.sort(dexNames, new Comparator<String>() {
                    public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }
                });
                for (int i = 0; i < dexNames.size(); i++) {
                    ZipEntry e = z.getEntry(dexNames.get(i));
                    if (e == null || e.getSize() > 128L * 1024L * 1024L) continue;
                    NativeCompileProbe probe = analyzeNativeCompileDex(
                            readZipEntryBytes(z, e, 128 * 1024 * 1024), e.getName());
                    if (probe == null) continue;
                    if (probe.nativeCompiled) return probe;
                    if (probe.eventMethodNameCount > best.eventMethodNameCount)
                        best = probe;
                }
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
            return best;
        }

        static boolean hasNativeEventMethodSuffix(String value) {
            if (value == null || value.length() <= 12) return false;
            int split = value.length() - 12;
            for (int i = split; i < value.length(); i++) {
                char c = value.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            }
            char first = value.charAt(0);
            return Character.isLetter(first) || first == '_' || first == '$';
        }

        static NativeCompileProbe analyzeNativeCompileDex(byte[] dex, String dexEntry) {
            NativeCompileProbe out = new NativeCompileProbe();
            out.dexEntry = dexEntry == null ? "" : dexEntry;
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return out;
                int stringIdsSize = u4(dex, 0x38), stringIdsOff = u4(dex, 0x3c);
                int typeIdsSize = u4(dex, 0x40), typeIdsOff = u4(dex, 0x44);
                int protoIdsSize = u4(dex, 0x48), protoIdsOff = u4(dex, 0x4c);
                int methodIdsSize = u4(dex, 0x58), methodIdsOff = u4(dex, 0x5c);
                if (stringIdsSize < 0 || stringIdsSize > 2000000
                        || typeIdsSize < 0 || typeIdsSize > 1000000
                        || protoIdsSize < 0 || protoIdsSize > 1000000
                        || methodIdsSize < 0 || methodIdsSize > 3000000
                        || stringIdsOff < 0 || stringIdsOff + stringIdsSize * 4L > dex.length
                        || typeIdsOff < 0 || typeIdsOff + typeIdsSize * 4L > dex.length
                        || protoIdsOff < 0 || protoIdsOff + protoIdsSize * 12L > dex.length
                        || methodIdsOff < 0 || methodIdsOff + methodIdsSize * 8L > dex.length) return out;
                String[] strings = readIndexedDexStrings(dex, stringIdsSize, stringIdsOff);
                for (int i = 0; i < strings.length; i++) {
                    String value = strings[i];
                    if ("Lcom/iapp/app/Aid_YuCodeX;".equals(value)) out.aidYuCodeXPresent = true;
                    if (value != null && value.length() >= 4 && value.length() <= 200000
                            && ((value.startsWith("(") && value.indexOf("\n{") >= 0)
                                || (value.startsWith("   ") && value.indexOf('(') >= 0))) {
                        out.sourceStringCount++;
                    }
                }
                // Count real method_ids, not arbitrary string-pool entries: the
                // event bridge must have a 12-hex suffix and an Aid_YuCodeX parameter.
                for (int i = 0; i < methodIdsSize; i++) {
                    int methodOff = methodIdsOff + i * 8;
                    int classIdx = u2(dex, methodOff);
                    int protoIdx = u2(dex, methodOff + 2);
                    int nameIdx = u4(dex, methodOff + 4);
                    if (classIdx < 0 || classIdx >= typeIdsSize
                            || protoIdx < 0 || protoIdx >= protoIdsSize
                            || nameIdx < 0 || nameIdx >= strings.length) continue;
                    String methodName = strings[nameIdx];
                    if (!hasNativeEventMethodSuffix(methodName)) continue;
                    int classStringIdx = u4(dex, typeIdsOff + classIdx * 4);
                    if ("Lcom/iapp/app/Aid_YuCodeX;".equals(safeString(strings, classStringIdx))) continue;
                    int parametersOff = u4(dex, protoIdsOff + protoIdx * 12 + 8);
                    if (parametersOff <= 0 || parametersOff + 4 > dex.length) continue;
                    int parameterCount = u4(dex, parametersOff);
                    if (parameterCount < 0 || parameterCount > 1024
                            || parametersOff + 4L + parameterCount * 2L > dex.length) continue;
                    boolean aidParameter = false;
                    for (int p = 0; p < parameterCount; p++) {
                        int typeIdx = u2(dex, parametersOff + 4 + p * 2);
                        if (typeIdx < 0 || typeIdx >= typeIdsSize) continue;
                        int typeStringIdx = u4(dex, typeIdsOff + typeIdx * 4);
                        if ("Lcom/iapp/app/Aid_YuCodeX;".equals(safeString(strings, typeStringIdx))) {
                            aidParameter = true;
                            break;
                        }
                    }
                    if (aidParameter) out.eventMethodNameCount++;
                }
                out.nativeCompiled = out.aidYuCodeXPresent && out.eventMethodNameCount > 0;
                if (out.nativeCompiled) {
                    out.reason = "app-package Aid_YuCodeX event methods with 12-hex source tokens detected";
                } else if (out.aidYuCodeXPresent) {
                    out.reason = "Aid_YuCodeX present but no 12-hex event method suffix";
                }
            } catch(Exception ignored) {}
            return out;
        }

        static final int DYNAMIC_RESTORE_DETECTOR_VERSION = 4;

        static class DynamicRestoreProbe {
            boolean dynamicEncrypted = false;
            String dexEntry = "";
            String classDescriptor = "";
            String className = "";
            int codeUnits = 0;
            int methodCount = 0;
            int commandCount = 0;
            int maxMethodCodeUnits = 0;
            int largestClassCodeUnits = 0;
            boolean baselineNumericTable = false;
            boolean randomizedNumericTable = false;
            int numericTablePairs = 0;
            int numericTableMin = 0;
            int numericTableMax = 0;
            boolean iapecRunClassPresent = false;
            int iapecNumericTokenCount = 0;
            String reason = "";
        }

        static DynamicRestoreProbe detectDynamicRestore(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "dynamic_restore_v14");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof DynamicRestoreProbe) return (DynamicRestoreProbe)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof DynamicRestoreProbe) return (DynamicRestoreProbe)cached;
                DynamicRestoreProbe value = detectDynamicRestoreUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static DynamicRestoreProbe detectDynamicRestoreUncached(File apk) throws Exception {
            DynamicRestoreProbe best = new DynamicRestoreProbe();
            if (apk == null || !apk.isFile()) return best;
            String lowFile = apk.getName().toLowerCase(Locale.US);
            if (lowFile.endsWith(".dex")) {
                DynamicRestoreProbe one = analyzeDynamicRestoreDex(readFileBytes(apk, 128 * 1024 * 1024), apk.getName());
                return one == null ? best : one;
            }

            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> dexNames = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String simple = e.getName().replace('\\', '/');
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    if (isDexFileName(simple)) dexNames.add(e.getName());
                }
                Collections.sort(dexNames, new Comparator<String>() {
                    public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }
                });
                for (int i = 0; i < dexNames.size(); i++) {
                    ZipEntry e = z.getEntry(dexNames.get(i));
                    if (e == null || e.getSize() > 128L * 1024L * 1024L) continue;
                    DynamicRestoreProbe p = analyzeDynamicRestoreDex(
                            readZipEntryBytes(z, e, 128 * 1024 * 1024), e.getName());
                    if (p == null) continue;
                    if (p.dynamicEncrypted) return p;
                    if (p.commandCount > best.commandCount
                            || (p.commandCount == best.commandCount && p.codeUnits > best.codeUnits)) {
                        best = p;
                    }
                }
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
            return best;
        }


        static class NumericTableProbe {
            boolean baseline = false;
            boolean randomized = false;
            int pairs = 0;
            int min = 0;
            int max = 0;
            int span = 0;
        }

        static int dexInsnUnits(byte[] dex, int pos, int end) {
            if (pos < 0 || pos + 2 > end) return 1;
            int word = u2(dex, pos);
            int op = word & 0xff;
            if (op == 0x00) {
                int ident = word & 0xff00;
                if (ident == 0x0100 && pos + 4 <= end) {
                    return 4 + u2(dex, pos + 2) * 2;
                }
                if (ident == 0x0200 && pos + 4 <= end) {
                    return 2 + u2(dex, pos + 2) * 4;
                }
                if (ident == 0x0300 && pos + 8 <= end) {
                    int width = u2(dex, pos + 2);
                    long size = ((long)u2(dex, pos + 4)) | (((long)u2(dex, pos + 6)) << 16);
                    long units = 4L + ((width * size + 1L) / 2L);
                    return units > Integer.MAX_VALUE ? 1 : (int)units;
                }
                return 1;
            }
            if (op == 0x01 || op == 0x04 || op == 0x07
                    || (op >= 0x0a && op <= 0x12)
                    || op == 0x1d || op == 0x1e || op == 0x21
                    || op == 0x27 || op == 0x28
                    || (op >= 0x3e && op <= 0x43)
                    || op == 0x73 || op == 0x79 || op == 0x7a
                    || (op >= 0x7b && op <= 0x8f)
                    || (op >= 0xb0 && op <= 0xcf)) return 1;
            if (op == 0x02 || op == 0x05 || op == 0x08
                    || op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19
                    || op == 0x1a || op == 0x1c || op == 0x1f || op == 0x20
                    || op == 0x22 || op == 0x23 || op == 0x29
                    || (op >= 0x2d && op <= 0x3d)
                    || (op >= 0x44 && op <= 0x6d)
                    || (op >= 0x90 && op <= 0xaf)
                    || (op >= 0xd0 && op <= 0xe2)
                    || op == 0xfe || op == 0xff) return 2;
            if (op == 0x03 || op == 0x06 || op == 0x09
                    || op == 0x14 || op == 0x17 || op == 0x1b
                    || op == 0x24 || op == 0x25 || op == 0x26
                    || op == 0x2a || op == 0x2b || op == 0x2c
                    || (op >= 0x6e && op <= 0x72)
                    || (op >= 0x74 && op <= 0x78)
                    || op == 0xfc || op == 0xfd) return 3;
            if (op == 0xfa || op == 0xfb) return 4;
            if (op == 0x18) return 5;
            return 1;
        }

        static NumericTableProbe scanIndexedNumericTable(byte[] dex, int codeOff,
                                                          String[] strings) {
            try {
                if (codeOff <= 0 || codeOff + 16 > dex.length) return null;
                int units = u4(dex, codeOff + 12);
                int start = codeOff + 16;
                long endLong = start + units * 2L;
                if (units <= 0 || endLong > dex.length) return null;
                int end = (int)endLong;

                HashMap<Integer,Integer> intRegs = new HashMap<Integer,Integer>();
                HashMap<Integer,String> pendingFuncs = new HashMap<Integer,String>();
                HashMap<Integer,String> funcs = new HashMap<Integer,String>();
                HashMap<Integer,Integer> nums = new HashMap<Integer,Integer>();
                int lastLarge = 0;
                int largeAge = 1000000;

                int pos = start;
                while (pos + 2 <= end) {
                    int word = u2(dex, pos);
                    int op = word & 0xff;
                    largeAge++;
                    int step = dexInsnUnits(dex, pos, end);
                    if (step <= 0) step = 1;

                    if (op == 0x12) {
                        int reg = (word >> 8) & 0x0f;
                        int value = (word >> 12) & 0x0f;
                        if ((value & 0x08) != 0) value -= 0x10;
                        intRegs.put(reg, value);
                        pendingFuncs.remove(reg);
                    } else if (op == 0x13 && pos + 4 <= end) {
                        int reg = (word >> 8) & 0xff;
                        int value = (short)u2(dex, pos + 2);
                        intRegs.put(reg, value);
                        pendingFuncs.remove(reg);
                        if (Math.abs((long)value) >= 10000L) {
                            lastLarge = Math.abs(value); largeAge = 0;
                        }
                    } else if (op == 0x14 && pos + 6 <= end) {
                        int reg = (word >> 8) & 0xff;
                        int value = u4(dex, pos + 2);
                        intRegs.put(reg, value);
                        pendingFuncs.remove(reg);
                        long av = Math.abs((long)value);
                        if (av >= 10000L && av <= 999999999L) {
                            lastLarge = (int)av; largeAge = 0;
                        }
                    } else if (op == 0x15 && pos + 4 <= end) {
                        int reg = (word >> 8) & 0xff;
                        int value = ((short)u2(dex, pos + 2)) << 16;
                        intRegs.put(reg, value);
                        pendingFuncs.remove(reg);
                        long av = Math.abs((long)value);
                        if (av >= 10000L && av <= 999999999L) {
                            lastLarge = (int)av; largeAge = 0;
                        }
                    } else if (op == 0x01) {
                        int dst = (word >> 8) & 0x0f;
                        int src = (word >> 12) & 0x0f;
                        if (intRegs.containsKey(src)) intRegs.put(dst, intRegs.get(src));
                        else intRegs.remove(dst);
                        pendingFuncs.remove(dst);
                    } else if (op == 0x02 && pos + 4 <= end) {
                        int dst = (word >> 8) & 0xff;
                        int src = u2(dex, pos + 2);
                        if (intRegs.containsKey(src)) intRegs.put(dst, intRegs.get(src));
                        else intRegs.remove(dst);
                        pendingFuncs.remove(dst);
                    } else if (op == 0xd8 && pos + 4 <= end) {
                        int dst = (word >> 8) & 0xff;
                        int second = u2(dex, pos + 2);
                        int src = second & 0xff;
                        int lit = (byte)((second >> 8) & 0xff);
                        if (intRegs.containsKey(src)) intRegs.put(dst, intRegs.get(src) + lit);
                        else intRegs.remove(dst);
                        pendingFuncs.remove(dst);
                    } else if (op == 0x1a && pos + 4 <= end) {
                        int reg = (word >> 8) & 0xff;
                        int idx = u2(dex, pos + 2);
                        pendingFuncs.remove(reg);
                        String value = safeString(strings, idx);
                        if (looksLikeIappCommand(value)) {
                            pendingFuncs.put(reg, value.substring(0, value.length() - 1));
                        }
                    } else if (op == 0x1b && pos + 6 <= end) {
                        int reg = (word >> 8) & 0xff;
                        int idx = u4(dex, pos + 2);
                        pendingFuncs.remove(reg);
                        String value = safeString(strings, idx);
                        if (looksLikeIappCommand(value)) {
                            pendingFuncs.put(reg, value.substring(0, value.length() - 1));
                        }
                    } else if (op == 0x4d && pos + 4 <= end) {
                        int valueReg = (word >> 8) & 0xff;
                        int second = u2(dex, pos + 2);
                        int indexReg = (second >> 8) & 0xff;
                        Integer index = intRegs.get(indexReg);
                        if (index != null && index >= 0 && index < 4096) {
                            String function = pendingFuncs.remove(valueReg);
                            if (function != null) {
                                if (!funcs.containsKey(index)) funcs.put(index, function);
                            } else if (lastLarge > 0 && largeAge <= 16) {
                                if (!nums.containsKey(index)) nums.put(index, lastLarge);
                                lastLarge = 0;
                                largeAge = 1000000;
                            }
                        }
                    }
                    pos += step * 2;
                }

                ArrayList<Integer> indexes = new ArrayList<Integer>();
                for (Integer index : funcs.keySet()) if (nums.containsKey(index)) indexes.add(index);
                Collections.sort(indexes);
                if (indexes.size() < 20) return null;
                if (!"f".equals(funcs.get(indexes.get(0)))
                        || !"for".equals(funcs.get(indexes.get(1)))
                        || !"w".equals(funcs.get(indexes.get(2)))
                        || !"t".equals(funcs.get(indexes.get(3)))) return null;

                int n = indexes.size();
                int baselineHits = 0, sequentialHits = 0;
                int min = Integer.MAX_VALUE, max = Integer.MIN_VALUE;
                HashSet<Integer> unique = new HashSet<Integer>();
                int previous = 0;
                for (int i = 0; i < n; i++) {
                    int value = nums.get(indexes.get(i));
                    unique.add(value);
                    if (value < min) min = value;
                    if (value > max) max = value;
                    if (value == 145001 + i) baselineHits++;
                    if (i > 0 && value == previous + 1) sequentialHits++;
                    previous = value;
                }
                float baselineRatio = baselineHits / (float)n;
                float sequentialRatio = sequentialHits / (float)Math.max(1, n - 1);
                float uniqueRatio = unique.size() / (float)n;
                int span = max - min;
                boolean baseline = baselineRatio >= 0.80f
                        || (min >= 145000 && min <= 145010 && sequentialRatio >= 0.80f);
                boolean randomized = !baseline
                        && uniqueRatio >= 0.85f
                        && sequentialRatio <= 0.35f
                        && span <= Math.max(10000, n * 250);

                NumericTableProbe out = new NumericTableProbe();
                out.baseline = baseline;
                out.randomized = randomized;
                out.pairs = n;
                out.min = min;
                out.max = max;
                out.span = span;
                return out;
            } catch(Exception ignored) {
                return null;
            }
        }

        static boolean betterNumericTable(NumericTableProbe a, NumericTableProbe b) {
            if (a == null) return false;
            if (b == null) return true;
            if (a.randomized != b.randomized) return a.randomized;
            if (a.baseline != b.baseline) return !a.baseline;
            return a.pairs > b.pairs;
        }

        static DynamicRestoreProbe analyzeDynamicRestoreDex(byte[] dex, String dexEntry) {
            DynamicRestoreProbe empty = new DynamicRestoreProbe();
            empty.dexEntry = dexEntry == null ? "" : dexEntry;
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return empty;
                int stringIdsSize = u4(dex, 0x38), stringIdsOff = u4(dex, 0x3c);
                int typeIdsSize = u4(dex, 0x40), typeIdsOff = u4(dex, 0x44);
                int classDefsSize = u4(dex, 0x60), classDefsOff = u4(dex, 0x64);
                if (stringIdsSize < 0 || stringIdsSize > 2000000
                        || typeIdsSize < 0 || typeIdsSize > 1000000
                        || classDefsSize < 0 || classDefsSize > 1000000) return empty;
                if (stringIdsOff < 0 || stringIdsOff + stringIdsSize * 4L > dex.length
                        || typeIdsOff < 0 || typeIdsOff + typeIdsSize * 4L > dex.length
                        || classDefsOff < 0 || classDefsOff + classDefsSize * 32L > dex.length) return empty;

                String[] strings = readIndexedDexStrings(dex, stringIdsSize, stringIdsOff);
                boolean iapecRunClassPresent = false;
                HashSet<String> iapecNumericIds = new HashSet<String>();
                for (int si = 0; si < strings.length; si++) {
                    String value = strings[si];
                    if ("LiApEcPro/DynamicEncryption/run;".equals(value)) iapecRunClassPresent = true;
                    if (value != null && value.matches("iApEcPro-\\d{10}\\(")) {
                        iapecNumericIds.add(value.substring(9, 19));
                    }
                }
                int largestUnits = 0;
                DynamicRestoreProbe commandBest = new DynamicRestoreProbe();
                commandBest.dexEntry = empty.dexEntry;
                DynamicRestoreProbe tableClass = null;
                NumericTableProbe selectedTable = null;

                for (int c = 0; c < classDefsSize; c++) {
                    int defOff = classDefsOff + c * 32;
                    int classIdx = u4(dex, defOff);
                    int classDataOff = u4(dex, defOff + 24);
                    if (classIdx < 0 || classIdx >= typeIdsSize || classDataOff <= 0 || classDataOff >= dex.length) continue;
                    int typeStringIdx = u4(dex, typeIdsOff + classIdx * 4);
                    String descriptor = safeString(strings, typeStringIdx);

                    int[] pp = new int[]{classDataOff};
                    int staticFields = readUleb(dex, pp);
                    int instanceFields = readUleb(dex, pp);
                    int directMethods = readUleb(dex, pp);
                    int virtualMethods = readUleb(dex, pp);
                    if (staticFields < 0 || instanceFields < 0 || directMethods < 0 || virtualMethods < 0
                            || staticFields + instanceFields > 1000000
                            || directMethods + virtualMethods > 1000000) continue;
                    for (int i = 0; i < staticFields + instanceFields && pp[0] < dex.length; i++) {
                        readUleb(dex, pp);
                        readUleb(dex, pp);
                    }

                    int totalUnits = 0;
                    int maxMethodUnits = 0;
                    int methodIdx = 0;
                    HashSet<String> commandRefs = new HashSet<String>();
                    NumericTableProbe classTable = null;
                    int methodTotal = directMethods + virtualMethods;
                    for (int i = 0; i < methodTotal && pp[0] < dex.length; i++) {
                        methodIdx += readUleb(dex, pp);
                        readUleb(dex, pp);
                        int codeOff = readUleb(dex, pp);
                        if (codeOff <= 0 || codeOff + 16 > dex.length) continue;
                        int units = u4(dex, codeOff + 12);
                        if (units < 0 || codeOff + 16L + units * 2L > dex.length) continue;
                        totalUnits += units;
                        if (units > maxMethodUnits) maxMethodUnits = units;
                        collectIappCommandRefs(dex, codeOff, units, strings, commandRefs);
                        NumericTableProbe table = scanIndexedNumericTable(dex, codeOff, strings);
                        if (betterNumericTable(table, classTable)) classTable = table;
                    }

                    if (totalUnits > largestUnits) largestUnits = totalUnits;
                    int commandCount = commandRefs.size();
                    if (commandCount > commandBest.commandCount
                            || (commandCount == commandBest.commandCount && totalUnits > commandBest.codeUnits)) {
                        commandBest.dexEntry = empty.dexEntry;
                        commandBest.classDescriptor = descriptor;
                        commandBest.className = dexDescriptorSimpleName(descriptor);
                        commandBest.codeUnits = totalUnits;
                        commandBest.methodCount = methodTotal;
                        commandBest.commandCount = commandCount;
                        commandBest.maxMethodCodeUnits = maxMethodUnits;
                    }

                    if (betterNumericTable(classTable, selectedTable)) {
                        selectedTable = classTable;
                        tableClass = new DynamicRestoreProbe();
                        tableClass.dexEntry = empty.dexEntry;
                        tableClass.classDescriptor = descriptor;
                        tableClass.className = dexDescriptorSimpleName(descriptor);
                        tableClass.codeUnits = totalUnits;
                        tableClass.methodCount = methodTotal;
                        tableClass.commandCount = commandCount;
                        tableClass.maxMethodCodeUnits = maxMethodUnits;
                    }
                }

                DynamicRestoreProbe best = tableClass != null ? tableClass : commandBest;
                best.largestClassCodeUnits = largestUnits;
                if (selectedTable != null) {
                    best.baselineNumericTable = selectedTable.baseline;
                    best.randomizedNumericTable = selectedTable.randomized;
                    best.numericTablePairs = selectedTable.pairs;
                    best.numericTableMin = selectedTable.min;
                    best.numericTableMax = selectedTable.max;
                }

                // The large v/t/w command class exists in ordinary iApp APKs.
                // Dynamic restore is required only when that class contains the
                // second shuffled/random numeric dispatch table.  The normal
                // 145001 -> f, 145002 -> for table is explicitly ignored.
                best.iapecRunClassPresent = iapecRunClassPresent;
                best.iapecNumericTokenCount = iapecNumericIds.size();
                boolean iapecDynamic = iapecRunClassPresent && iapecNumericIds.size() >= 8;
                best.dynamicEncrypted = (selectedTable != null && selectedTable.randomized) || iapecDynamic;
                if (iapecDynamic) {
                    best.reason = "LiApEcPro/DynamicEncryption/run; with iApEcPro-########## dispatch table";
                    best.classDescriptor = "LiApEcPro/DynamicEncryption/run;";
                    best.className = "run";
                } else if (best.dynamicEncrypted) {
                    best.reason = "randomized numeric command table detected";
                } else if (selectedTable != null && selectedTable.baseline) {
                    best.reason = "only baseline 145001 command table; dynamic restore not required";
                } else if (best.commandCount > 0) {
                    best.reason = "iApp command class found but no randomized numeric table";
                }
                return best;
            } catch(Exception ignored) {
                return empty;
            }
        }

        static String[] readIndexedDexStrings(byte[] dex, int count, int off) {
            String[] out = new String[count];
            for (int i = 0; i < count; i++) {
                try {
                    int p0 = u4(dex, off + i * 4);
                    if (p0 <= 0 || p0 >= dex.length) { out[i] = ""; continue; }
                    int[] pp = new int[]{p0};
                    readUleb(dex, pp);
                    int p = pp[0], q = p;
                    while (q < dex.length && dex[q] != 0 && q - p <= 4096) q++;
                    out[i] = q > p ? new String(dex, p, q - p, "UTF-8") : "";
                } catch(Exception ignored) {
                    out[i] = "";
                }
            }
            return out;
        }

        static void collectIappCommandRefs(byte[] dex, int codeOff, int units,
                                           String[] strings, HashSet<String> refs) {
            int start = codeOff + 16;
            for (int i = 0; i < units; i++) {
                int pos = start + i * 2;
                if (pos + 2 > dex.length) break;
                int op = dex[pos] & 0xff;
                int stringIdx = -1;
                if (op == 0x1a && i + 1 < units && pos + 4 <= dex.length) {
                    stringIdx = u2(dex, pos + 2);
                } else if (op == 0x1b && i + 2 < units && pos + 6 <= dex.length) {
                    stringIdx = u4(dex, pos + 2);
                }
                if (stringIdx >= 0 && stringIdx < strings.length) {
                    String s = strings[stringIdx];
                    if (looksLikeIappCommand(s)) refs.add(s);
                }
            }
        }

        static boolean looksLikeIappCommand(String s) {
            if (s == null || s.length() < 2 || s.length() > 96 || !s.endsWith("(")) return false;
            char first = s.charAt(0);
            if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z'))) return false;
            for (int i = 1; i < s.length() - 1; i++) {
                char c = s.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '+' || c == '-'
                        || c == '*' || c == '/' || c == '%' || c == '_';
                if (!ok) return false;
            }
            return true;
        }

        static String dexDescriptorSimpleName(String descriptor) {
            if (descriptor == null) return "";
            String s = descriptor;
            if (s.startsWith("L")) s = s.substring(1);
            if (s.endsWith(";")) s = s.substring(0, s.length() - 1);
            int slash = s.lastIndexOf('/');
            return slash >= 0 ? s.substring(slash + 1) : s;
        }

        static final int DYNAMIC_SO_FEATURE_VERSION = 1;

        // IAPT_CLIENT_ANCIENT_LABEL_SCAN_CACHE_V2: 同一 APK 的检测结果复用。
        // 键包含绝对路径、文件大小和最后修改时间，APK 改动后会自动失效。
        static final HashMap<String,Object> APK_SCAN_CACHE = new HashMap<String,Object>();
        static final HashMap<String,Object> APK_SCAN_LOCKS = new HashMap<String,Object>();

        static String apkScanCacheKey(File apk, String kind) {
            String path = "<null>";
            long size = -1L;
            long modified = -1L;
            if (apk != null) {
                try { path = apk.getCanonicalPath(); }
                catch(Exception ignored) { path = apk.getAbsolutePath(); }
                try { size = apk.length(); } catch(Exception ignored) {}
                try { modified = apk.lastModified(); } catch(Exception ignored) {}
            }
            return kind + ":" + path + ":" + size + ":" + modified;
        }

        static Object apkScanCacheGet(String key) {
            synchronized (APK_SCAN_CACHE) { return APK_SCAN_CACHE.get(key); }
        }

        static void apkScanCachePut(String key, Object value) {
            if (value == null) return;
            synchronized (APK_SCAN_CACHE) {
                if (APK_SCAN_CACHE.size() >= 96) APK_SCAN_CACHE.clear();
                APK_SCAN_CACHE.put(key, value);
            }
        }

        static Object apkScanLock(String key) {
            synchronized (APK_SCAN_LOCKS) {
                Object lock = APK_SCAN_LOCKS.get(key);
                if (lock == null) {
                    lock = new Object();
                    APK_SCAN_LOCKS.put(key, lock);
                    if (APK_SCAN_LOCKS.size() > 128) {
                        // 保留当前锁；其它旧锁只影响重复扫描，不影响正确性。
                        HashMap<String,Object> keep = new HashMap<String,Object>();
                        keep.put(key, lock);
                        APK_SCAN_LOCKS.clear();
                        APK_SCAN_LOCKS.putAll(keep);
                    }
                }
                return lock;
            }
        }

        static class IapecProtectionProbe {
            boolean efficientEncrypted = false;
            boolean dynamicEncrypted = false;
            boolean selfDestruct = false;
            boolean runClassPresent = false;
            int numericTokenCount = 0;
            String dexEntry = "";
            String reason = "";
        }

        static IapecProtectionProbe detectIapecProtection(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "iapec_protection_v14");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof IapecProtectionProbe) return (IapecProtectionProbe)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof IapecProtectionProbe) return (IapecProtectionProbe)cached;
                IapecProtectionProbe value = detectIapecProtectionUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static void inspectIapecProtectionDex(byte[] dex, String entry, IapecProtectionProbe out) {
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return;
                int count = u4(dex, 0x38), off = u4(dex, 0x3c);
                if (count < 0 || count > 2000000 || off < 0 || off + count * 4L > dex.length) return;
                String[] strings = readIndexedDexStrings(dex, count, off);
                HashSet<String> ids = new HashSet<String>();
                boolean run = false;
                for (int i = 0; i < strings.length; i++) {
                    String value = strings[i];
                    if ("LiApEcPro/DynamicEncryption/run;".equals(value)) run = true;
                    if ("LiApEcPro/EfficientEncryption/decrypt;".equals(value)) out.efficientEncrypted = true;
                    if ("LDestruction0/Self;".equals(value)) out.selfDestruct = true;
                    if (value != null && value.matches("iApEcPro-\\d{10}\\(")) ids.add(value.substring(9, 19));
                }
                if (run && ids.size() >= 8) {
                    out.runClassPresent = true;
                    out.dynamicEncrypted = true;
                    out.numericTokenCount = Math.max(out.numericTokenCount, ids.size());
                    out.dexEntry = entry == null ? "" : entry;
                    out.reason = "LiApEcPro/DynamicEncryption/run; + " + ids.size() + " numeric dispatch strings";
                } else if (run) {
                    out.runClassPresent = true;
                    out.numericTokenCount = Math.max(out.numericTokenCount, ids.size());
                }
            } catch(Exception ignored) {}
        }

        static IapecProtectionProbe detectIapecProtectionUncached(File apk) throws Exception {
            IapecProtectionProbe out = new IapecProtectionProbe();
            if (apk == null || !apk.isFile()) return out;
            String lowName = apk.getName().toLowerCase(Locale.US);
            if (lowName.endsWith(".dex")) {
                inspectIapecProtectionDex(readFileBytes(apk, 128 * 1024 * 1024), apk.getName(), out);
                return out;
            }
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> dexNames = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String name = e.getName().replace('\\', '/');
                    String low = name.toLowerCase(Locale.US);
                    if (low.endsWith("libefficient.so") || low.endsWith("libefficientprotect.so")
                            || low.indexOf("protect_代码高效加密") >= 0) out.efficientEncrypted = true;
                    if (low.endsWith("libdestruction.so") || low.indexOf("protect_655") >= 0
                            || low.indexOf("destruction0") >= 0) out.selfDestruct = true;
                    String simple = name.substring(name.lastIndexOf('/') + 1);
                    if (isDexFileName(simple)) dexNames.add(e.getName());
                }
                Collections.sort(dexNames, new Comparator<String>() {
                    public int compare(String left, String right) { return dexOrder(left) - dexOrder(right); }
                });
                for (int i = 0; i < dexNames.size(); i++) {
                    ZipEntry e = z.getEntry(dexNames.get(i));
                    if (e == null || e.getSize() > 128L * 1024L * 1024L) continue;
                    inspectIapecProtectionDex(readZipEntryBytes(z, e, 128 * 1024 * 1024), e.getName(), out);
                }
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
            return out;
        }

        static class AntiQiushuiProbe {
            final boolean canonicalLibPresent;
            final boolean qiushuiLike;
            final String containerEntry;
            final int sidecarCount;
            AntiQiushuiProbe(boolean canonicalLibPresent, boolean qiushuiLike,
                             String containerEntry, int sidecarCount) {
                this.canonicalLibPresent = canonicalLibPresent;
                this.qiushuiLike = qiushuiLike;
                this.containerEntry = containerEntry == null ? "" : containerEntry;
                this.sidecarCount = sidecarCount;
            }
        }

        static AntiQiushuiProbe detectAntiQiushuiProbe(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "anti_qiushui");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof AntiQiushuiProbe) return (AntiQiushuiProbe)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof AntiQiushuiProbe) return (AntiQiushuiProbe)cached;
                AntiQiushuiProbe value = detectAntiQiushuiProbeUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static AntiQiushuiProbe detectAntiQiushuiProbeUncached(File apk) throws Exception {
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> names = new ArrayList<String>();
                boolean canonical = false;
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry entry = en.nextElement();
                    if (entry == null || entry.isDirectory()) continue;
                    String name = entry.getName();
                    if (name == null) continue;
                    names.add(name);
                    if ("assets/lib.so".equalsIgnoreCase(name.replace('\\', '/'))
                            && entry.getSize() >= 64L) {
                        canonical = true;
                    }
                }
                if (canonical) {
                    // V109：标准 assets/lib.so 是普通 V3/V6 容器，不等于“反加密样本”。
                    // 反加密样本只在 lib.so 被隐藏/长路径混淆并带 sidecar，或存在
                    // 明显隐藏资源壳特征时自动开启。否则所有正常样本都会被误勾选，
                    // 下载阶段也会错误输出 assets/res/**。
                    return new AntiQiushuiProbe(true, false, "assets/lib.so", 0);
                }

                String container = selectObfuscatedIappContainer(z, names);
                if (container == null) return new AntiQiushuiProbe(false, false, "", 0);
                int sidecars = 0;
                for (int i = 0; i < names.size(); i++) {
                    String name = names.get(i);
                    if (container.equals(name)) continue;
                    int extra = name.length() - container.length();
                    if (extra < 1 || extra > 32 || !name.startsWith(container)) continue;
                    ZipEntry entry = z.getEntry(name);
                    if (entry != null && !entry.isDirectory()
                            && entry.getSize() >= 0 && entry.getSize() <= 8192) {
                        sidecars++;
                    }
                }
                ZipEntry selectedEntry = z.getEntry(container);
                boolean xor40Like = selectedEntry != null && selectedEntry.getSize() >= 64L * 1024L
                        && container.length() >= 1000 && container.indexOf('/') >= 0;
                return new AntiQiushuiProbe(false, sidecars > 0 || xor40Like, container, sidecars);
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
        }

        static class LegacyIappProbe {
            final boolean oldIapp;
            final String sokey;
            final long decodedSize;
            LegacyIappProbe(boolean oldIapp, String sokey, long decodedSize) {
                this.oldIapp = oldIapp;
                this.sokey = sokey == null ? "" : sokey;
                this.decodedSize = decodedSize;
            }
        }

        static boolean isOldIappBase64Container(byte[] raw) {
            if (raw == null || raw.length < 64) return false;
            ByteArrayOutputStream compact = new ByteArrayOutputStream(raw.length);
            for (int i=0;i<raw.length;i++) {
                int c = raw[i] & 0xff;
                if (c==' ' || c=='\r' || c=='\n' || c=='\t') continue;
                boolean ok = (c>='A'&&c<='Z') || (c>='a'&&c<='z') || (c>='0'&&c<='9') || c=='+' || c=='/' || c=='=';
                if (!ok) return false;
                compact.write(c);
            }
            byte[] text = compact.toByteArray();
            if (text.length==0 || (text.length%4)!=0) return false;
            try {
                byte[] decoded = android.util.Base64.decode(text, android.util.Base64.DEFAULT);
                return decoded != null && decoded.length >= 16 && (decoded.length%16)==0;
            } catch(Exception e) { return false; }
        }

        static String legacyAbiFromEntry(String name) {
            String low = name == null ? "" : name.replace('\\','/').toLowerCase(Locale.US);
            String[] abis = new String[]{"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64"};
            for (int i=0;i<abis.length;i++) {
                if (low.indexOf("/" + abis[i] + "/") >= 0 || low.startsWith("lib/" + abis[i] + "/")) return abis[i];
            }
            return "unknown";
        }

        static int legacyAbiWeight(String abi) {
            if ("arm64-v8a".equals(abi) || "armeabi-v7a".equals(abi)) return 8;
            if ("armeabi".equals(abi)) return 6;
            if ("x86".equals(abi)) return 4;
            if ("x86_64".equals(abi)) return 1;
            return 1;
        }

        static String extractLegacySokeyFromApkConsensus(File apk) {
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                HashMap<String,Integer> mobileCounts = new HashMap<String,Integer>();
                HashMap<String,Integer> allCounts = new HashMap<String,Integer>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String name = e.getName().replace('\\','/');
                    String low = name.toLowerCase(Locale.US);
                    if (!low.endsWith("/libygsiyu.so") && !"libygsiyu.so".equals(low)) continue;
                    if (e.getSize() > 128L * 1024L * 1024L) continue;
                    String key = findLegacySokeyInBytes(readZipEntryBytes(z, e, 128 * 1024 * 1024));
                    if (key == null || !key.matches("[A-Za-z0-9]{4}")) continue;
                    String abi = legacyAbiFromEntry(name);
                    int weight = legacyAbiWeight(abi);
                    allCounts.put(key, allCounts.containsKey(key) ? allCounts.get(key) + weight : weight);
                    if ("arm64-v8a".equals(abi) || "armeabi-v7a".equals(abi) || "armeabi".equals(abi)) {
                        mobileCounts.put(key, mobileCounts.containsKey(key) ? mobileCounts.get(key) + weight : weight);
                    }
                }
                HashMap<String,Integer> source = mobileCounts.size() > 0 ? mobileCounts : allCounts;
                String best = ""; int bestScore = -1;
                for (Map.Entry<String,Integer> row : source.entrySet()) {
                    int score = row.getValue() == null ? 0 : row.getValue().intValue();
                    if (score > bestScore || (score == bestScore && row.getKey().compareTo(best) < 0)) {
                        best = row.getKey(); bestScore = score;
                    }
                }
                return best;
            } catch(Exception ignored) {
                return "";
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
        }

        static LegacyIappProbe detectLegacyIapp(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "legacy_iapp");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof LegacyIappProbe) return (LegacyIappProbe)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof LegacyIappProbe) return (LegacyIappProbe)cached;
                LegacyIappProbe value = detectLegacyIappUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static LegacyIappProbe detectLegacyIappUncached(File apk) throws Exception {
            // 远古方案只以 assets/lib.so 的旧版 Base64/AES 容器为准。
            // libygsiyu.so 中的 4 位字符串只能作为远古参数，不能作为远古判定依据，
            // 否则新版 V3 样本会被误标为“远古”。
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ZipEntry lib = null;
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e != null && !e.isDirectory()
                            && "assets/lib.so".equalsIgnoreCase(e.getName().replace('\\','/'))) {
                        lib = e;
                        break;
                    }
                }
                if (lib == null || lib.getSize() <= 0 || lib.getSize() > 256L*1024L*1024L) {
                    return new LegacyIappProbe(false, "", 0);
                }
                byte[] raw = readZipEntryBytes(z, lib, 256*1024*1024);
                if (!isOldIappBase64Container(raw)) return new LegacyIappProbe(false, "", 0);
                long decoded = 0;
                try {
                    ByteArrayOutputStream compact = new ByteArrayOutputStream(raw.length);
                    for (int i=0;i<raw.length;i++) {
                        int c=raw[i]&0xff;
                        if(c!=' '&&c!='\r'&&c!='\n'&&c!='\t') compact.write(c);
                    }
                    decoded = android.util.Base64.decode(compact.toByteArray(), android.util.Base64.DEFAULT).length;
                } catch(Exception ignored) {}
                String sk = extractLegacySokeyFromApkConsensus(apk);
                return new LegacyIappProbe(true, sk == null ? "" : sk.trim(), decoded);
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
        }

        static String findLegacySokeyInBytes(byte[] data) {
            if (data == null || data.length < 16) return "";
            ArrayList<String> values = new ArrayList<String>();
            ArrayList<Integer> offsets = new ArrayList<Integer>();
            int start = 0;
            for (int i=0;i<data.length;i++) {
                if (data[i] != 0) continue;
                int len = i-start;
                if (len>=2 && len<=160) {
                    boolean ascii=true;
                    for (int j=start;j<i;j++) { int c=data[j]&0xff; if(c<0x20||c>0x7e){ascii=false;break;} }
                    if (ascii) {
                        try { values.add(new String(data,start,len,"US-ASCII")); offsets.add(start); } catch(Exception ignored) {}
                    }
                }
                start=i+1;
            }
            for (int i=0;i<values.size();i++) {
                if (!"lib.so".equalsIgnoreCase(values.get(i))) continue;
                for (int back=1;back<=8 && i-back>=0;back++) {
                    String cand=values.get(i-back);
                    if (offsets.get(i)-offsets.get(i-back)>256) break;
                    if (!cand.matches("[A-Za-z0-9]{4}")) continue;
                    if ("iapp".equalsIgnoreCase(cand) || "main".equalsIgnoreCase(cand) || "true".equalsIgnoreCase(cand)) continue;
                    if (i-back+1<i && "aa".equals(values.get(i-back+1))) return cand;
                }
            }
            return "";
        }

        static Integer extractVmpDexKeyFromNative(ZipFile z) {
            try {
                HashMap<Integer,Integer> counts = new HashMap<Integer,Integer>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e=en.nextElement(); if(e==null||e.isDirectory()) continue;
                    String simple=e.getName(); int slash=simple.lastIndexOf('/'); if(slash>=0)simple=simple.substring(slash+1);
                    if (!"libLianYi.so".equalsIgnoreCase(simple) || e.getSize()>32L*1024L*1024L) continue;
                    byte[] d=readZipEntryBytes(z,e,32*1024*1024);
                    String all=new String(d,"ISO-8859-1");
                    if (all.indexOf("Lcom/iapp/app/f;")<0 && all.indexOf("classesInit0")<0) continue;
                    for(int i=0;i+8<=d.length;i++) {
                        if ((d[i]&0xff)==0xea && d[i+1]==0 && (d[i+6]&0xff)==0x36 && d[i+7]==0) {
                            int v=(d[i+2]&0xff)|((d[i+3]&0xff)<<8)|((d[i+4]&0xff)<<16)|((d[i+5]&0xff)<<24);
                            if(v>=100000&&v<=20000000) counts.put(v,counts.containsKey(v)?counts.get(v)+1:1);
                        }
                    }
                }
                int best=0,bestCount=0;
                for(Map.Entry<Integer,Integer> row:counts.entrySet()) if(row.getValue()>bestCount){best=row.getKey();bestCount=row.getValue();}
                return bestCount>0?Integer.valueOf(best):null;
            } catch(Exception ignored) { return null; }
        }

        static class TaskSecurityOptions {
            final boolean userPasswordRequired;
            final boolean signatureVerifyRequired;
            TaskSecurityOptions(boolean userPasswordRequired, boolean signatureVerifyRequired) {
                this.userPasswordRequired = userPasswordRequired;
                this.signatureVerifyRequired = signatureVerifyRequired;
            }
        }

        static TaskSecurityOptions detectTaskSecurityOptions(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "security");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof TaskSecurityOptions) return (TaskSecurityOptions)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof TaskSecurityOptions) return (TaskSecurityOptions)cached;
                TaskSecurityOptions value = detectTaskSecurityOptionsUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static TaskSecurityOptions detectTaskSecurityOptionsUncached(File apk) throws Exception {
            boolean userPasswordRequired = false;
            boolean signatureVerifyRequired = false;
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ZipEntry userEntry = z.getEntry("assets/userencryption.xml");
                if (userEntry != null && !userEntry.isDirectory()) {
                    String userXml = readSmallZipText(z, userEntry, 1024 * 1024);
                    String normalized = userXml == null ? "" : userXml.toLowerCase(Locale.US).replaceAll("\\s+", "");
                    userPasswordRequired = normalized.indexOf("<ok>true</ok>") >= 0;
                }
                ZipEntry signatureEntry = z.getEntry("assets/extra_conf1g.xml");
                if (signatureEntry == null || signatureEntry.isDirectory()) {
                    // 找不到 extra_conf1g.xml 时默认没有签名校验，不自动开启参数。
                    signatureVerifyRequired = false;
                } else {
                    String signatureConfig = readSmallZipText(z, signatureEntry, 1024 * 1024);
                    if (signatureConfig == null) signatureConfig = "";
                    // iApp 实际规则：空文件=参与签名；任意非空字符串=不参与签名。
                    // 去掉 BOM、NUL 和首尾空白后再判断，避免空配置被误认为字符串。
                    String normalized = signatureConfig
                            .replace("\uFEFF", "")
                            .replace("\u0000", "")
                            .trim();
                    signatureVerifyRequired = normalized.length() == 0;
                }
            } finally {
                try { if (z != null) z.close(); } catch(Exception ignored) {}
            }
            return new TaskSecurityOptions(userPasswordRequired, signatureVerifyRequired);
        }

        static String readSmallZipText(ZipFile z, ZipEntry entry, int maxBytes) throws Exception {
            if (z == null || entry == null) return "";
            InputStream in = new BufferedInputStream(z.getInputStream(entry), 8192);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            try {
                for (;;) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    total += n;
                    if (total > maxBytes) throw new IOException("XML entry too large: " + entry.getName());
                    out.write(buf, 0, n);
                }
            } finally {
                try { in.close(); } catch(Exception ignored) {}
            }
            return new String(out.toByteArray(), "UTF-8");
        }

        static String detectMainFileFromApk(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "main_file");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof String) return (String)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof String) return (String)cached;
                String value = detectMainFileFromApkUncached(apk);
                if (value == null) value = "";
                apkScanCachePut(key, value);
                return value;
            }
        }

        static String detectMainFileFromApkUncached(File apk) throws Exception {
            if (apk == null || !apk.isFile()) return "";
            ZipFile z = new ZipFile(apk);
            try {
                ArrayList<String> dexNames = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String simple = e.getName();
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    if (isDexFileName(simple)) dexNames.add(e.getName());
                }
                Collections.sort(dexNames, new Comparator<String>() { public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }});

                // Fast path: iApp V3/V4 normally keeps the launch page in
                // com.iapp.app.run.mian.d().  Parse only that class/method and
                // return the exact string constant used there.  This avoids the
                // previous full-string-pool scoring pass, which took seconds on
                // large/multidex APKs.
                for (int di = 0; di < dexNames.size(); di++) {
                    ZipEntry e = z.getEntry(dexNames.get(di));
                    if (e == null || e.getSize() > 128L * 1024L * 1024L) continue;
                    byte[] dex = readZipEntryBytes(z, e, 128 * 1024 * 1024);
                    String fast = extractMainFileFromRunMianD(dex);
                    if (fast.length() > 0) return fast;
                }

                // Ultra-light fallback: scan raw DEX bytes for nul-terminated
                // page file names.  Do not decode the whole string pool and do
                // not perform full const-string context scoring here; that was
                // the remaining 2-3s delay on large multidex APKs.  If this
                // fallback is uncertain it returns empty and the user can still
                // fill the custom main file manually.
                for (int di = 0; di < dexNames.size(); di++) {
                    ZipEntry e = z.getEntry(dexNames.get(di));
                    if (e == null || e.getSize() > 32L * 1024L * 1024L) continue;
                    byte[] dex = readZipEntryBytes(z, e, 32 * 1024 * 1024);
                    String v = extractMainFileRawLight(dex);
                    if (v.length() > 0) return v;
                }
                return "";
            } finally { try { z.close(); } catch(Exception ignored) {} }
        }

        static String extractMainFileFromRunMianD(byte[] dex) {
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return "";
                int stringIdsSize = u4(dex, 0x38), stringIdsOff = u4(dex, 0x3c);
                int typeIdsSize = u4(dex, 0x40), typeIdsOff = u4(dex, 0x44);
                int methodIdsSize = u4(dex, 0x58), methodIdsOff = u4(dex, 0x5c);
                int classDefsSize = u4(dex, 0x60), classDefsOff = u4(dex, 0x64);
                if (stringIdsSize <= 0 || stringIdsSize > 2000000 || stringIdsOff <= 0 || stringIdsOff + stringIdsSize * 4L > dex.length) return "";
                if (typeIdsSize <= 0 || typeIdsOff <= 0 || typeIdsOff + typeIdsSize * 4L > dex.length) return "";
                if (methodIdsSize <= 0 || methodIdsOff <= 0 || methodIdsOff + methodIdsSize * 8L > dex.length) return "";
                if (classDefsSize <= 0 || classDefsOff <= 0 || classDefsOff + classDefsSize * 32L > dex.length) return "";

                int targetClassString = -1, methodDString = -1;
                for (int i = 0; i < stringIdsSize; i++) {
                    int off = u4(dex, stringIdsOff + i * 4);
                    if (targetClassString < 0 && dexStringEqualsAscii(dex, off, "Lcom/iapp/app/run/mian;")) targetClassString = i;
                    if (methodDString < 0 && dexStringEqualsAscii(dex, off, "d")) methodDString = i;
                    if (targetClassString >= 0 && methodDString >= 0) break;
                }
                if (targetClassString < 0 || methodDString < 0) return "";

                int targetType = -1;
                for (int i = 0; i < typeIdsSize; i++) {
                    int si = u4(dex, typeIdsOff + i * 4);
                    if (si == targetClassString) { targetType = i; break; }
                }
                if (targetType < 0) return "";

                for (int c = 0; c < classDefsSize; c++) {
                    int off = classDefsOff + c * 32;
                    int classIdx = u4(dex, off);
                    int classDataOff = u4(dex, off + 24);
                    if (classIdx != targetType || classDataOff <= 0 || classDataOff >= dex.length) continue;
                    int[] pp = new int[]{classDataOff};
                    int staticFields = readUleb(dex, pp);
                    int instanceFields = readUleb(dex, pp);
                    int directMethods = readUleb(dex, pp);
                    int virtualMethods = readUleb(dex, pp);
                    for (int i = 0; i < staticFields + instanceFields; i++) { readUleb(dex, pp); readUleb(dex, pp); }
                    int methodIdx = 0;
                    for (int i = 0; i < directMethods + virtualMethods; i++) {
                        methodIdx += readUleb(dex, pp);
                        readUleb(dex, pp);
                        int codeOff = readUleb(dex, pp);
                        if (methodIdx < 0 || methodIdx >= methodIdsSize || codeOff <= 0) continue;
                        int moff = methodIdsOff + methodIdx * 8;
                        if (u2(dex, moff) == targetType && u4(dex, moff + 4) == methodDString) {
                            String v = extractMainFileFromCodeItem(dex, stringIdsSize, stringIdsOff, codeOff);
                            if (v.length() > 0) return v;
                        }
                    }
                }
            } catch(Exception ignored) {}
            return "";
        }

        static boolean dexStringEqualsAscii(byte[] dex, int off, String ascii) {
            try {
                if (dex == null || ascii == null || off <= 0 || off >= dex.length) return false;
                int[] pp = new int[]{off};
                int utf16len = readUleb(dex, pp);
                int p = pp[0];
                int n = ascii.length();
                if (utf16len != n || p < 0 || p + n >= dex.length) return false;
                for (int i = 0; i < n; i++) if ((dex[p + i] & 0xff) != ascii.charAt(i)) return false;
                return dex[p + n] == 0;
            } catch(Exception ignored) { return false; }
        }

        static String readDexStringById(byte[] dex, int stringIdsSize, int stringIdsOff, int idx) {
            try {
                if (idx < 0 || idx >= stringIdsSize) return "";
                int off = u4(dex, stringIdsOff + idx * 4);
                return readDexStringAt(dex, off);
            } catch(Exception ignored) { return ""; }
        }

        static String readDexStringAt(byte[] dex, int off) {
            try {
                if (off <= 0 || off >= dex.length) return "";
                int[] pp = new int[]{off}; readUleb(dex, pp);
                int p = pp[0], q = p;
                while (q < dex.length && dex[q] != 0 && q - p <= 1024) q++;
                if (q <= p || q >= dex.length) return "";
                return new String(dex, p, q - p, "UTF-8");
            } catch(Exception ignored) { return ""; }
        }

        static String extractMainFileFromCodeItem(byte[] dex, int stringIdsSize, int stringIdsOff, int codeOff) {
            try {
                if (codeOff <= 0 || codeOff + 16 > dex.length) return "";
                int insnsSize = u4(dex, codeOff + 12);
                int p = codeOff + 16;
                if (insnsSize <= 0 || p + insnsSize * 2L > dex.length) return "";
                for (int i = 0; i < insnsSize; i++) {
                    int pos = p + i * 2;
                    int op = dex[pos] & 0xff;
                    int idx = -1;
                    if (op == 0x1a && i + 1 < insnsSize) idx = u2(dex, pos + 2);
                    else if (op == 0x1b && i + 2 < insnsSize) idx = u4(dex, pos + 2);
                    if (idx < 0 || idx >= stringIdsSize) continue;
                    String candidate = safeMainFileCandidate(readDexStringById(dex, stringIdsSize, stringIdsOff, idx));
                    if (candidate.length() > 0) return candidate;
                }
            } catch(Exception ignored) {}
            return "";
        }

        static String extractMainFileRawLight(byte[] dex) {
            if (dex == null || dex.length == 0) return "";
            String best = ""; int bestScore = Integer.MIN_VALUE;
            String[] exts = new String[]{".iyu", ".myu", ".mjava", ".mlua", ".mjs", ".ijs", ".ilua", ".ijava"};
            for (int ei = 0; ei < exts.length; ei++) {
                byte[] needle;
                try { needle = exts[ei].getBytes("UTF-8"); } catch(Exception e) { continue; }
                for (int p = 0; p + needle.length < dex.length; p++) {
                    int j = 0;
                    while (j < needle.length && lowerAscii(dex[p + j] & 0xff) == needle[j]) j++;
                    if (j != needle.length) continue;
                    int s = p - 1;
                    while (s >= 0 && p - s <= 96 && isMainFileByte(dex[s] & 0xff)) s--;
                    int e = p + needle.length;
                    while (e < dex.length && e - p <= 24 && isMainFileByte(dex[e] & 0xff)) e++;
                    if (e <= p || s + 1 >= p) continue;
                    String raw;
                    try { raw = new String(dex, s + 1, e - (s + 1), "UTF-8"); } catch(Exception ignored) { continue; }
                    String cand = safeMainFileCandidate(raw);
                    if (cand.length() == 0) continue;
                    String low = cand.toLowerCase(Locale.US);
                    int score = low.endsWith(".iyu") ? 40 : 20;
                    if ("mian.iyu".equals(low)) score += 60;
                    if (low.indexOf("main") >= 0 || low.indexOf("mian") >= 0) score += 20;
                    if (score > bestScore) { bestScore = score; best = cand; }
                    if (bestScore >= 100) return best;
                }
            }
            return best;
        }

        static int lowerAscii(int c) { return (c >= 'A' && c <= 'Z') ? (c + 32) : c; }
        static boolean isMainFileByte(int c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        }

        static void addMainScore(LinkedHashMap<String,Integer> scores, String name, int delta) {
            String candidate = safeMainFileCandidate(name);
            if (candidate.length() == 0) return;
            Integer old = scores.get(candidate);
            scores.put(candidate, Integer.valueOf((old == null ? 0 : old.intValue()) + delta));
        }

        static void scoreDexMainFileContext(byte[] dex, ArrayList<String> strings, LinkedHashMap<String,Integer> scores) {
            if (dex == null || strings == null || strings.size() == 0) return;
            HashSet<Integer> triggerIds = new HashSet<Integer>();
            HashMap<Integer,String> mainIds = new HashMap<Integer,String>();
            for (int i = 0; i < strings.size(); i++) {
                String value = strings.get(i);
                if ("OpenFilexmlui".equals(value) || "OpenFile".equals(value) || "xmlui".equalsIgnoreCase(value)) triggerIds.add(Integer.valueOf(i));
                String candidate = safeMainFileCandidate(value);
                if (candidate.length() > 0) mainIds.put(Integer.valueOf(i), candidate);
            }
            if (triggerIds.size() == 0 || mainIds.size() == 0) return;
            ArrayList<int[]> triggerRefs = new ArrayList<int[]>();
            ArrayList<int[]> mainRefs = new ArrayList<int[]>();
            // DEX code_item instruction streams are 16-bit aligned.  A bounded raw
            // const-string scan avoids shipping a full DEX disassembler in the client.
            for (int pos = 0; pos + 6 <= dex.length; pos += 2) {
                int op = dex[pos] & 0xff;
                int idx = -1;
                if (op == 0x1a) idx = u2(dex, pos + 2);
                else if (op == 0x1b && pos + 6 <= dex.length) idx = u4(dex, pos + 2);
                if (idx < 0 || idx >= strings.size()) continue;
                if (triggerIds.contains(Integer.valueOf(idx))) triggerRefs.add(new int[]{pos, idx});
                String mf = mainIds.get(Integer.valueOf(idx));
                if (mf != null) mainRefs.add(new int[]{pos, idx});
            }
            for (int ti = 0; ti < triggerRefs.size(); ti++) {
                int tp = triggerRefs.get(ti)[0];
                for (int mi = 0; mi < mainRefs.size(); mi++) {
                    int mp = mainRefs.get(mi)[0];
                    int dist = Math.abs(mp - tp);
                    if (dist > 96) continue;
                    String mf = mainIds.get(Integer.valueOf(mainRefs.get(mi)[1]));
                    int bonus = dist <= 8 ? 500 : (dist <= 24 ? 240 : 100);
                    addMainScore(scores, mf, bonus);
                }
            }
        }

        static ArrayList<String> readDexStringPool(byte[] dex) {
            ArrayList<String> out = new ArrayList<String>();
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return out;
                int count = u4(dex, 0x38), off = u4(dex, 0x3c);
                if (count < 0 || count > 2000000 || off < 0 || off + count * 4L > dex.length) return out;
                for (int i = 0; i < count; i++) {
                    int p0 = u4(dex, off + i * 4);
                    if (p0 <= 0 || p0 >= dex.length) continue;
                    int[] pp = new int[]{p0}; readUleb(dex, pp);
                    int p = pp[0], q = p;
                    while (q < dex.length && dex[q] != 0 && q - p <= 1024) q++;
                    if (q > p && q < dex.length) out.add(new String(dex, p, q - p, "UTF-8"));
                }
            } catch(Exception ignored) {}
            return out;
        }

        static String safeMainFileCandidate(String value) {
            if (value == null) return "";
            String s = value.trim();
            if (s.length() < 5 || s.length() > 180 || s.indexOf("..") >= 0 || s.indexOf('/') >= 0 || s.indexOf('\\') >= 0) return "";
            if (!s.matches("[-\\p{L}\\p{N}_.]+\\.(?i:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)")) return "";
            return s;
        }

        static int countBytes(byte[] haystack, byte[] needle) {
            if (haystack == null || needle == null || needle.length == 0) return 0;
            int count = 0;
            for (int i = 0; i + needle.length <= haystack.length; ) {
                int j = 0;
                while (j < needle.length && haystack[i+j] == needle[j]) j++;
                if (j == needle.length) { count++; i += needle.length; }
                else i++;
            }
            return count;
        }

        static class DynamicSoFeatureRow {
            final String abi;
            final String sha256;
            final String entryName;
            DynamicSoFeatureRow(String abi, String sha256, String entryName) {
                this.abi = abi;
                this.sha256 = sha256;
                this.entryName = entryName;
            }
        }

        static class DynamicSoFingerprintInfo {
            final ArrayList<DynamicSoFeatureRow> rows = new ArrayList<DynamicSoFeatureRow>();
            final JSONObject features = new JSONObject();
            String firstEntry = "";
            String firstAbi = "";
            boolean defaultScheme = false;
            boolean hasLibraries() { return rows.size() > 0; }
        }

        static DynamicSoFingerprintInfo inspectDynamicSoSource(File source) throws Exception {
            if (source == null || !source.isFile()) throw new IOException("文件不存在");
            FileInputStream in = new FileInputStream(source);
            byte[] head = new byte[4];
            int n;
            try { n = in.read(head); } finally { try { in.close(); } catch(Exception ignored) {} }
            if (n == 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
                if (source.length() > 128L * 1024L * 1024L) throw new IOException("libygsiyu.so 超过 128MB");
                byte[] so = readFileBytes(source, 128 * 1024 * 1024);
                DynamicSoFingerprintInfo info = new DynamicSoFingerprintInfo();
                String abi = dynamicSoAbi(source.getName(), so);
                String feature = dynamicSoFeatureSha256(so);
                info.rows.add(new DynamicSoFeatureRow(abi, feature, source.getName()));
                info.features.put(abi, feature);
                info.firstEntry = source.getName();
                info.firstAbi = abi;
                info.defaultScheme = defaultDynamicSoFeature(abi).equalsIgnoreCase(feature);
                return info;
            }
            return inspectDynamicSoFingerprints(source);
        }

        static DynamicSoFingerprintInfo inspectDynamicSoFingerprints(File apk) throws Exception {
            String key = apkScanCacheKey(apk, "dynamic_so");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof DynamicSoFingerprintInfo) return (DynamicSoFingerprintInfo)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof DynamicSoFingerprintInfo) return (DynamicSoFingerprintInfo)cached;
                DynamicSoFingerprintInfo value = inspectDynamicSoFingerprintsUncached(apk);
                apkScanCachePut(key, value);
                return value;
            }
        }

        static DynamicSoFingerprintInfo inspectDynamicSoFingerprintsUncached(File apk) throws Exception {
            if (apk == null || !apk.isFile()) throw new IOException("APK 文件不存在");
            DynamicSoFingerprintInfo info = new DynamicSoFingerprintInfo();
            ZipFile z = new ZipFile(apk);
            try {
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String name = e.getName().replace('\\', '/');
                    String low = name.toLowerCase(Locale.US);
                    if (!low.endsWith("/libygsiyu.so") && !"libygsiyu.so".equals(low)) continue;
                    if (e.getSize() > 128L * 1024L * 1024L) throw new IOException("libygsiyu.so 超过 128MB");
                    byte[] so = readZipEntryBytes(z, e, 128 * 1024 * 1024);
                    if (so.length < 20 || so[0] != 0x7f || so[1] != 'E' || so[2] != 'L' || so[3] != 'F') continue;
                    String abi = dynamicSoAbi(name, so);
                    if (info.features.has(abi)) continue;
                    String feature = dynamicSoFeatureSha256(so);
                    info.rows.add(new DynamicSoFeatureRow(abi, feature, name));
                    info.features.put(abi, feature);
                    if (info.firstEntry.length() == 0) {
                        info.firstEntry = name;
                        info.firstAbi = abi;
                    }
                }
            } finally {
                try { z.close(); } catch(Exception ignored) {}
            }
            if (info.hasLibraries()) {
                boolean allDefault = true;
                for (int i=0; i<info.rows.size(); i++) {
                    DynamicSoFeatureRow row = info.rows.get(i);
                    String expected = defaultDynamicSoFeature(row.abi);
                    if (expected.length() == 0 || !expected.equalsIgnoreCase(row.sha256)) {
                        allDefault = false;
                        break;
                    }
                }
                info.defaultScheme = allDefault;
            }
            return info;
        }

        static int findFirstPoolFeatureMatch(DynamicSoFingerprintInfo info, ArrayList<JSONObject> schemeFeatures) {
            if (info == null || schemeFeatures == null) return -1;
            // APK archive order wins: the first ABI fingerprint that matches a
            // downloaded scheme selects that scheme.
            for (int r=0; r<info.rows.size(); r++) {
                DynamicSoFeatureRow row = info.rows.get(r);
                for (int i=2; i<schemeFeatures.size(); i++) {
                    JSONObject features = schemeFeatures.get(i);
                    if (features == null) continue;
                    String expected = features.optString(row.abi, "").trim();
                    if (expected.length() > 0 && expected.equalsIgnoreCase(row.sha256)) return i;
                }
            }
            return -1;
        }

        static String defaultDynamicSoFeature(String abi) {
            String a = abi == null ? "" : abi.toLowerCase(Locale.US);
            if ("arm64-v8a".equals(a)) return "3a23c0921beff4f64807f0fb146effacace9e1ad9da8df6922386d73a125859f";
            if ("armeabi".equals(a)) return "837c17e37a8023e36234fd8dedf6551e95117f95dd83ebdbf84f863460b7c62d";
            if ("armeabi-v7a".equals(a)) return "1d14f12ceba3532730b0efa2d7c53955cecd647d1a44500358f9a4ede036a41f";
            if ("x86".equals(a)) return "48ef70262dcda6c4593f3beb357cf2a5ac02339959c3c67053a80fc96c004ac8";
            if ("x86_64".equals(a)) return "48ee9648c16183f452813ba4c9a775e797bff91c97dbad9dfb41be27d294e758";
            return "";
        }

        static String dynamicSoFeatureSha256(byte[] so) throws Exception {
            byte[] normalized = so == null ? new byte[0] : (byte[])so.clone();
            byte[] placeholder = "YDXFKCDOTN".getBytes("US-ASCII");
            for (int i=0; i+32<=normalized.length; ) {
                boolean prefix = true;
                boolean exactPlaceholder = true;
                for (int j=0; j<10; j++) {
                    if (normalized[i+j] != placeholder[j]) exactPlaceholder = false;
                    if (!isHexAscii(normalized[i+j])) prefix = false;
                }
                prefix = prefix || exactPlaceholder;
                boolean suffix = prefix;
                for (int j=10; suffix && j<20; j++) suffix = normalized[i+j] == 'Q';
                for (int j=20; suffix && j<30; j++) suffix = normalized[i+j] == 'W';
                if (suffix) suffix = normalized[i+30] == 'E' && normalized[i+31] == 'E';
                if (suffix) {
                    for (int j=0; j<32; j++) normalized[i+j] = '0';
                    i += 32;
                } else i++;
            }
            return sha256Hex(normalized);
        }

        static boolean isHexAscii(byte b) {
            int v = b & 0xff;
            return (v >= '0' && v <= '9') || (v >= 'A' && v <= 'F') || (v >= 'a' && v <= 'f');
        }

        static String dynamicSoAbi(String entryName, byte[] so) {
            String name = entryName == null ? "" : entryName.replace('\\', '/').toLowerCase(Locale.US);
            String[] known = new String[]{"arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86"};
            for (int i=0; i<known.length; i++) if (name.indexOf("/" + known[i] + "/") >= 0 || name.startsWith(known[i] + "/")) return known[i];
            if (so != null && so.length >= 20) {
                int machine = (so[18] & 0xff) | ((so[19] & 0xff) << 8);
                if (machine == 183) return "arm64-v8a";
                if (machine == 40) return "armeabi-v7a";
                if (machine == 62) return "x86_64";
                if (machine == 3) return "x86";
            }
            return "unknown";
        }

        static byte[] readFileBytes(File file, int maxBytes) throws Exception {
            InputStream in = new BufferedInputStream(new FileInputStream(file), 64 * 1024);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[64 * 1024];
            int total = 0;
            try {
                for (;;) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    total += n;
                    if (total > maxBytes) throw new IOException("file too large: " + file.getName());
                    out.write(buf, 0, n);
                }
            } finally { try { in.close(); } catch(Exception ignored) {} }
            return out.toByteArray();
        }

        static byte[] readZipEntryBytes(ZipFile z, ZipEntry entry, int maxBytes) throws Exception {
            InputStream in = new BufferedInputStream(z.getInputStream(entry), 64 * 1024);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[64 * 1024];
            int total = 0;
            try {
                for (;;) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    total += n;
                    if (total > maxBytes) throw new IOException("ZIP entry too large: " + entry.getName());
                    out.write(buf, 0, n);
                }
            } finally {
                try { in.close(); } catch(Exception ignored) {}
            }
            return out.toByteArray();
        }

        static String extractSokeyFromApkTextSearch(File apk) {
            String key = apkScanCacheKey(apk, "sokey");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof String) return (String)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof String) return (String)cached;
                String value = extractSokeyFromApkTextSearchUncached(apk);
                if (value == null) value = "";
                apkScanCachePut(key, value);
                return value;
            }
        }

        static String extractSokeyFromApkTextSearchUncached(File apk) {
            // 新版 V3 hidden/sokey：只提取完整 32 位模式。
            // 远古 4 位 sokey 走 extractLegacySokeyFromApkConsensus，避免新版样本误判。
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> names = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String name = e.getName().replace('\\','/');
                    String low = name.toLowerCase(Locale.US);
                    if (low.endsWith("/libygsiyu.so") || "libygsiyu.so".equals(low)) names.add(e.getName());
                }
                Collections.sort(names, new Comparator<String>(){ public int compare(String a, String b){
                    int pa = ygsiyuUploadPriority(a), pb = ygsiyuUploadPriority(b);
                    if (pa != pb) return pa - pb;
                    return a.compareToIgnoreCase(b);
                }});
                byte[] suffix = "QQQQQQQQQQWWWWWWWWWWEE".getBytes("US-ASCII");
                for (int i=0; i<names.size(); i++) {
                    ZipEntry e = z.getEntry(names.get(i));
                    if (e == null || e.getSize() > 128L * 1024L * 1024L) continue;
                    byte[] data = readZipEntryBytes(z, e, 128 * 1024 * 1024);
                    String hidden = findSokeyInBytes(data, suffix);
                    if (hidden.length() > 0) return hidden;
                }
            } catch(Exception e) {
            } finally { try { if (z != null) z.close(); } catch(Exception e) {} }
            return "";
        }

        static String findSokeyInBytes(byte[] data, byte[] suffix) {
            if (data == null || suffix == null || data.length < 32) return "";
            for (int i=10; i+suffix.length<=data.length; i++) {
                boolean ok = true;
                for (int j=0; j<suffix.length; j++) { if (data[i+j] != suffix[j]) { ok = false; break; } }
                if (!ok) continue;
                boolean prefix = true;
                for (int j=i-10; j<i; j++) {
                    int c = data[j] & 0xff;
                    boolean alnum = (c>='0'&&c<='9') || (c>='A'&&c<='Z') || (c>='a'&&c<='z');
                    if (!alnum) { prefix = false; break; }
                }
                if (prefix) {
                    try { return new String(data, i-10, 32, "US-ASCII"); } catch(Exception ignored) { return ""; }
                }
            }
            return "";
        }

        static String extractDexKeyFromApk(File apk) {
            String key = apkScanCacheKey(apk, "dexkey");
            Object cached = apkScanCacheGet(key);
            if (cached instanceof String) return (String)cached;
            synchronized (apkScanLock(key)) {
                cached = apkScanCacheGet(key);
                if (cached instanceof String) return (String)cached;
                String value = extractDexKeyFromApkUncached(apk);
                if (value == null) value = "";
                apkScanCachePut(key, value);
                return value;
            }
        }

        static String extractDexKeyFromApkUncached(File apk) {
            ZipFile z = null;
            try {
                z = new ZipFile(apk);
                ArrayList<String> dexNames = new ArrayList<String>();
                Enumeration<? extends ZipEntry> en = z.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null || e.isDirectory()) continue;
                    String simple = e.getName();
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    if (isDexFileName(simple)) dexNames.add(e.getName());
                }
                Collections.sort(dexNames, new Comparator<String>() { public int compare(String a, String b) { return dexOrder(a) - dexOrder(b); }});
                byte[] buf = new byte[1024 * 1024];
                for (int i = 0; i < dexNames.size(); i++) {
                    ZipEntry e = z.getEntry(dexNames.get(i));
                    if (e == null) continue;
                    ByteArrayOutputStream baos = new ByteArrayOutputStream(e.getSize() > 0 && e.getSize() < 64L * 1024L * 1024L ? (int)e.getSize() : 4096);
                    InputStream in = new BufferedInputStream(z.getInputStream(e), 1024 * 1024);
                    try { copyStream(in, baos, buf); } finally { try { in.close(); } catch(Exception ex) {} }
                    Integer v = extractFbFromDex(baos.toByteArray());
                    if (v != null) return String.valueOf(v.intValue());
                }
                Integer nativeVmp = extractVmpDexKeyFromNative(z);
                if (nativeVmp != null) return String.valueOf(nativeVmp.intValue());
            } catch(Exception e) {
            } finally { try { if (z != null) z.close(); } catch(Exception e) {} }
            return "";
        }

        static Integer extractFbFromDex(byte[] dex) {
            try {
                if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return null;
                int stringIdsSize = u4(dex, 0x38), stringIdsOff = u4(dex, 0x3c);
                int typeIdsSize = u4(dex, 0x40), typeIdsOff = u4(dex, 0x44);
                int protoIdsSize = u4(dex, 0x48), protoIdsOff = u4(dex, 0x4c);
                int methodIdsSize = u4(dex, 0x58), methodIdsOff = u4(dex, 0x5c);
                int classDefsSize = u4(dex, 0x60), classDefsOff = u4(dex, 0x64);
                String[] strings = new String[stringIdsSize];
                for (int i = 0; i < stringIdsSize; i++) {
                    int off = u4(dex, stringIdsOff + i * 4);
                    int[] pp = new int[]{off}; readUleb(dex, pp);
                    int p = pp[0], q = p;
                    while (q < dex.length && dex[q] != 0) q++;
                    strings[i] = new String(dex, p, Math.max(0, q - p), "UTF-8");
                }
                int[] typeStringIdx = new int[typeIdsSize];
                int targetType = -1;
                for (int i = 0; i < typeIdsSize; i++) {
                    int si = u4(dex, typeIdsOff + i * 4);
                    typeStringIdx[i] = si;
                    if (si >= 0 && si < strings.length && "Lcom/iapp/app/f;".equals(strings[si])) targetType = i;
                }
                if (targetType < 0) return null;
                String[] protoShorty = new String[protoIdsSize];
                String[] protoRet = new String[protoIdsSize];
                for (int i = 0; i < protoIdsSize; i++) {
                    int off = protoIdsOff + i * 12;
                    int shortyIdx = u4(dex, off);
                    int retTypeIdx = u4(dex, off + 4);
                    protoShorty[i] = safeString(strings, shortyIdx);
                    int retStrIdx = retTypeIdx >= 0 && retTypeIdx < typeStringIdx.length ? typeStringIdx[retTypeIdx] : -1;
                    protoRet[i] = safeString(strings, retStrIdx);
                }
                int[] mClass = new int[methodIdsSize];
                int[] mProto = new int[methodIdsSize];
                int[] mName = new int[methodIdsSize];
                for (int i = 0; i < methodIdsSize; i++) {
                    int off = methodIdsOff + i * 8;
                    mClass[i] = u2(dex, off);
                    mProto[i] = u2(dex, off + 2);
                    mName[i] = u4(dex, off + 4);
                }
                for (int c = 0; c < classDefsSize; c++) {
                    int off = classDefsOff + c * 32;
                    int classIdx = u4(dex, off);
                    int classDataOff = u4(dex, off + 24);
                    if (classIdx != targetType || classDataOff == 0) continue;
                    int[] pp = new int[]{classDataOff};
                    int staticFields = readUleb(dex, pp);
                    int instanceFields = readUleb(dex, pp);
                    int directMethods = readUleb(dex, pp);
                    int virtualMethods = readUleb(dex, pp);
                    for (int i = 0; i < staticFields + instanceFields; i++) { readUleb(dex, pp); readUleb(dex, pp); }
                    int methodIdx = 0;
                    for (int i = 0; i < directMethods + virtualMethods; i++) {
                        methodIdx += readUleb(dex, pp);
                        readUleb(dex, pp);
                        int codeOff = readUleb(dex, pp);
                        if (methodIdx < 0 || methodIdx >= methodIdsSize) continue;
                        String methodName = safeString(strings, mName[methodIdx]);
                        String shorty = mProto[methodIdx] >= 0 && mProto[methodIdx] < protoShorty.length ? protoShorty[mProto[methodIdx]] : "";
                        String ret = mProto[methodIdx] >= 0 && mProto[methodIdx] < protoRet.length ? protoRet[mProto[methodIdx]] : "";
                        if (mClass[methodIdx] == targetType && "b".equals(methodName) && "I".equals(shorty) && "I".equals(ret) && codeOff > 0) {
                            return readDexConstReturnInt(dex, codeOff);
                        }
                    }
                }
            } catch(Exception e) {}
            return null;
        }

        static Integer readDexConstReturnInt(byte[] dex, int codeOff) {
            try {
                if (codeOff <= 0 || codeOff + 16 > dex.length) return null;
                int insnsSize = u4(dex, codeOff + 12);
                int p = codeOff + 16;
                if (p + insnsSize * 2 > dex.length) return null;
                Integer lastConst = null;
                int lastReg = -1;
                int i = 0;
                while (i < insnsSize) {
                    int inst = u2(dex, p + i * 2);
                    int op = inst & 0xff;
                    if (op == 0x12) {
                        int aa = (inst >> 8) & 0xff;
                        int reg = aa & 0x0f;
                        int imm = (aa >> 4) & 0x0f;
                        if ((imm & 0x8) != 0) imm -= 0x10;
                        lastReg = reg; lastConst = Integer.valueOf(imm); i += 1; continue;
                    }
                    if (op == 0x13 && i + 1 < insnsSize) {
                        int reg = (inst >> 8) & 0xff;
                        int imm = u2(dex, p + (i + 1) * 2);
                        if ((imm & 0x8000) != 0) imm -= 0x10000;
                        lastReg = reg; lastConst = Integer.valueOf(imm); i += 2; continue;
                    }
                    if (op == 0x14 && i + 2 < insnsSize) {
                        int reg = (inst >> 8) & 0xff;
                        int imm = u2(dex, p + (i + 1) * 2) | (u2(dex, p + (i + 2) * 2) << 16);
                        lastReg = reg; lastConst = Integer.valueOf(imm); i += 3; continue;
                    }
                    if (op == 0x15 && i + 1 < insnsSize) {
                        int reg = (inst >> 8) & 0xff;
                        int imm = u2(dex, p + (i + 1) * 2) << 16;
                        lastReg = reg; lastConst = Integer.valueOf(imm); i += 2; continue;
                    }
                    if (op == 0x0f) {
                        int reg = (inst >> 8) & 0xff;
                        if (lastConst != null && (lastReg < 0 || lastReg == reg)) return lastConst;
                        return lastConst;
                    }
                    i += 1;
                }
                return lastConst;
            } catch(Exception e) { return null; }
        }

        static String safeString(String[] arr, int idx) { return idx >= 0 && idx < arr.length && arr[idx] != null ? arr[idx] : ""; }
        static int u2(byte[] b, int p) { return (b[p] & 0xff) | ((b[p+1] & 0xff) << 8); }
        static int u4(byte[] b, int p) { return (b[p] & 0xff) | ((b[p+1] & 0xff) << 8) | ((b[p+2] & 0xff) << 16) | ((b[p+3] & 0xff) << 24); }
        static int readUleb(byte[] b, int[] pp) {
            int p = pp[0], result = 0, shift = 0;
            while (p < b.length) {
                int v = b[p++] & 0xff;
                result |= (v & 0x7f) << shift;
                if (v < 0x80) break;
                shift += 7;
            }
            pp[0] = p;
            return result;
        }

        static File prepareV6DexOnlyUpload(File src) throws Exception {
            String lower = src.getName().toLowerCase(Locale.US);
            if (lower.endsWith(".dex")) return src;
            File tmp = File.createTempFile("iapt_v6_dex_", ".zip");
            int count = 0;
            try {
                count = copyDexesFromFileToZip(src, tmp, 0);
            } catch (OutOfMemoryError oom) {
                try { tmp.delete(); } catch(Exception e) {}
                throw new Exception("V6提取DEX内存不足，请直接选择DEX文件");
            }
            if (count <= 0) {
                try { tmp.delete(); } catch(Exception e) {}
                throw new Exception("未找到 DEX");
            }
            return tmp;
        }

        static int copyDexesFromFileToZip(File src, File outZip, int depth) throws Exception {
            ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outZip)));
            try {
                FileInputStream fis = new FileInputStream(src);
                try { return copyDexesFromZipStream(fis, zos, depth); }
                finally { try { fis.close(); } catch(Exception e) {} }
            } finally {
                try { zos.close(); } catch(Exception e) {}
            }
        }

        static int copyDexesFromZipStream(InputStream input, ZipOutputStream zos, int depth) throws Exception {
            if (depth > 3) return 0;
            ZipInputStream zis = new ZipInputStream(new BufferedInputStream(input));
            byte[] buf = new byte[8192];
            int copied = 0;
            File nestedBest = null;
            int nestedScore = -1;
            HashSet<String> names = new HashSet<String>();
            try {
                ZipEntry ze;
                while ((ze = zis.getNextEntry()) != null) {
                    String name = ze.getName();
                    String simple = name;
                    int slash = simple.lastIndexOf('/');
                    if (slash >= 0) simple = simple.substring(slash + 1);
                    String lower = name.toLowerCase(Locale.US);
                    if (isDexFileName(simple)) {
                        String outName = normalizeDexName(simple);
                        if (!names.contains(outName)) {
                            names.add(outName);
                            zos.putNextEntry(new ZipEntry(outName));
                            copyStream(zis, zos, buf);
                            zos.closeEntry();
                            copied++;
                        }
                    } else if (copied == 0 && lower.endsWith(".apk")) {
                        int score = lower.startsWith("bin/") ? 3 : (lower.indexOf("/bin/") >= 0 ? 2 : 1);
                        if (score > nestedScore) {
                            if (nestedBest != null) { try { nestedBest.delete(); } catch(Exception e) {} }
                            nestedBest = File.createTempFile("iapt_v6_nested_", ".apk");
                            FileOutputStream fos = new FileOutputStream(nestedBest);
                            try { copyStream(zis, fos, buf); }
                            finally { try { fos.close(); } catch(Exception e) {} }
                            nestedScore = score;
                        }
                    }
                    zis.closeEntry();
                }
            } finally {
                try { zis.close(); } catch(Exception e) {}
            }
            if (copied == 0 && nestedBest != null) {
                FileInputStream nf = new FileInputStream(nestedBest);
                try { copied = copyDexesFromZipStream(nf, zos, depth + 1); }
                finally { try { nf.close(); } catch(Exception e) {}; try { nestedBest.delete(); } catch(Exception e) {} }
            } else if (nestedBest != null) {
                try { nestedBest.delete(); } catch(Exception e) {}
            }
            return copied;
        }

        static void copyStream(InputStream in, OutputStream out, byte[] buf) throws Exception {
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }

        static String normalizeDexName(String name) {
            if ("classes.dex".equals(name)) return "classes.dex";
            if (name != null && name.matches("classes(\\d+)\\.dex")) return name;
            return "classes.dex";
        }

        static boolean isDexFileName(String name) {
            return name != null && name.matches("classes(\\d*)\\.dex");
        }

        static byte[] readEntryBytes(InputStream in, byte[] buf) throws Exception {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int n;
            while ((n = in.read(buf)) > 0) baos.write(buf, 0, n);
            return baos.toByteArray();
        }

        byte[] downloadBytes(String route) throws Exception {
            URL url = new URL(base + route); String path = url.getPath();
            String salt = hex(randomBytes(12)); String ts = String.valueOf(System.currentTimeMillis()/1000L); String nonce = hex(randomBytes(12)); String bodyHash = sha256Hex(new byte[0]); String tk = token(); String sign = sign("GET", path, ts, nonce, salt, bodyHash, tk);
            HttpURLConnection c = (HttpURLConnection)url.openConnection(); c.setRequestMethod("GET"); c.setConnectTimeout(15000); c.setReadTimeout(60000); c.setUseCaches(true);
            c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
            c.setRequestProperty("X-IAPT-Upload-Mode", "serial-linear-v100");
            c.setRequestProperty("Authorization", "Bearer " + tk); c.setRequestProperty("X-App-Id", appId); c.setRequestProperty("X-Timestamp", ts); c.setRequestProperty("X-Nonce", nonce); c.setRequestProperty("X-Salt", salt); c.setRequestProperty("X-Body-Hash", bodyHash); c.setRequestProperty("X-Sign", sign);
            int code=c.getResponseCode(); if(code<200||code>=300){ String err=read(c.getErrorStream()); if(code==401) throw new AuthException(errorText(err, code)); throw new Exception(errorText(err, code)); }
            return readBytes(c.getInputStream());
        }

        // IAPT_CHUNK_DOWNLOAD_V13_BEGIN
        byte[] downloadV13Chunk(String route) throws Exception {
            Exception last = null;
            for (int attempt = 1; attempt <= 5; attempt++) {
                HttpURLConnection c = null;
                try {
                    URL url = new URL(base + route);
                    String path = url.getPath() + (url.getQuery()==null?"":"?"+url.getQuery());
                    String salt = hex(randomBytes(12));
                    String ts = String.valueOf(System.currentTimeMillis()/1000L);
                    String nonce = hex(randomBytes(12));
                    String bodyHash = sha256Hex(new byte[0]);
                    String tk = token();
                    String sign = sign("GET", path, ts, nonce, salt, bodyHash, tk);
                    c = (HttpURLConnection)url.openConnection();
                    c.setRequestMethod("GET");
                    c.setConnectTimeout(25000);
                    c.setReadTimeout(120000);
                    c.setUseCaches(false);
                    c.setRequestProperty("Accept-Encoding", "identity");
                    c.setRequestProperty("Cache-Control", "no-cache");
                    c.setRequestProperty("Authorization", "Bearer " + tk);
                    c.setRequestProperty("X-App-Id", appId);
                    c.setRequestProperty("X-Timestamp", ts);
                    c.setRequestProperty("X-Nonce", nonce);
                    c.setRequestProperty("X-Salt", salt);
                    c.setRequestProperty("X-Body-Hash", bodyHash);
                    c.setRequestProperty("X-Sign", sign);
                    int code = c.getResponseCode();
                    if (code < 200 || code >= 300) {
                        String err = read(c.getErrorStream());
                        if (code == 401) throw new AuthException(errorText(err, code));
                        throw new Exception(errorText(err, code));
                    }
                    long expected = c.getContentLengthLong();
                    if (expected < 0L) expected = c.getContentLength();
                    InputStream in = new BufferedInputStream(c.getInputStream(), 256 * 1024);
                    ByteArrayOutputStream baos = expected > 0L && expected <= Integer.MAX_VALUE
                            ? new ByteArrayOutputStream((int)expected) : new ByteArrayOutputStream();
                    byte[] buf = new byte[64 * 1024];
                    long total = 0L;
                    try {
                        while (true) {
                            int n = in.read(buf);
                            if (n < 0) break;
                            if (n == 0) continue;
                            baos.write(buf, 0, n);
                            total += n;
                        }
                    } finally { try { in.close(); } catch(Exception ignored) {} }
                    if (expected >= 0L && total != expected) throw new EOFException("分片长度不完整：" + total + "/" + expected);
                    byte[] data = baos.toByteArray();
                    String chunkSha = c.getHeaderField("x-iapt-chunk-sha256");
                    if (chunkSha != null && chunkSha.length() > 0 && !chunkSha.equalsIgnoreCase(sha256Hex(data))) {
                        throw new IOException("分片校验失败");
                    }
                    return data;
                } catch (Exception e) {
                    last = e;
                    if (e instanceof AuthException || attempt >= 5) throw e;
                    try { Thread.sleep(350L * attempt); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); throw e;
                    }
                } finally { if (c != null) try { c.disconnect(); } catch(Exception ignored) {} }
            }
            throw last == null ? new IOException("下载分片失败") : last;
        }

        byte[] downloadV13Session(JSONObject meta, String chunkPrefix) throws Exception {
            String session = meta.optString("session", "");
            long size = meta.optLong("size", -1L);
            int chunkSize = meta.optInt("chunk_size", 262144);
            if (session.length() == 0 || size < 0L || size > Integer.MAX_VALUE) throw new IOException("下载会话信息无效");
            if (chunkSize < 16384 || chunkSize > 524288) chunkSize = 262144;
            ByteArrayOutputStream all = new ByteArrayOutputStream((int)size);
            long offset = 0L;
            while (offset < size) {
                int want = (int)Math.min((long)chunkSize, size - offset);
                String route = chunkPrefix + "/chunk?session=" + java.net.URLEncoder.encode(session, "UTF-8")
                        + "&offset=" + offset + "&length=" + want;
                byte[] part = downloadV13Chunk(route);
                if (part.length != want) throw new EOFException("分片长度错误：" + part.length + "/" + want);
                all.write(part);
                offset += part.length;
            }
            byte[] data = all.toByteArray();
            if (data.length != (int)size) throw new EOFException("文件长度不完整：" + data.length + "/" + size);
            String sha = meta.optString("sha256", "");
            if (sha.length() > 0 && !sha.equalsIgnoreCase(sha256Hex(data))) throw new IOException("完整文件 SHA256 校验失败");
            return data;
        }

        static void verifyDownloadedZip(File file) throws Exception {
            java.util.zip.ZipFile z = null;
            try {
                z = new java.util.zip.ZipFile(file);
                java.util.Enumeration<? extends java.util.zip.ZipEntry> en = z.entries();
                int count = 0;
                while (en.hasMoreElements()) { java.util.zip.ZipEntry e = en.nextElement(); if (!e.isDirectory()) count++; }
                if (count <= 0) throw new IOException("ZIP 内没有文件");
            } finally { if (z != null) try { z.close(); } catch(Exception ignored) {} }
        }

        File saveV13Zip(byte[] data, File dir, String requestedName) throws Exception {
            String fn = clean(requestedName);
            if (fn.length() == 0) fn = "task.zip";
            if (!fn.toLowerCase(Locale.US).endsWith(".zip")) fn += ".zip";
            File out = uniqueFile(dir, fn);
            File part = new File(out.getAbsolutePath() + ".part");
            FileOutputStream fos = new FileOutputStream(part);
            try { fos.write(data); fos.flush(); } finally { fos.close(); }
            verifyDownloadedZip(part);
            if (!part.renameTo(out)) {
                FileInputStream in = new FileInputStream(part);
                FileOutputStream fin = new FileOutputStream(out);
                byte[] buf = new byte[256 * 1024]; int n;
                try { while ((n = in.read(buf)) > 0) fin.write(buf, 0, n); }
                finally { try { in.close(); } catch(Exception ignored) {} try { fin.close(); } catch(Exception ignored) {} }
                part.delete();
            }
            return out;
        }

        // IAPT_LINEAR_DOWNLOAD_V115_BEGIN
        byte[] downloadV115Linear(JSONObject meta, String streamPrefix) throws Exception {
            String session = meta.optString("session", "");
            long size = meta.optLong("size", -1L);
            if (session.length() == 0 || size < 0L || size > Integer.MAX_VALUE) throw new IOException("下载会话信息无效");
            String route = streamPrefix + "?session=" + java.net.URLEncoder.encode(session, "UTF-8");
            Exception last = null;
            for (int attempt = 1; attempt <= 3; attempt++) {
                HttpURLConnection c = null;
                try {
                    URL url = new URL(base + route);
                    String path = url.getPath() + (url.getQuery()==null?"":"?"+url.getQuery());
                    String salt = hex(randomBytes(12));
                    String ts = String.valueOf(System.currentTimeMillis()/1000L);
                    String nonce = hex(randomBytes(12));
                    String bodyHash = sha256Hex(new byte[0]);
                    String tk = token();
                    String sign = sign("GET", path, ts, nonce, salt, bodyHash, tk);
                    c = (HttpURLConnection)url.openConnection();
                    c.setRequestMethod("GET");
                    c.setConnectTimeout(25000);
                    c.setReadTimeout(15 * 60 * 1000);
                    c.setUseCaches(false);
                    c.setRequestProperty("Accept-Encoding", "identity");
                    c.setRequestProperty("Cache-Control", "no-cache");
                    c.setRequestProperty("Connection", "keep-alive"); c.setRequestProperty("Keep-Alive", "timeout=60, max=100");
                    c.setRequestProperty("X-IAPT-Download-Mode", "linear-512k-v115");
                    c.setRequestProperty("Authorization", "Bearer " + tk);
                    c.setRequestProperty("X-App-Id", appId);
                    c.setRequestProperty("X-Timestamp", ts);
                    c.setRequestProperty("X-Nonce", nonce);
                    c.setRequestProperty("X-Salt", salt);
                    c.setRequestProperty("X-Body-Hash", bodyHash);
                    c.setRequestProperty("X-Sign", sign);
                    int code = c.getResponseCode();
                    if (code < 200 || code >= 300) {
                        String err = read(c.getErrorStream());
                        if (code == 401) throw new AuthException(errorText(err, code));
                        throw new IOException(errorText(err, code));
                    }
                    long expected = c.getContentLengthLong();
                    if (expected < 0L) expected = size;
                    InputStream in = new BufferedInputStream(c.getInputStream(), 512 * 1024);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream((int)size);
                    byte[] buf = new byte[512 * 1024];
                    long total = 0L;
                    try {
                        while (true) {
                            int n = in.read(buf);
                            if (n < 0) break;
                            if (n == 0) continue;
                            baos.write(buf, 0, n);
                            total += n;
                        }
                    } finally { try { in.close(); } catch(Exception ignored) {} }
                    if (total != size || (expected >= 0L && total != expected))
                        throw new EOFException("线性下载长度不完整：" + total + "/" + size);
                    byte[] data = baos.toByteArray();
                    String sha = meta.optString("sha256", "");
                    if (sha.length() > 0 && !sha.equalsIgnoreCase(sha256Hex(data)))
                        throw new IOException("完整文件 SHA256 校验失败");
                    return data;
                } catch (Exception e) {
                    last = e;
                    if (e instanceof AuthException || attempt >= 3) throw e;
                    try { Thread.sleep(500L * attempt); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); throw e;
                    }
                } finally { if (c != null) try { c.disconnect(); } catch(Exception ignored) {} }
            }
            throw last == null ? new IOException("线性下载失败") : last;
        }
        // IAPT_LINEAR_DOWNLOAD_V115_END

        File downloadAdminTaskSource(int id, File dir, String apkName) throws Exception {
            JSONObject meta = get("/admin/tasks/" + id + "/download-source-v13/start");
            byte[] data;
            try {
                data = downloadV115Linear(meta, "/admin/tasks/" + id + "/download-source-v115/stream");
            } catch (Exception linearError) {
                data = downloadV13Session(meta, "/admin/tasks/" + id + "/download-source-v13");
            }
            String fallback = clean(apkName); if (fallback.length()==0) fallback="task";
            if (fallback.toLowerCase(Locale.US).endsWith(".apk")) fallback = fallback.substring(0, fallback.length()-4);
            return saveV13Zip(data, dir, meta.optString("filename", fallback + "_source.zip"));
        }

        File downloadTask(int id, File dir, String apkName) throws Exception {
            JSONObject meta = get("/tasks/" + id + "/download-v13/start");
            byte[] encrypted;
            try {
                encrypted = downloadV115Linear(meta, "/tasks/" + id + "/download-v115/stream");
            } catch (Exception linearError) {
                encrypted = downloadV13Session(meta, "/tasks/" + id + "/download-v13");
            }
            String mode = meta.optString("mode", "");
            byte[] plain = encrypted;
            if (mode.startsWith("aes-")) {
                plain = decryptZip(
                    encrypted, token(), meta.optString("task_no", ""),
                    meta.optString("salt", ""), meta.optString("ts", ""),
                    meta.optString("iv", "")
                );
            }
            String fallback = clean(apkName); if(fallback.length()==0) fallback="task";
            if(!fallback.toLowerCase(Locale.US).endsWith(".zip")) fallback += "_decrypted.zip";
            String name = meta.optString("filename", fallback);
            if (name.toLowerCase(Locale.US).endsWith(".izip")) name = name.substring(0, name.length()-5) + ".zip";
            return saveV13Zip(plain, dir, name);
        }
        // IAPT_CHUNK_DOWNLOAD_V13_END

        static File uniqueFile(File dir, String name) { File f = new File(dir, name); if(!f.exists()) return f; int dot=name.lastIndexOf('.'); String base=dot>0?name.substring(0,dot):name; String ext=dot>0?name.substring(dot):""; for(int i=1;i<999;i++){ f=new File(dir, base+"_"+i+ext); if(!f.exists()) return f; } return f; }
        static String clean(String s){ if(s==null) return ""; return s.replaceAll("[\\/:*?\"<>|]", "_"); }
        static void writeForm(OutputStream os, String b, String name, String value) throws Exception { os.write(("--"+b+"\r\nContent-Disposition: form-data; name=\""+name+"\"\r\n\r\n"+value+"\r\n").getBytes("UTF-8")); }
        static void writeFile(OutputStream os, String b, String name, String fn, File f) throws Exception { os.write(("--"+b+"\r\nContent-Disposition: form-data; name=\""+name+"\"; filename=\""+fn+"\"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n").getBytes("UTF-8")); FileInputStream in=new FileInputStream(f); byte[] buf=new byte[1024 * 1024]; int n; while((n=in.read(buf))>0) os.write(buf,0,n); in.close(); os.write("\r\n".getBytes("UTF-8")); }
        static void writeFileTyped(OutputStream os, String b, String name, String fn, File f, String contentType) throws Exception { os.write(("--"+b+"\r\nContent-Disposition: form-data; name=\""+name+"\"; filename=\""+fn+"\"\r\nContent-Type: "+(contentType==null?"application/octet-stream":contentType)+"\r\n\r\n").getBytes("UTF-8")); FileInputStream in=new FileInputStream(f); byte[] buf=new byte[1024 * 1024]; int n; while((n=in.read(buf))>0) os.write(buf,0,n); in.close(); os.write("\r\n".getBytes("UTF-8")); }

        Enc encrypt(String plain, String salt) throws Exception { byte[] iv=randomBytes(16); SecretKeySpec key=new SecretKeySpec(sha256Bytes((secret+"|aes|"+salt).getBytes("UTF-8")), "AES"); Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding"); cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)); byte[] ct=cipher.doFinal(plain.getBytes("UTF-8")); Enc e=new Enc(); e.data=android.util.Base64.encodeToString(ct, android.util.Base64.NO_WRAP); e.iv=android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP); return e; }
        byte[] decryptZip(byte[] data, String tk, String taskNo, String salt, String ts, String iv64) throws Exception { byte[] iv=android.util.Base64.decode(iv64, android.util.Base64.NO_WRAP); byte[] keyRaw=(secret+"|zip|"+tk+"|"+taskNo+"|"+salt+"|"+ts).getBytes("UTF-8"); SecretKeySpec key=new SecretKeySpec(sha256Bytes(keyRaw), "AES"); Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding"); cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv)); return cipher.doFinal(data); }
        String sign(String method, String path, String ts, String nonce, String salt, String bodyHash, String tk) throws Exception { String raw=method.toUpperCase(Locale.US)+"\n"+path+"\n"+ts+"\n"+nonce+"\n"+salt+"\n"+bodyHash+"\n"+(tk==null?"":tk); Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(sha256Bytes((secret+":"+salt).getBytes("UTF-8")), "HmacSHA256")); return hex(mac.doFinal(raw.getBytes("UTF-8"))); }
        byte[] randomBytes(int n){ byte[] b=new byte[n]; rnd.nextBytes(b); return b; }
        static byte[] sha256Bytes(byte[] b) throws Exception { MessageDigest md=MessageDigest.getInstance("SHA-256"); return md.digest(b); }
        static String sha256Hex(byte[] b) throws Exception { return hex(sha256Bytes(b)); }
        static String hex(byte[] b){ char[] h="0123456789abcdef".toCharArray(); char[] out=new char[b.length*2]; for(int i=0;i<b.length;i++){ int v=b[i]&255; out[i*2]=h[v>>>4]; out[i*2+1]=h[v&15]; } return new String(out); }
        static String read(InputStream in) throws Exception { if(in==null) return ""; byte[] b=readBytes(in); return new String(b, "UTF-8"); }
        static byte[] readBytes(InputStream in) throws Exception { ByteArrayOutputStream baos=new ByteArrayOutputStream(); byte[] buf=new byte[8192]; int n; while((n=in.read(buf))>0) baos.write(buf,0,n); in.close(); return baos.toByteArray(); }
        static String errorText(String text, int code) {
            String raw = text == null ? "" : text;
            try {
                JSONObject o = new JSONObject(raw);
                String detail = o.optString("detail", raw);
                String low = (detail + " " + raw).toLowerCase(Locale.US);
                if (low.contains("修改失败") || low.contains("immutable")
                        || low.contains("cannot be deleted")
                        || low.contains("protected subscription")
                        || low.contains("xbhostroot")) return "修改失败";
                return "HTTP " + code + "：" + detail;
            } catch(Exception e) {
                String low = raw.toLowerCase(Locale.US);
                if (low.contains("修改失败") || low.contains("immutable")
                        || low.contains("cannot be deleted")
                        || low.contains("protected subscription")
                        || low.contains("xbhostroot")) return "修改失败";
                return "HTTP " + code + "：" + raw;
            }
        }
    }
    static class AuthException extends Exception {
        AuthException(String msg) { super(msg == null || msg.length() == 0 ? "登录已失效，请重新登录" : msg); }
    }
    static class Enc { String data; String iv; }
}
