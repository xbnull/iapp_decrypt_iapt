package com.iapt.client.hook;

import android.app.Application;
import android.app.Instrumentation;
import android.content.ContentValues;
import android.content.Intent;
import android.content.Context;
import android.content.ComponentName;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import org.json.JSONArray;
import java.io.File;
import java.io.FileOutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Map;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class IaptHookEntry implements IXposedHookLoadPackage {

    // 原生获取当前 Application Context 的方法，完美替代 AndroidAppHelper
    private static android.app.Application getCurrentApplication() {
        try {
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            java.lang.reflect.Method method = activityThreadClass.getMethod("currentApplication");
            return (android.app.Application) method.invoke(null);
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    static final String SELF = "com.iapt.client";
    static final String TARGET_CLASS = "com.iapp.app.f";
    static final String TARGET_METHOD = "b";
    static final Uri URI = Uri.parse("content://com.iapt.client.hook/events");
    static final Uri DUMP_URI = Uri.parse("content://com.iapt.client.hook/dump");
    static final String DUMP_ROOT = "/sdcard/iApt/dump/";
    static final int MAX_DUMP_CHARS = 240000;

    static final HashSet<String> HOOKED = new HashSet<String>();
    static final HashSet<String> DYNAMIC_HOOKED = new HashSet<String>();
    static final HashSet<String> WRITTEN_HASH = new HashSet<String>();
    static final HashSet<String> FB_DEXKEY_REPORTED = new HashSet<String>();
    static final HashSet<String> FUNC_HOOKED = new HashSet<String>();
    static final HashSet<String> FUNC_RULE_REPORTED = new HashSet<String>();
    static final HashMap<String, Class> FUNC_AID_CLASS_CACHE = new HashMap<String, Class>();
    static final HashMap<String, Class> OBSERVED_IAPP_CLASSES = new HashMap<String, Class>();
    static final HashMap<String, String> DYNAMIC_FILE_HASH = new HashMap<String, String>();
    static final HashMap<String, PageBuf> PAGES = new HashMap<String, PageBuf>();
    static boolean APP_LIFECYCLE_HOOKED = false;
    static boolean APP_ATTACH_HOOKED = false;
    static boolean APP_READY_DONE = false;
    static boolean LOADCLASS_HOOKED = false;
    static boolean FINDCLASS_HOOKED = false;
    static boolean CLASS_WATCH_DIAG_REPORTED = false;
    static boolean DELAYED_FUNC_HOOK_SCHEDULED = false;
    static boolean CONTEXT_PROBE_STARTED = false;
    static boolean CONFIG_DIAG_REPORTED = false;
    static boolean INSTALL_DIAG_REPORTED = false;
    static Context APP_CONTEXT;
    static String CURRENT_UI_FILE;
    static String CURRENT_EVENT_FILE;
    static String CURRENT_SCRIPT_FILE;
    static long CONFIG_LAST_MS = 0L;
    static boolean FB_ENABLED = false;
    static boolean DYNAMIC_ENABLED = false;
    static boolean FUNC_ENABLED = false;
    static String FUNC_RULES_RAW = "";
    static final ArrayList FUNC_RULES = new ArrayList();

    static final String[] DYNAMIC_CLASSES = new String[]{
        "bsh.Interpreter",
        "com.iapp.app.e",
        "com.iapp.app.b",
        "com.b.a.a.h",
        "com.iapp.app.run.mian",
        "com.iapp.app.run.main",
        "com.iapp.app.run.main2",
        "com.iapp.app.run.main3",
        "c.b.a.a.p",
        "c.b.a.a.P",
        // 1.3.1：部分 V3/动态加密项目不会走 c.b.a.a.p / com.b.a.a.h，
        // 而是直接在 Aid_YuCode/Aid_YuCodeX 中提取并执行事件。
        "com.h.y.tool.Aid_YuCode",
        "com.iapp.app.Aid_YuCodeX"
    };

    // v197：iApp V3 内置函数宿主类。
    // 只在函数控制已开启且有对应规则时，由 ClassLoader.loadClass 命中后精确 Hook；
    // 不主动 loadClass，不扫描全包，避免关闭函数控制时仍影响目标启动。
    static final String[] FUNC_RUNTIME_CLASSES = new String[]{
        "com.iapp.app.Aid_YuCodeX",
        "com.iapp.app.Aid_javaCode",
        "com.iapp.app.Aid_jsCode",
        "com.iapp.app.Aid_luaCode"
    };

    // v210：按样本确认的“代码传入执行器”入口。
    // 不主动加载这些类；只在目标进程自己 loadClass 成功后，按规则精确 Hook String 代码参数。
    static final String[] IAPP_CODE_EXECUTOR_CLASSES = new String[]{
        "c.b.a.a.t",          // V3/Yu 逐行解释入口：f/e(String)，部分版本类名可能变成 w/v，不能只依赖它
        "com.iapp.app.d"      // Lua/脚本入口：g/h/i(String)
    };

    // v211：真正更稳的事件代码提取入口。V3 样本中 run.mian.s/t、菜单、ActivityResult
    // 都会通过 c.b.a.a.p.c(full, startTag, endTag) 从 <eventItme> 中取出代码。
    // 在这里改返回值，就不需要知道后面是 t/w/v 解释器，还是 goUIEventset 反射事件类。
    static final String IAPP_EVENT_EXTRACTOR_CLASS = "c.b.a.a.p";

    static class PageBuf {
        String file;
        String ui = "";
        String loading = "";
        String event = "";
        String script = "";
        PageBuf(String f) { file = f; }
    }

    static class ViewNode {
        String id;
        String did;
        String block;
        int order;
        ViewNode(String i, String d, String b, int o) { id = i; did = d; block = b; order = o; }
    }

    static class FuncRule {
        String mode;
        String cls;
        String method;
        String value;
        String toCls;
        String toMethod;
        String raw;
    }

    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || lpparam.packageName == null) return;
        if (SELF.equals(lpparam.packageName)) return;

        // This line is written directly to LSPosed's framework log before any target
        // Application/Provider/Receiver is involved. It is the authoritative signal
        // that the framework actually invoked this module entry.
        log("handleLoadPackage package=" + lpparam.packageName + " process=" + lpparam.processName
                + " first=" + lpparam.isFirstApplication + " cl=" + lpparam.classLoader);

        // Install lightweight class-resolution watchers before Application.attach.
        // Configuration is not available yet, so resolved iApp classes are only cached;
        // after the Bootstrap supplies a Context, the cached classes are hooked. This
        // prevents missing classes loaded during a custom Application startup.
        hookClassLoaderLoadClass(lpparam);
        hookBaseDexFindClass(lpparam);

        // At this point the target process does not yet have a Context. Do not make
        // functional Hook installation depend on configuration here. The Bootstrap
        // passes the real target Context after Application.attach, then configuration is
        // read authoritatively from the module provider.
        refreshConfig(lpparam.packageName);
        installConfiguredHooks(lpparam, lpparam.classLoader, "handleLoadPackage");

        hookApplicationLifecycle(lpparam);
        scheduleContextProbe(lpparam);
    }

    /** Called directly by the small Bootstrap after Application.attach. */
    public void onBootstrapAttach(final XC_LoadPackage.LoadPackageParam lpparam, Context context, String stage) {
        try {
            if (lpparam == null || context == null) return;
            Context app = context.getApplicationContext();
            APP_CONTEXT = app != null ? app : context;
            CONFIG_LAST_MS = 0L;
            refreshConfig(lpparam.packageName);
            if (!CONFIG_DIAG_REPORTED) {
                CONFIG_DIAG_REPORTED = true;
                reportStatus(lpparam.packageName, "配置已读取",
                        "source=provider; fb=" + FB_ENABLED
                        + "; dynamic=" + DYNAMIC_ENABLED
                        + "; func=" + FUNC_ENABLED
                        + "; rules=" + copyFuncRules().size());
            }
            installConfiguredHooks(lpparam,
                    APP_CONTEXT.getClassLoader() != null ? APP_CONTEXT.getClassLoader() : lpparam.classLoader,
                    "bootstrap." + String.valueOf(stage));
        } catch (Throwable e) {
            log("onBootstrapAttach failed: " + e);
            try { reportStatus(lpparam == null ? "" : lpparam.packageName,
                    "业务入口连接失败", String.valueOf(e)); } catch (Throwable ignored) {}
        }
    }

    static void installConfiguredHooks(final XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl, String from) {
        try {
            if (lpparam == null || cl == null) {
                log("install hooks skipped without classloader from=" + from);
                return;
            }
            refreshConfig(lpparam.packageName);
            boolean fb = FB_ENABLED;
            boolean dyn = DYNAMIC_ENABLED;
            boolean func = hasAnyIappFuncRules(lpparam.packageName);
            int ruleCount = copyFuncRules().size();
            log("install hooks from=" + from + " pkg=" + lpparam.packageName
                    + " fb=" + fb + " dynamic=" + dyn + " func=" + func
                    + " rules=" + ruleCount);
            if (!fb && !dyn && !func) {
                if (APP_CONTEXT != null && !INSTALL_DIAG_REPORTED) {
                    INSTALL_DIAG_REPORTED = true;
                    reportStatus(lpparam.packageName, "Hook未安装",
                            "开关均为关闭或函数规则为空; fb=" + fb
                            + "; dynamic=" + dyn + "; func=" + func
                            + "; rules=" + ruleCount);
                }
                return;
            }
            if (fb) tryHookNow(lpparam.packageName, cl, from + ".fb");
            if (dyn || func) {
                hookClassLoaderLoadClass(lpparam);
                hookBaseDexFindClass(lpparam);
                // Function control also needs the same iApp runtime entry points used by
                // dynamic extraction. V11 only resolved them when dynamic dump was on,
                // leaving function-only rules permanently waiting for c.b.a.a.p.c.
                tryHookDynamicNow(lpparam.packageName, cl, from + ".runtime");
                forceResolveKnownIappClasses(lpparam.packageName, cl, from + ".resolve");
                hookObservedIappClasses(lpparam.packageName, from + ".observed");
            }
            if (func) {
                tryHookFuncNow(lpparam.packageName, cl, from + ".rules");
                cacheAlreadyLoadedAidClasses(cl, from + ".cache");
                hookCachedAidClasses(lpparam.packageName, from + ".cache");
            }
            if (dyn || func) hookAlreadyLoadedIappEventExtractor(
                    lpparam.packageName, cl, from + ".dynamicFunc");
            if (func) scheduleDelayedIappFuncHook(lpparam.packageName, cl, from + ".func");
            if (APP_CONTEXT != null && !INSTALL_DIAG_REPORTED) {
                INSTALL_DIAG_REPORTED = true;
                reportStatus(lpparam.packageName, "Hook安装已执行",
                        "from=" + from + "; fb=" + fb + "; dynamic=" + dyn
                        + "; func=" + func + "; rules=" + ruleCount);
            }
        } catch (Throwable e) {
            log("installConfiguredHooks failed from=" + from + ": " + e);
        }
    }

    static void scheduleContextProbe(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (CONTEXT_PROBE_STARTED) return;
            CONTEXT_PROBE_STARTED = true;
            final Handler h = new Handler(Looper.getMainLooper());
            h.post(new Runnable() {
                int attempt = 0;
                public void run() {
                    try {
                        Application app = getCurrentApplication();
                        if (app != null) {
                            log("context probe ready attempt=" + attempt + " pkg=" + lpparam.packageName);
                            onApplicationReady(lpparam, app);
                            return;
                        }
                        attempt++;
                        if (attempt < 40) h.postDelayed(this, 250L);
                        else log("context probe timeout pkg=" + lpparam.packageName);
                    } catch (Throwable e) {
                        log("context probe failed: " + e);
                    }
                }
            });
        } catch (Throwable e) {
            CONTEXT_PROBE_STARTED = false;
            log("schedule context probe failed: " + e);
        }
    }

    static void hookApplicationLifecycle(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (!APP_LIFECYCLE_HOOKED) {
            try {
                APP_LIFECYCLE_HOOKED = true;
                Method callback = Instrumentation.class.getMethod("callApplicationOnCreate", Application.class);
                XposedBridge.hookMethod(callback, new XC_MethodHook() {
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            Application app = null;
                            if (param != null && param.args != null && param.args.length > 0
                                    && param.args[0] instanceof Application) {
                                app = (Application)param.args[0];
                            }
                            if (app == null) app = getCurrentApplication();
                            onApplicationReady(lpparam, app);
                        } catch (Throwable e) {
                            log("application lifecycle callback failed: " + e);
                        }
                    }
                });
                log("hooked Instrumentation.callApplicationOnCreate");
            } catch (Throwable e) {
                APP_LIFECYCLE_HOOKED = false;
                log("hook Instrumentation.callApplicationOnCreate failed: " + e);
            }
        }
        // Also install the traditional attach hook. Some apps use a custom
        // Instrumentation override that does not invoke the framework base method.
        hookApplicationAttachFallback(lpparam);
    }

    static void hookApplicationAttachFallback(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (APP_ATTACH_HOOKED) return;
            APP_ATTACH_HOOKED = true;
            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            XposedBridge.hookMethod(attach, new XC_MethodHook() {
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Application app = getCurrentApplication();
                        if (app == null && param != null && param.thisObject instanceof Application) {
                            app = (Application)param.thisObject;
                        }
                        onApplicationReady(lpparam, app);
                    } catch (Throwable e) {
                        log("Application.attach fallback failed: " + e);
                    }
                }
            });
            log("hooked Application.attach fallback");
        } catch (Throwable e) {
            APP_ATTACH_HOOKED = false;
            log("hook Application.attach fallback failed: " + e);
        }
    }

    static void onApplicationReady(final XC_LoadPackage.LoadPackageParam lpparam, Application app) {
        try {
            if (app != null) APP_CONTEXT = app.getApplicationContext();
            if (APP_CONTEXT == null && app != null) APP_CONTEXT = app;
            if (APP_CONTEXT == null) APP_CONTEXT = getCurrentApplication();
            if (APP_CONTEXT == null) {
                log("application ready without context pkg=" + lpparam.packageName);
                return;
            }
            if (APP_READY_DONE) return;

            refreshConfig(lpparam.packageName);
            ClassLoader cl = APP_CONTEXT.getClassLoader();
            if (cl == null) cl = lpparam.classLoader;
            APP_READY_DONE = true;

            // Send the UI status through an explicit broadcast first. Provider access
            // is retained only as a secondary transport because package visibility and
            // vendor background rules can reject cross-package provider acquisition.
            reportStatus(lpparam.packageName, "模块已加载", "application_ready");
            installConfiguredHooks(lpparam, cl, "application_ready");
        } catch (Throwable e) {
            log("onApplicationReady failed: " + e);
        }
    }

    static void hookClassLoaderLoadClass(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (LOADCLASS_HOOKED) {
                reportClassWatchStatus(lpparam.packageName, "loadClass=ready; findClass=" + FINDCLASS_HOOKED);
                return;
            }
            LOADCLASS_HOOKED = true;
            Method[] ms = ClassLoader.class.getDeclaredMethods();
            int n = 0;
            for (int i=0;i<ms.length;i++) {
                final Method load = ms[i];
                if (!"loadClass".equals(load.getName())) continue;
                try { load.setAccessible(true); } catch(Throwable ignored) {}
                try {
                    XposedBridge.hookMethod(load, new XC_MethodHook() {
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                if (param == null || param.args == null || param.args.length == 0) return;
                                String name = String.valueOf(param.args[0]);
                                Object r = param.getResult();
                                if (!(r instanceof Class)) return;
                                Class<?> c = (Class<?>)r;
                                onResolvedClass(lpparam.packageName, c, "ClassLoader.loadClass");
                            } catch(Throwable e) { log("loadClass after error: " + e); }
                        }
                    });
                    n++;
                } catch(Throwable e) { log("hook one loadClass failed: " + e); }
            }
            log("hooked ClassLoader.loadClass count=" + n);
            reportClassWatchStatus(lpparam.packageName, "loadClass=" + n);
        } catch(Throwable e) { log("hook ClassLoader.loadClass failed: " + e); }
    }


    static void hookBaseDexFindClass(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (FINDCLASS_HOOKED) {
                reportClassWatchStatus(lpparam.packageName, "loadClass=" + LOADCLASS_HOOKED + "; findClass=ready");
                return;
            }
            FINDCLASS_HOOKED = true;
            Class<?> base = Class.forName("dalvik.system.BaseDexClassLoader");
            Method[] ms = base.getDeclaredMethods();
            int n = 0;
            for (int i = 0; i < ms.length; i++) {
                final Method m = ms[i];
                if (!"findClass".equals(m.getName())) continue;
                if (m.getReturnType() != Class.class) continue;
                try { m.setAccessible(true); } catch (Throwable ignored) {}
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                Object r = param == null ? null : param.getResult();
                                if (r instanceof Class) {
                                    onResolvedClass(lpparam.packageName, (Class<?>) r,
                                            "BaseDexClassLoader.findClass");
                                }
                            } catch (Throwable e) { log("findClass after error: " + e); }
                        }
                    });
                    n++;
                } catch (Throwable e) { log("hook one findClass failed: " + e); }
            }
            log("hooked BaseDexClassLoader.findClass count=" + n);
            reportClassWatchStatus(lpparam.packageName, "findClass=" + n);
        } catch (Throwable e) {
            FINDCLASS_HOOKED = false;
            log("hook BaseDexClassLoader.findClass failed: " + e);
        }
    }

    static void reportClassWatchStatus(String pkg, String detail) {
        try {
            if (APP_CONTEXT == null || CLASS_WATCH_DIAG_REPORTED) return;
            CLASS_WATCH_DIAG_REPORTED = true;
            reportStatus(pkg, "类加载监听已安装", detail);
        } catch (Throwable ignored) {}
    }

    static boolean isPotentialIappClassName(String name) {
        try {
            if (name == null) return false;
            if (TARGET_CLASS.equals(name) || IAPP_EVENT_EXTRACTOR_CLASS.equals(name)) return true;
            if (isDynamicClassName(name) || isIappCodeExecutorClassName(name)
                    || isIappAidRuntimeClassName(name)) return true;
            return name.startsWith("c.b.a.a.") || name.startsWith("com.iapp.app.")
                    || name.startsWith("com.h.y.tool.") || "bsh.Interpreter".equals(name);
        } catch (Throwable e) { return false; }
    }

    static void rememberObservedIappClass(Class<?> c) {
        try {
            if (c == null || !isPotentialIappClassName(c.getName())) return;
            synchronized (OBSERVED_IAPP_CLASSES) {
                OBSERVED_IAPP_CLASSES.put(c.getName(), c);
            }
        } catch (Throwable ignored) {}
    }

    static void onResolvedClass(String pkg, Class<?> c, String from) {
        try {
            if (c == null) return;
            String name = c.getName();
            if (!isPotentialIappClassName(name) && !isFuncRuleClass(pkg, name)) return;
            rememberObservedIappClass(c);

            if (TARGET_CLASS.equals(name) && isFbEnabled(pkg)) hookClass(pkg, c, from);
            if (isRuntimeScriptControlEnabled(pkg) && isDynamicClassName(name)) {
                hookDynamicClass(pkg, c, from);
            }
            if (hasDynamicOrIappFuncRules(pkg) && isIappEventExtractorCandidate(c)) {
                hookIappEventExtractorClass(pkg, c, from + ".eventExtractor");
            }
            if (hasAnyIappFuncRules(pkg) && isIappCodeExecutorClassName(name)) {
                hookIappCodeExecutorClass(pkg, c, from + ".executor");
            }
            if (isFuncRuleClass(pkg, name)) hookFuncClass(pkg, c, from + ".rule");
            if (isIappAidRuntimeClassName(name)) {
                cacheIappAidRuntimeClass(c);
                if (hasIappRuntimeFuncRules(pkg)) hookFuncClass(pkg, c, from + ".Aid");
            }
        } catch (Throwable e) { log("onResolvedClass failed: " + e); }
    }

    static void hookObservedIappClasses(String pkg, String from) {
        try {
            ArrayList classes = new ArrayList();
            synchronized (OBSERVED_IAPP_CLASSES) {
                classes.addAll(OBSERVED_IAPP_CLASSES.values());
            }
            int n = 0;
            for (int i = 0; i < classes.size(); i++) {
                Object o = classes.get(i);
                if (o instanceof Class) {
                    onResolvedClass(pkg, (Class<?>) o, from);
                    n++;
                }
            }
            if (n > 0) reportStatus(pkg, "已处理早期加载类", "iApp候选类=" + n);
        } catch (Throwable e) { log("hook observed classes failed: " + e); }
    }

    static void forceResolveKnownIappClasses(String pkg, ClassLoader cl, String from) {
        try {
            if (cl == null) return;
            ArrayList names = new ArrayList();
            for (int i = 0; i < DYNAMIC_CLASSES.length; i++) names.add(DYNAMIC_CLASSES[i]);
            for (int i = 0; i < FUNC_RUNTIME_CLASSES.length; i++) names.add(FUNC_RUNTIME_CLASSES[i]);
            for (int i = 0; i < IAPP_CODE_EXECUTOR_CLASSES.length; i++) names.add(IAPP_CODE_EXECUTOR_CLASSES[i]);
            names.add(IAPP_EVENT_EXTRACTOR_CLASS);
            names.add("c.b.a.a.P");
            ArrayList rules = copyFuncRules();
            for (int i = 0; i < rules.size(); i++) {
                FuncRule r = (FuncRule) rules.get(i);
                if (r != null && r.cls != null && r.cls.trim().length() > 0) names.add(r.cls.trim());
            }
            HashSet seen = new HashSet();
            int found = 0;
            StringBuilder hit = new StringBuilder();
            for (int i = 0; i < names.size(); i++) {
                String name = String.valueOf(names.get(i));
                if (name.length() == 0 || seen.contains(name)) continue;
                seen.add(name);
                try {
                    Class<?> c = Class.forName(name, false, cl);
                    if (c != null) {
                        found++;
                        if (hit.length() < 500) {
                            if (hit.length() > 0) hit.append(',');
                            hit.append(c.getName());
                        }
                        onResolvedClass(pkg, c, from);
                    }
                } catch (Throwable ignored) {}
            }
            reportStatus(pkg, "主动解析运行类", "found=" + found + "; " + hit.toString());
        } catch (Throwable e) { log("force resolve classes failed: " + e); }
    }

    static boolean isIappEventExtractorCandidate(Class<?> cls) {
        try {
            if (cls == null) return false;
            String name = cls.getName();
            if (IAPP_EVENT_EXTRACTOR_CLASS.equals(name) || "c.b.a.a.P".equals(name)) return true;
            if (name == null || !name.startsWith("c.b.a.a.")) return false;
            Method[] ms = cls.getDeclaredMethods();
            for (int i = 0; i < ms.length; i++) {
                if (shouldHookIappEventExtractorMethod(cls, ms[i])) return true;
            }
        } catch (Throwable ignored) {}
        return false;
    }

    static boolean isDynamicClassName(String name) {
        if (name == null) return false;
        for (int i=0;i<DYNAMIC_CLASSES.length;i++) if (DYNAMIC_CLASSES[i].equals(name)) return true;
        return false;
    }

    static boolean isIappAidRuntimeClassName(String name) {
        try {
            if (name == null) return false;
            for (int i=0;i<FUNC_RUNTIME_CLASSES.length;i++) if (FUNC_RUNTIME_CLASSES[i].equals(name)) return true;
            return false;
        } catch(Throwable e) { return false; }
    }

    static boolean isIappCodeExecutorClassName(String name) {
        try {
            if (name == null) return false;
            for (int i=0;i<IAPP_CODE_EXECUTOR_CLASSES.length;i++) if (IAPP_CODE_EXECUTOR_CLASSES[i].equals(name)) return true;
            return false;
        } catch(Throwable e) { return false; }
    }

    static boolean hasAnyIappFuncRules(String pkg) {
        try {
            if (!isFuncEnabled(pkg)) return false;
            return copyFuncRules().size() > 0;
        } catch(Throwable ignored) {}
        return false;
    }

    static boolean hasDynamicOrIappFuncRules(String pkg) {
        try {
            if (shouldDumpDynamic(pkg)) return true;
            return hasAnyIappFuncRules(pkg);
        } catch(Throwable ignored) {}
        return false;
    }

    static boolean isIappAidRuntimeRuleClassToken(String token) {
        try {
            if (token == null) return false;
            String x = token.trim();
            if (x.length() == 0) return false;
            if (isIappAidRuntimeClassName(x)) return true;
            return "Aid_YuCodeX".equals(x) || "Aid_javaCode".equals(x)
                    || "Aid_jsCode".equals(x) || "Aid_luaCode".equals(x);
        } catch(Throwable e) { return false; }
    }


    static void cacheIappAidRuntimeClass(Class c) {
        try {
            if (c == null) return;
            String n = c.getName();
            if (!isIappAidRuntimeClassName(n)) return;
            synchronized (FUNC_AID_CLASS_CACHE) { FUNC_AID_CLASS_CACHE.put(n, c); }
        } catch(Throwable ignored) {}
    }

    static void cacheAlreadyLoadedAidClasses(ClassLoader cl, String from) {
        try {
            if (cl == null) return;
            Method fm = ClassLoader.class.getDeclaredMethod("findLoadedClass", String.class);
            try { fm.setAccessible(true); } catch(Throwable ignored) {}
            int count = 0;
            for (int i=0;i<FUNC_RUNTIME_CLASSES.length;i++) {
                try {
                    Object r = fm.invoke(cl, FUNC_RUNTIME_CLASSES[i]);
                    if (r instanceof Class) { cacheIappAidRuntimeClass((Class)r); count++; }
                } catch(Throwable ignored) {}
            }
            if (count > 0) log("cached loaded Aid class x=" + count + " from=" + from);
        } catch(Throwable e) { log("cache loaded Aid failed: " + e); }
    }

    static void hookCachedAidClasses(String pkg, String from) {
        try {
            if (!hasIappRuntimeFuncRules(pkg)) return;
            ArrayList cs = new ArrayList();
            synchronized (FUNC_AID_CLASS_CACHE) { cs.addAll(FUNC_AID_CLASS_CACHE.values()); }
            int count = 0;
            for (int i=0;i<cs.size();i++) {
                Object o = cs.get(i);
                if (o instanceof Class) { hookFuncClass(pkg, (Class)o, from); count++; }
            }
            if (count > 0) reportStatus(pkg, "函数控制缓存Hook", "Aid x" + count);
            else reportStatus(pkg, "函数控制未命中", "未缓存Aid类");
        } catch(Throwable e) { log("hook cached Aid failed: " + e); }
    }

    static boolean hasIappRuntimeFuncRules(String pkg) {
        try {
            if (!isFuncEnabled(pkg)) return false;
            ArrayList rules = copyFuncRules();
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (isIappRuntimeRule(r)) return true;
            }
        } catch(Throwable ignored) {}
        return false;
    }

    static boolean isIappRuntimeRule(FuncRule r) {
        try {
            if (r == null || r.method == null || r.method.length() == 0) return false;
            if (isAuxTextRule(r)) return false;
            if (r.cls == null || r.cls.length() == 0) return true;
            return isIappAidRuntimeRuleClassToken(r.cls);
        } catch(Throwable ignored) {}
        return false;
    }

    static boolean iappRuntimeClassRuleMatches(String actualClass, String ruleClass) {
        try {
            if (ruleClass == null || ruleClass.trim().length() == 0) return true;
            if (actualClass == null || actualClass.length() == 0) return true;
            String r = ruleClass.trim();
            if (actualClass.equals(r)) return true;
            int p = actualClass.lastIndexOf('.');
            String simple = p >= 0 ? actualClass.substring(p + 1) : actualClass;
            return simple.equals(r);
        } catch(Throwable e) { return false; }
    }


    // V12：函数控制不能只被动等待类自然加载。使用 Class.forName(..., false, cl)
    // 只解析、不初始化候选类，并在 0.5s/2s/5s 三次补挂，兼容二次 DEX 加载。
    static void scheduleDelayedIappFuncHook(final String pkg, final ClassLoader cl, final String from) {
        try {
            if (cl == null) return;
            if (DELAYED_FUNC_HOOK_SCHEDULED) return;
            if (!hasAnyIappFuncRules(pkg)) return;
            DELAYED_FUNC_HOOK_SCHEDULED = true;
            final Handler h = new Handler(Looper.getMainLooper());
            final long[] delays = new long[]{500L, 2000L, 5000L};
            for (int i = 0; i < delays.length; i++) {
                final int attempt = i + 1;
                h.postDelayed(new Runnable() {
                    public void run() {
                        try {
                            refreshConfig(pkg);
                            forceResolveKnownIappClasses(pkg, cl, from + ".retry" + attempt);
                            hookObservedIappClasses(pkg, from + ".retry" + attempt);
                            tryHookFuncNow(pkg, cl, from + ".retry" + attempt);
                            if (hasIappRuntimeFuncRules(pkg)) {
                                cacheAlreadyLoadedAidClasses(cl, from + ".retry" + attempt);
                                hookCachedAidClasses(pkg, from + ".retry" + attempt);
                            }
                        } catch(Throwable e) { log("func delayed hook failed: " + e); }
                    }
                }, delays[i]);
            }
            log("scheduled active func hook from=" + from);
        } catch(Throwable e) { log("schedule active func hook failed: " + e); }
    }

    static void tryHookNow(String pkg, ClassLoader cl, String from) {
        try {
            if (cl == null) return;
            Class<?> cls = cl.loadClass(TARGET_CLASS);
            hookClass(pkg, cls, from);
        } catch(Throwable e) { log("target not ready from=" + from + " err=" + e.getClass().getName()); }
    }

    static void tryHookDynamicNow(String pkg, ClassLoader cl, String from) {
        if (cl == null) return;
        for (int i=0;i<DYNAMIC_CLASSES.length;i++) {
            try { hookDynamicClass(pkg, cl.loadClass(DYNAMIC_CLASSES[i]), from); }
            catch(Throwable ignored) {}
        }
    }


    static void tryHookFuncNow(String pkg, ClassLoader cl, String from) {
        try {
            if (cl == null) return;
            if (!isFuncEnabled(pkg)) return;
            ArrayList rules = copyFuncRules();
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r.cls != null && r.cls.length() > 0) { try { hookFuncClass(pkg, cl.loadClass(r.cls), from); } catch(Throwable ignored) {} }
            }
        } catch(Throwable e) { log("tryHookFuncNow failed: " + e); }
    }

    static boolean isFuncRuleClass(String pkg, String name) {
        try {
            if (name == null) return false;
            if (!isFuncEnabled(pkg)) return false;
            ArrayList rules = copyFuncRules();
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r.cls != null && r.cls.length() > 0 && name.equals(r.cls)) return true;
            }
        } catch(Throwable ignored) {}
        return false;
    }


    static void hookAlreadyLoadedIappEventExtractor(String pkg, ClassLoader cl, String from) {
        try {
            if (cl == null) return;
            if (!hasDynamicOrIappFuncRules(pkg)) return;
            Method fm = ClassLoader.class.getDeclaredMethod("findLoadedClass", String.class);
            try { fm.setAccessible(true); } catch(Throwable ignored) {}
            Object r = fm.invoke(cl, IAPP_EVENT_EXTRACTOR_CLASS);
            if (!(r instanceof Class)) {
                try { r = fm.invoke(cl, "c.b.a.a.P"); } catch (Throwable ignored) {}
            }
            if (r instanceof Class) hookIappEventExtractorClass(pkg, (Class)r, from + ".loaded");
            else {
                forceResolveKnownIappClasses(pkg, cl, from + ".force");
                reportStatus(pkg, "函数控制正在解析入口", "已启用主动解析和双层类加载监听");
            }
        } catch(Throwable e) { log("hook loaded event extractor failed: " + e); }
    }

    static void hookIappEventExtractorClass(final String pkg, final Class<?> cls, String from) {
        try {
            if (cls == null) return;
            if (!isIappEventExtractorCandidate(cls)) return;
            if (!hasDynamicOrIappFuncRules(pkg)) return;
            Method[] ms;
            try { ms = cls.getDeclaredMethods(); } catch(Throwable e) { return; }
            int count = 0;
            for (int i=0;i<ms.length;i++) {
                final Method m = ms[i];
                if (!shouldHookIappEventExtractorMethod(cls, m)) continue;
                final String sig = methodSig(m);
                synchronized (FUNC_HOOKED) {
                    String key = "EVENT_EXTRACT|" + sig;
                    if (FUNC_HOOKED.contains(key)) continue;
                    FUNC_HOOKED.add(key);
                }
                try { m.setAccessible(true); } catch(Throwable ignored) {}
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                if (!hasDynamicOrIappFuncRules(pkg)) return;
                                if (param == null || param.args == null || param.args.length < 3) return;
                                Object result = param.getResult();
                                if (!(result instanceof String) && !(result instanceof CharSequence)) return;
                                String full = param.args[0] == null ? null : String.valueOf(param.args[0]);
                                String start = param.args[1] == null ? null : String.valueOf(param.args[1]);
                                String end = param.args[2] == null ? null : String.valueOf(param.args[2]);
                                String old = String.valueOf(result);
                                if (!isIappEventCodeExtract(start, end, old, full)) return;
                                String file = CURRENT_EVENT_FILE == null ? (CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE) : CURRENT_EVENT_FILE;
                                boolean dump = shouldDumpDynamic(pkg);
                                boolean func = isFuncEnabled(pkg);
                                String fixed = func ? applyIappFuncRulesForExecutor(pkg, file, old) : old;
                                if (func && fixed != null && !fixed.equals(old)) {
                                    param.setResult(fixed);
                                    reportFunc(pkg, "事件代码提取", sig, "成功：已修改");
                                } else if (func) {
                                    reportFuncSample(pkg, "事件代码提取", sig, "成功：未命中");
                                }
                                if (dump && fixed != null && fixed.length() > 0) {
                                    appendPagePart(pkg, sig, file, "event", fixed);
                                    reportStatus(pkg, "动态解密", "成功");
                                }
                            } catch(Throwable e) { log("event extractor after failed " + sig + " err=" + e); }
                        }
                    });
                    count++;
                    log("hooked iApp event extractor " + sig + " from=" + from);
                } catch(Throwable e) { log("hook event extractor failed " + sig + " err=" + e); }
            }
            if (count > 0) reportStatus(pkg, "函数控制事件入口已Hook", cls.getName() + " x" + count);
        } catch(Throwable e) { log("hookIappEventExtractorClass failed: " + e); }
    }

    static boolean shouldHookIappEventExtractorMethod(Class<?> cls, Method m) {
        try {
            if (m == null || cls == null) return false;
            if (shouldSkipHookMethod(m)) return false;
            String cn = cls.getName();
            String mn = m.getName();
            if (m.getReturnType() != String.class && m.getReturnType() != CharSequence.class) return false;
            Class[] ps = m.getParameterTypes();
            if (ps == null || ps.length != 3) return false;
            if (!(ps[0] == String.class && ps[1] == String.class && ps[2] == String.class)) return false;
            if (IAPP_EVENT_EXTRACTOR_CLASS.equals(cn)) return "c".equals(mn);
            // Newer/obfuscated iApp runtimes may rename p/P and its short method.
            // The callback still validates event tags before changing a result.
            return cn != null && cn.startsWith("c.b.a.a.") && mn != null && mn.length() <= 2;
        } catch(Throwable e) { return false; }
    }

    static boolean isIappEventCodeExtract(String start, String end, String code, String full) {
        try {
            if (code == null || code.length() == 0) return false;
            boolean tag = false;
            if (start != null && start.indexOf("<eventItme") >= 0) tag = true;
            if (end != null && end.indexOf("</eventItme>") >= 0) tag = true;
            if (!tag && full != null && full.indexOf("<eventItme") >= 0 && full.indexOf(code) >= 0) tag = true;
            if (!tag) return false;
            String t = code.trim();
            if (t.length() == 0) return false;
            // iApp 事件代码通常以 [true] 标记，或直接包含函数调用/语句。
            if (t.startsWith("[true]")) return true;
            if (looksLikeIappRuntimeCode(t)) return true;
            // 有些事件只是变量/条件/简短语句，仍然应该放过但记录少量样本，避免误伤普通 UI 属性。
            return t.indexOf('(') >= 0 || t.indexOf('=') >= 0 || t.indexOf(';') >= 0 || t.indexOf('\n') >= 0;
        } catch(Throwable e) { return false; }
    }

    static void reportFuncSample(String pkg, String mode, String sig, String detail) {
        try {
            String key = "SAMPLE|" + mode + "|" + sig + "|" + detail;
            synchronized (FUNC_RULE_REPORTED) {
                if (FUNC_RULE_REPORTED.contains(key)) return;
                if (FUNC_RULE_REPORTED.size() > 200) FUNC_RULE_REPORTED.clear();
                FUNC_RULE_REPORTED.add(key);
            }
            reportFunc(pkg, mode, sig, detail);
        } catch(Throwable ignored) {}
    }

    static void hookIappCodeExecutorClass(final String pkg, final Class<?> cls, String from) {
        try {
            if (cls == null) return;
            if (!hasAnyIappFuncRules(pkg)) return;
            Method[] ms;
            try { ms = cls.getDeclaredMethods(); } catch(Throwable e) { return; }
            int count = 0;
            String cn = cls.getName();
            for (int i=0;i<ms.length;i++) {
                final Method m = ms[i];
                if (!shouldHookIappCodeExecutorMethod(cn, m)) continue;
                final String sig = methodSig(m);
                synchronized (FUNC_HOOKED) {
                    String key = "EXEC|" + sig;
                    if (FUNC_HOOKED.contains(key)) continue;
                    FUNC_HOOKED.add(key);
                }
                try { m.setAccessible(true); } catch(Throwable ignored) {}
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                if (!hasAnyIappFuncRules(pkg)) return;
                                if (param == null || param.args == null || param.args.length == 0) return;
                                for (int ai=0; ai<param.args.length; ai++) {
                                    Object v = param.args[ai];
                                    if (!(v instanceof String) && !(v instanceof CharSequence)) continue;
                                    String old = String.valueOf(v);
                                    if (!looksLikeIappRuntimeCode(old)) continue;
                                    String file = CURRENT_SCRIPT_FILE == null ? (CURRENT_EVENT_FILE == null ? (CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE) : CURRENT_EVENT_FILE) : CURRENT_SCRIPT_FILE;
                                    String fixed = applyIappFuncRulesForExecutor(pkg, file, old);
                                    if (fixed != null && !fixed.equals(old)) {
                                        param.args[ai] = fixed;
                                        reportFunc(pkg, "传入执行器", sig, "成功：已修改");
                                    }
                                }
                            } catch(Throwable e) { log("executor before failed " + sig + " err=" + e); }
                        }
                    });
                    count++;
                    log("hooked iApp executor " + sig + " from=" + from);
                } catch(Throwable e) { log("hook iApp executor failed " + sig + " err=" + e); }
            }
            if (count > 0) reportStatus(pkg, "函数控制执行器已Hook", cls.getName() + " x" + count);
        } catch(Throwable e) { log("hookIappCodeExecutorClass failed: " + e); }
    }

    static boolean shouldHookIappCodeExecutorMethod(String cn, Method m) {
        try {
            if (cn == null || m == null) return false;
            if (shouldSkipHookMethod(m)) return false;
            Class[] ps = m.getParameterTypes();
            if (ps == null || ps.length == 0) return false;
            boolean hasString = false;
            for (int i=0;i<ps.length;i++) if (ps[i] == String.class || ps[i] == CharSequence.class) hasString = true;
            if (!hasString) return false;
            String mn = m.getName();
            // V3/Yu 样本确认：c.b.a.a.t.e(String) 是逐行解释执行入口，包含 tw/uigo 函数派发表。
            if ("c.b.a.a.t".equals(cn) && "e".equals(mn)) return true;
            // Lua/脚本执行入口，传入的是整段脚本或小段脚本。
            if ("com.iapp.app.d".equals(cn) && ("g".equals(mn) || "h".equals(mn) || "i".equals(mn))) return true;
            return false;
        } catch(Throwable e) { return false; }
    }

    static void hookFuncClass(final String pkg, final Class<?> cls, String from) {
        try {
            if (cls == null) return;
            if (!isFuncEnabled(pkg)) return;
            ArrayList rules = copyFuncRules();
            if (rules.size() == 0) return;
            Method[] ms = cls.getDeclaredMethods();
            int count = 0;
            for (int i=0;i<ms.length;i++) {
                final Method m = ms[i];
                if (shouldSkipHookMethod(m)) continue;
                final FuncRule rule = findRuleForMethod(cls.getName(), m.getName(), rules);
                if (rule == null) continue;
                final String sig = methodSig(m);
                synchronized (FUNC_HOOKED) { if (FUNC_HOOKED.contains(sig + "|" + rule.raw)) continue; FUNC_HOOKED.add(sig + "|" + rule.raw); }
                try { m.setAccessible(true); } catch(Throwable ignored) {}
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                if (!isFuncEnabled(pkg)) return;
                                if ("disable".equals(rule.mode)) {
                                    Object ret = parseReturnValue(rule.value, m.getReturnType());
                                    param.setResult(ret);
                                    reportFunc(pkg, "关闭", sig, valueText(ret));
                                } else if ("replace".equals(rule.mode)) {
                                    Object ret;
                                    boolean sameClassRuntime = isIappRuntimeRule(rule) && (rule.toCls == null || rule.toCls.length() == 0 || isIappAidRuntimeRuleClassToken(rule.toCls));
                                    if (sameClassRuntime) ret = invokeSameClassReplacement(pkg, rule, m, param);
                                    else ret = invokeReplacement(pkg, rule, m, param);
                                    if (ret != FUNC_NO_RESULT) {
                                        param.setResult(ret);
                                        reportFunc(pkg, "伪造", sig, rule.method + " => " + rule.toMethod + " " + valueText(ret));
                                    }
                                }
                            } catch(Throwable e) { log("func control failed " + sig + " err=" + e); }
                        }
                    });
                    count++;
                    log("hooked func rule " + sig + " from=" + from);
                } catch(Throwable e) { log("hook func failed " + sig + " err=" + e); }
            }
            if (count > 0) reportStatus(pkg, "函数控制已Hook", cls.getName() + " x" + count);
        } catch(Throwable e) { log("hookFuncClass failed: " + e); }
    }

    static FuncRule findRuleForMethod(String cls, String method, ArrayList rules) {
        try {
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r == null || method == null || !method.equals(r.method)) continue;
                if (cls != null && cls.equals(r.cls)) return r;
                if (isIappAidRuntimeClassName(cls) && isIappRuntimeRule(r) && iappRuntimeClassRuleMatches(cls, r.cls)) return r;
            }
        } catch(Throwable ignored) {}
        return null;
    }

    static boolean shouldSkipHookMethod(Method m) {
        try {
            if (m == null) return true;
            int mod = m.getModifiers();
            if (Modifier.isAbstract(mod) || Modifier.isNative(mod)) return true;
            if (m.isSynthetic() || m.isBridge()) return true;
            return false;
        } catch(Throwable e) { return true; }
    }

    static void hookClass(final String pkg, Class<?> cls, String from) {
        if (cls == null) return;
        Method[] ms;
        try { ms = cls.getDeclaredMethods(); } catch(Throwable e) { log("get methods failed: " + e); return; }
        int count = 0;
        for (int i=0;i<ms.length;i++) {
            final Method m = ms[i];
            if (!TARGET_METHOD.equals(m.getName())) continue;
            final String sig = methodSig(m);
            synchronized (HOOKED) { if (HOOKED.contains(sig)) continue; HOOKED.add(sig); }
            try { m.setAccessible(true); } catch(Throwable ignored) {}
            try {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // 动态获取dexkey只记录 after 非空返回值；before 不再输出，避免刷屏。
                    }
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try { if (isFbEnabled(pkg) && param != null) reportDexKeyOnce(pkg, param.getResult()); }
                        catch(Throwable e) { log("dexkey report failed: " + e); }
                    }
                });
                count++;
                log("hooked " + sig + " from=" + from);
            } catch(Throwable e) { log("hook failed " + sig + " err=" + e); }
        }
        if (count > 0) reportStatus(pkg, "已Hook", "动态获取dexkey x" + count);
    }

    static void hookDynamicClass(final String pkg, final Class<?> cls, String from) {
        if (cls == null) return;
        Method[] ms;
        try { ms = cls.getDeclaredMethods(); } catch(Throwable e) { return; }
        int count = 0;
        for (int i=0;i<ms.length;i++) {
            final Method m = ms[i];
            if (!shouldHookDynamicMethod(cls, m)) continue;
            // The dedicated event-extractor hook performs stricter tag validation and
            // avoids applying the same function rule twice to the same return value.
            if (isIappEventExtractorCandidate(cls)
                    && shouldHookIappEventExtractorMethod(cls, m)) continue;
            final String sig = methodSig(m);
            synchronized (DYNAMIC_HOOKED) { if (DYNAMIC_HOOKED.contains(sig)) continue; DYNAMIC_HOOKED.add(sig); }
            try { m.setAccessible(true); } catch(Throwable ignored) {}
            try {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try { if (isRuntimeScriptControlEnabled(pkg)) handleDynamicBefore(pkg, cls, m, sig, param); }
                        catch(Throwable e) { log("dynamic before failed: " + e); }
                    }
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try { if (isRuntimeScriptControlEnabled(pkg)) handleDynamicAfter(pkg, cls, m, sig, param); }
                        catch(Throwable e) { log("dynamic after failed: " + e); }
                    }
                });
                count++;
                log("hooked dynamic " + sig + " from=" + from);
            } catch(Throwable e) { log("hook dynamic failed " + sig + " err=" + e); }
        }
        if (count > 0) reportStatus(pkg, "动态已Hook", cls.getName() + " x" + count);
    }

    static boolean shouldHookDynamicMethod(Class<?> cls, Method m) {
        try {
            String cn = cls.getName();
            String mn = m.getName();
            if ("bsh.Interpreter".equals(cn) && "eval".equals(mn)) return true;
            if ("com.iapp.app.e".equals(cn) && "ah".equals(mn)) return true;
            // 1.3.2：V3 动态项目常通过 native com.iapp.app.b.h*/h3/h4 直接返回解密后的 UI/事件源码。
            // 旧版只在 before 里记录文件名，没有在 after 里保存返回值，所以齿轮辅助这类样本会没有输出。
            if ("com.iapp.app.b".equals(cn) && ("h".equals(mn) || "h2".equals(mn) || "h3".equals(mn)
                    || "h4".equals(mn) || "h5".equals(mn) || "h6".equals(mn)
                    || "h7".equals(mn) || "h8".equals(mn) || "h9".equals(mn))) return true;
            if ("com.b.a.a.h".equals(cn) && ("k".equals(mn) || "l".equals(mn))) return true;
            if ("com.iapp.app.run.mian".equals(cn) && ("g".equals(mn) || "goevent".equals(mn) || "goUIEventset".equals(mn))) return true;
            if (("com.iapp.app.run.main".equals(cn) || "com.iapp.app.run.main2".equals(cn) || "com.iapp.app.run.main3".equals(cn))
                    && ("geteventItme".equals(mn) || "addeventItme".equals(mn) || "executeLua".equals(mn) || "xmltolua".equals(mn))) return true;
            if ("c.b.a.a.p".equals(cn) && "c".equals(mn)) return true;

            // 1.3.1：动态加密 V3 样本（如齿轮辅助）常见事件链：
            // Aid_YuCode/Aid_YuCodeX.geteventItme(...) 提取事件代码，goevent/goUIEventset/f/ssj 再执行。
            // 只 Hook 这些小范围入口，用于动态导出和函数/内容控制。
            if (("com.h.y.tool.Aid_YuCode".equals(cn) || "com.iapp.app.Aid_YuCodeX".equals(cn))
                    && ("geteventItme".equals(mn) || "goevent".equals(mn) || "goUIEventset".equals(mn)
                    || "f".equals(mn) || "ssj".equals(mn))) return true;

            // v189: 有些 iApp 版本会用其它短方法直接返回事件源码。
            // 只在已知 iApp 类里扩展 hook String/CharSequence/Object 返回，避免全局误伤。
            Class rt = m.getReturnType();
            if (("com.iapp.app.b".equals(cn) || "com.b.a.a.h".equals(cn) || "com.iapp.app.run.mian".equals(cn))
                    && (rt == String.class || rt == CharSequence.class || rt == Object.class)) {
                return true;
            }
            return false;
        } catch(Throwable e) { return false; }
    }

    static void handleDynamicBefore(String pkg, Class<?> cls, Method m, String sig, XC_MethodHook.MethodHookParam param) {
        String cn = cls.getName();
        String mn = m.getName();
        Object[] args = param == null ? null : param.args;
        boolean dump = shouldDumpDynamic(pkg);
        boolean func = isFuncEnabled(pkg);

        // v190: 不再因为参数里“包含”目标函数就直接跳过当前 Hook 方法。
        // 这些参数大多是整段 iApp 脚本文本，直接 setResult 会导致整段事件不执行。
        // 这里改为只删除/替换目标函数调用本身，然后把修改后的参数交回解释器。
        if (func && args != null) {
            String rtFile = CURRENT_SCRIPT_FILE == null ? (CURRENT_EVENT_FILE == null ? (CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE) : CURRENT_EVENT_FILE) : CURRENT_SCRIPT_FILE;
            applyRulesToRuntimeArgs(pkg, rtFile, args, sig);
        }

        if (isAidEventRuntimeClass(cn)) {
            handleAidEventRuntimeBefore(pkg, sig, args);
            return;
        }

        if ("com.iapp.app.b".equals(cn) && "h4".equals(mn)) {
            String file = normalizeIappName(argString(args, 1), ".iyu");
            CURRENT_UI_FILE = file;
            getPage(file);
            return;
        }

        if ("com.iapp.app.e".equals(cn) && "ah".equals(mn)) {
            String text = argString(args, 1);
            String file = CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE;
            if (dump && text != null && text.length() > 0) appendPagePart(pkg, sig, file, "ui", text);
            return;
        }

        if ("com.iapp.app.b".equals(cn) && "h3".equals(mn)) {
            String file = normalizeIappName(argString(args, 1), ".iyu");
            CURRENT_EVENT_FILE = file;
            getPage(file);
            if (func && args != null) applyRulesToStringArgs(pkg, file, args, sig);
            return;
        }

        if ("com.iapp.app.b".equals(cn) && "h7".equals(mn)) {
            String file = normalizeIappName(argString(args, 2), ".iyu");
            CURRENT_SCRIPT_FILE = file;
            getPage(file);
            if (func && args != null) applyRulesToStringArgs(pkg, file, args, sig);
            return;
        }

        if ("bsh.Interpreter".equals(cn) && "eval".equals(mn)) {
            if (args != null && args.length > 0 && args[0] instanceof Reader) {
                String text = readerToStringSafe((Reader)args[0]);
                if (text != null) {
                    String file = CURRENT_SCRIPT_FILE == null ? (CURRENT_EVENT_FILE == null ? "mian.iyu" : CURRENT_EVENT_FILE) : CURRENT_SCRIPT_FILE;
                    String fixed = func ? applyIappFuncRules(pkg, file, text) : text;
                    // 读过 Reader 后必须放回新的 StringReader，否则目标解释器会读到新的内容。
                    try { args[0] = new StringReader(fixed == null ? text : fixed); } catch(Throwable ignored) {}
                    if (dump && fixed != null && fixed.length() > 0) appendPagePart(pkg, sig, file, "script", fixed);
                }
            }
            return;
        }

        if ("com.iapp.app.run.mian".equals(cn) && "g".equals(mn)) {
            String text = null;
            boolean fromArg = false;
            if (args != null && args.length > 0 && args[0] instanceof String) { text = (String)args[0]; fromArg = true; }
            if ((text == null || text.length() == 0) && param != null && param.thisObject != null) text = getObjectFieldText(param.thisObject, "r");
            if (text != null && text.length() > 0) {
                String file = CURRENT_EVENT_FILE == null ? (CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE) : CURRENT_EVENT_FILE;
                String fixed = func ? applyIappFuncRules(pkg, file, text) : text;
                if (fromArg && fixed != null && !fixed.equals(text)) {
                    try { args[0] = fixed; } catch(Throwable ignored) {}
                }
                if (dump && fixed != null) appendPagePart(pkg, sig, file, "event", fixed);
            }
        }
    }

    static void handleDynamicAfter(String pkg, Class<?> cls, Method m, String sig, XC_MethodHook.MethodHookParam param) {
        String cn = cls.getName();
        String mn = m.getName();
        boolean dump = shouldDumpDynamic(pkg);
        boolean func = isFuncEnabled(pkg);

        if ("com.iapp.app.b".equals(cn)) {
            handleNativeIappBOutput(pkg, sig, mn, param, dump, func);
            // h3/h4/h5/h6/h 返回值已经在上面处理；h7/h8/h9 通常不是文本返回。
            if ("h".equals(mn) || "h3".equals(mn) || "h4".equals(mn) || "h5".equals(mn) || "h6".equals(mn)) return;
        }

        // v189: 直接拦截“返回事件/脚本源码”的方法。
        // 这里改的是返回给 iApp 解释器之前的事件文本，不是只改导出文件。
        if (func && param != null) {
            tryRewriteReturnedIappSource(pkg, sig, param);
        }

        if (isAidEventRuntimeClass(cn)) {
            handleAidEventRuntimeAfter(pkg, sig, param);
            return;
        }

        if ("com.b.a.a.h".equals(cn) && "k".equals(mn)) {
            Object r = param == null ? null : param.getResult();
            String text = r == null ? null : String.valueOf(r);
            if (text != null && text.length() > 0) {
                String file = CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE;
                String fixed = func ? applyIappFuncRules(pkg, file, text) : text;
                if (func && param != null && fixed != null && !fixed.equals(text)) {
                    try { param.setResult(fixed); } catch(Throwable ignored) {}
                }
                if (dump && fixed != null) appendPagePart(pkg, sig, file, "loading", fixed);
            }
            return;
        }

        if ("com.b.a.a.h".equals(cn) && "l".equals(mn)) {
            if (dump) dumpFunctionMap(pkg, cls, sig);
            return;
        }

        if (dump && !("com.iapp.app.e".equals(cn) || "com.iapp.app.b".equals(cn) || "com.iapp.app.run.mian".equals(cn) || "bsh.Interpreter".equals(cn))) {
            Object r = param == null ? null : param.getResult();
            String text = objectToText(r);
            if (looksLikeIappSource(text)) appendStandalone(pkg, sig, text);
        }
    }



    static void handleNativeIappBOutput(String pkg, String sig, String mn, XC_MethodHook.MethodHookParam param, boolean dump, boolean func) {
        try {
            if (param == null) return;
            Object r = param.getResult();
            if (!(r instanceof String) && !(r instanceof CharSequence)) return;
            String text = String.valueOf(r);
            if (text == null || text.trim().length() == 0) return;

            Object[] args = param.args;
            String name = null;
            try {
                if (args != null && args.length > 1 && args[1] != null) name = String.valueOf(args[1]);
                else if (args != null && args.length > 2 && args[2] != null) name = String.valueOf(args[2]);
            } catch(Throwable ignored) {}

            String file = chooseNativeIappBFile(mn, name);
            String type = chooseNativeIappBType(mn, file, text);
            String fixed = func ? applyIappFuncRules(pkg, file, text) : text;
            if (func && fixed != null && !fixed.equals(text)) {
                try { param.setResult(fixed); } catch(Throwable ignored) {}
                text = fixed;
            }
            if (dump && isUsefulNativeIappBText(text)) {
                appendPagePart(pkg, sig, file, type, text);
                reportStatus(pkg, "动态解密", "成功");
            }
        } catch(Throwable e) { log("handleNativeIappBOutput failed: " + e); }
    }

    static String chooseNativeIappBFile(String mn, String name) {
        try {
            String n = name == null ? "" : name.trim();
            if (n.length() == 0) {
                if (CURRENT_SCRIPT_FILE != null && CURRENT_SCRIPT_FILE.length() > 0) return CURRENT_SCRIPT_FILE;
                if (CURRENT_EVENT_FILE != null && CURRENT_EVENT_FILE.length() > 0) return CURRENT_EVENT_FILE;
                if (CURRENT_UI_FILE != null && CURRENT_UI_FILE.length() > 0) return CURRENT_UI_FILE;
                return "mian.iyu";
            }
            String low = n.toLowerCase(Locale.US);
            if (low.endsWith(".iyu") || low.endsWith(".myu") || low.endsWith(".ilua") || low.endsWith(".mlua")
                    || low.endsWith(".lua") || low.endsWith(".ijava") || low.endsWith(".mjava")
                    || low.endsWith(".java") || low.endsWith(".ijs") || low.endsWith(".mjs") || low.endsWith(".js")) return n;
            return normalizeIappName(n, ".iyu");
        } catch(Throwable e) { return "mian.iyu"; }
    }

    static String chooseNativeIappBType(String mn, String file, String text) {
        try {
            String t = text == null ? "" : text.toLowerCase(Locale.US);
            if ("h4".equals(mn)) return "ui";
            if ("h3".equals(mn)) return "event";
            if ("h7".equals(mn)) return "script";
            if (t.indexOf("<view") >= 0 || t.indexOf("<uieventset") >= 0 || t.indexOf("<xxbj") >= 0) return "ui";
            if (t.indexOf("<eventitme") >= 0 || t.indexOf("[true]") >= 0) return "event";
            if (looksLikeIappRuntimeCode(text) || looksLikeIappSource(text)) return "event";
            if (file != null && !isIyuFile(file)) return "standalone";
            return "event";
        } catch(Throwable e) { return "event"; }
    }

    static boolean isUsefulNativeIappBText(String s) {
        try {
            if (s == null) return false;
            if (s.length() < 2 || s.length() > 1024 * 1024 * 5) return false;
            String t = s.toLowerCase(Locale.US);
            if (t.indexOf("<view") >= 0 || t.indexOf("<eventitme") >= 0 || t.indexOf("<uieventset") >= 0 || t.indexOf("<xxbj") >= 0) return true;
            if (t.indexOf("[true]") >= 0) return true;
            return looksLikeIappSource(s) || looksLikeIappRuntimeCode(s);
        } catch(Throwable e) { return false; }
    }



    static boolean isAidEventRuntimeClass(String cn) {
        try {
            return "com.h.y.tool.Aid_YuCode".equals(cn) || "com.iapp.app.Aid_YuCodeX".equals(cn);
        } catch(Throwable e) { return false; }
    }

    static void handleAidEventRuntimeBefore(String pkg, String sig, Object[] args) {
        try {
            boolean dump = shouldDumpDynamic(pkg);
            boolean func = isFuncEnabled(pkg);
            if (!dump && !func) return;
            if (args == null || args.length == 0) return;
            String file = currentRuntimeFile();
            boolean wrote = false;
            for (int i=0;i<args.length;i++) {
                Object v = args[i];
                if (!(v instanceof String) && !(v instanceof CharSequence)) continue;
                String old = String.valueOf(v);
                if (old == null || old.length() == 0) continue;
                String fixed = func ? applyIappFuncRules(pkg, file, old) : old;
                if (func && fixed != null && !fixed.equals(old)) {
                    args[i] = fixed;
                    old = fixed;
                }
                if (dump && isUsefulAidRuntimeText(old)) {
                    appendAidRuntimeText(pkg, sig, file, old);
                    wrote = true;
                }
            }
            if (func) reportFuncSample(pkg, "运行时", sig, "成功");
            if (dump && wrote) reportStatus(pkg, "动态解密", "成功");
        } catch(Throwable e) { log("handleAidEventRuntimeBefore failed: " + e); }
    }

    static void handleAidEventRuntimeAfter(String pkg, String sig, XC_MethodHook.MethodHookParam param) {
        try {
            boolean dump = shouldDumpDynamic(pkg);
            boolean func = isFuncEnabled(pkg);
            if (!dump && !func) return;
            if (param == null) return;
            Object r = param.getResult();
            if (!(r instanceof String) && !(r instanceof CharSequence)) return;
            String old = String.valueOf(r);
            if (old == null || old.length() == 0) return;
            String file = currentRuntimeFile();
            String fixed = func ? applyIappFuncRules(pkg, file, old) : old;
            if (func && fixed != null && !fixed.equals(old)) {
                try { param.setResult(fixed); } catch(Throwable ignored) {}
                old = fixed;
            }
            if (dump && isUsefulAidRuntimeText(old)) {
                appendAidRuntimeText(pkg, sig, file, old);
                reportStatus(pkg, "动态解密", "成功");
            }
            if (func) reportFuncSample(pkg, "事件代码", sig, "成功");
        } catch(Throwable e) { log("handleAidEventRuntimeAfter failed: " + e); }
    }

    static String currentRuntimeFile() {
        try {
            if (CURRENT_SCRIPT_FILE != null && CURRENT_SCRIPT_FILE.length() > 0) return CURRENT_SCRIPT_FILE;
            if (CURRENT_EVENT_FILE != null && CURRENT_EVENT_FILE.length() > 0) return CURRENT_EVENT_FILE;
            if (CURRENT_UI_FILE != null && CURRENT_UI_FILE.length() > 0) return CURRENT_UI_FILE;
        } catch(Throwable ignored) {}
        return "mian.iyu";
    }

    static boolean isUsefulAidRuntimeText(String s) {
        try {
            if (s == null) return false;
            if (s.length() < 3 || s.length() > 1024 * 1024 * 3) return false;
            String t = s.toLowerCase(Locale.US);
            if (t.indexOf("<eventitme") >= 0 || t.indexOf("<uieventset") >= 0 || t.indexOf("</eventitme>") >= 0) return true;
            return looksLikeIappSource(s) || looksLikeIappRuntimeCode(s);
        } catch(Throwable e) { return false; }
    }

    static void appendAidRuntimeText(String pkg, String sig, String file, String text) {
        try {
            if (text == null || text.trim().length() == 0) return;
            String t = text.trim();
            if (t.indexOf("<eventItme") >= 0 || t.indexOf("<eventitme") >= 0 || t.indexOf("<UIEventset") >= 0) {
                appendPagePart(pkg, sig, file, "event", t);
            } else if (looksLikeIappSource(t) || looksLikeIappRuntimeCode(t)) {
                appendPagePart(pkg, sig, file, "event", t);
            }
        } catch(Throwable e) { log("appendAidRuntimeText failed: " + e); }
    }

    static Object defaultResultFor(Class rt) {
        try {
            if (rt == null || rt == Void.TYPE || rt == Void.class) return null;
            if (rt == Boolean.TYPE) return Boolean.FALSE;
            if (rt == Integer.TYPE) return Integer.valueOf(0);
            if (rt == Long.TYPE) return Long.valueOf(0L);
            if (rt == Float.TYPE) return Float.valueOf(0f);
            if (rt == Double.TYPE) return Double.valueOf(0d);
            if (rt == Short.TYPE) return Short.valueOf((short)0);
            if (rt == Byte.TYPE) return Byte.valueOf((byte)0);
            if (rt == Character.TYPE) return Character.valueOf('\0');
            return null;
        } catch(Throwable e) { return null; }
    }

    static String findDisableFuncInRuntimeArgs(String pkg, String file, Object[] args) {
        try {
            if (args == null || !isFuncEnabled(pkg)) return null;
            for (int i=0;i<args.length;i++) {
                String r = findDisableFuncInRuntimeObject(file, args[i], 0);
                if (r != null && r.length() > 0) return r;
            }
        } catch(Throwable e) { log("findDisableFuncInRuntimeArgs failed: " + e); }
        return null;
    }

    static String findDisableFuncInRuntimeObject(String file, Object obj, int depth) {
        try {
            if (obj == null || depth > 4) return null;
            if (obj instanceof String || obj instanceof CharSequence) {
                return findDisableFuncInText(file, String.valueOf(obj));
            }
            // Reader 会被读空，所以不要在通用扫描里读；eval 分支会单独处理 Reader。
            if (obj instanceof Reader) return null;
            Class<?> c = obj.getClass();
            if (c.isArray() && c.getComponentType() != null && !c.getComponentType().isPrimitive()) {
                Object[] arr = (Object[])obj;
                for (int i=0;i<arr.length;i++) {
                    String r = findDisableFuncInRuntimeObject(file, arr[i], depth + 1);
                    if (r != null && r.length() > 0) return r;
                }
            }
        } catch(Throwable e) { log("findDisableFuncInRuntimeObject failed: " + e); }
        return null;
    }

    static String findDisableFuncInText(String file, String text) {
        try {
            if (text == null || text.length() == 0) return null;
            if (!isIappRuntimeFile(file)) return null;
            ArrayList rules = copyFuncRules();
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r == null || !"disable".equals(r.mode) || r.method == null || r.method.length() == 0) continue;
                if (containsIappFuncCall(text, r.method)) return r.method;
            }
        } catch(Throwable e) { log("findDisableFuncInText failed: " + e); }
        return null;
    }

    static boolean containsIappFuncCall(String text, String name) {
        try {
            return findIappFuncCall(text, name, 0) >= 0;
        } catch(Throwable e) { return false; }
    }

    static void applyRulesToStringArgs(String pkg, String file, Object[] args, String sig) {
        applyRulesToRuntimeArgs(pkg, file, args, sig);
    }

    static void applyRulesToRuntimeArgs(String pkg, String file, Object[] args, String sig) {
        try {
            if (args == null || !isFuncEnabled(pkg)) return;
            boolean changed = false;
            for (int i=0;i<args.length;i++) {
                Object old = args[i];
                Object fixed = applyRulesToRuntimeObject(pkg, file, old, 0);
                if (fixed != old) {
                    args[i] = fixed;
                    changed = true;
                }
            }
            if (changed) reportFunc(pkg, "运行时", sig, "已修改参数");
        } catch(Throwable e) { log("applyRulesToRuntimeArgs failed: " + e); }
    }

    static Object applyRulesToRuntimeObject(String pkg, String file, Object obj, int depth) {
        try {
            if (obj == null) return obj;
            if (depth > 4) return obj;

            if (obj instanceof String) {
                String old = (String)obj;
                String fixed = applyIappFuncRules(pkg, file, old);
                if (fixed != null && !fixed.equals(old)) return fixed;
                return obj;
            }

            if (obj instanceof CharSequence) {
                String old = String.valueOf(obj);
                String fixed = applyIappFuncRules(pkg, file, old);
                if (fixed != null && !fixed.equals(old)) return fixed;
                return obj;
            }

            if (obj instanceof Reader) {
                String old = readerToStringSafe((Reader)obj);
                if (old == null) return obj;
                String fixed = applyIappFuncRules(pkg, file, old);
                if (fixed == null) fixed = old;
                return new StringReader(fixed);
            }

            Class<?> c = obj.getClass();
            if (c.isArray() && c.getComponentType() != null && !c.getComponentType().isPrimitive()) {
                Object[] arr = (Object[])obj;
                for (int i=0;i<arr.length;i++) {
                    Object old = arr[i];
                    Object fixed = applyRulesToRuntimeObject(pkg, file, old, depth + 1);
                    if (fixed != old) arr[i] = fixed;
                }
                return obj;
            }
        } catch(Throwable e) { log("applyRulesToRuntimeObject failed: " + e); }
        return obj;
    }


    static PageBuf getPage(String file) {
        String f = normalizeIappName(file, ".iyu");
        synchronized (PAGES) {
            PageBuf p = PAGES.get(f);
            if (p == null) { p = new PageBuf(f); PAGES.put(f, p); }
            return p;
        }
    }

    static void appendPagePart(String pkg, String sig, String file, String type, String text) {
        try {
            if (text == null || text.length() == 0) return;
            String f = normalizeIappName(file, ".iyu");
            String normalized = normalizeDynamicText(f, type, text);
            if (normalized == null || normalized.trim().length() == 0) return;
            // 有些版本的动态解密会把 UI 半成品从 event/script/standalone 分支吐出来，
            // 例如 <UIEventset><View ...> 但没有 </View>。只要是 .iyu 且含 View，
            // 一律改走 ui 聚合分支，后面 buildIyu() 才能按 id/did 补闭合。
            if (isIyuFile(f) && normalized.indexOf("<View") >= 0) {
                type = "ui";
            }
            if ("loading".equals(type) || "event".equals(type) || "script".equals(type) || "standalone".equals(type)) {
                normalized = applyIappFuncRules(pkg, f, normalized);
            }

            // mjava / mjs / mlua / java / js / lua / myu 等不是界面文件，直接输出源码本体，不包 xxbj/CDAT A。
            if (!isIyuFile(f)) {
                String path = writeTextFile(pkg, f, normalized, false);
                reportDynamicFile(pkg, sig, f, normalized, path);
                return;
            }

            PageBuf p = getPage(f);
            synchronized (p) {
                if ("ui".equals(type)) p.ui = mergeUnique(p.ui, normalized);
                else if ("loading".equals(type)) p.loading = mergeUnique(p.loading, normalized);
                else if ("event".equals(type)) p.event = mergeUnique(p.event, normalized);
                else if ("script".equals(type)) p.script = mergeUnique(p.script, normalized);
                else p.event = mergeUnique(p.event, normalized);
                String built = buildIyu(p);
                String path = writeTextFile(pkg, p.file, built, false);
                reportDynamicFile(pkg, sig, p.file, built, path);
            }
        } catch(Throwable e) { log("appendPagePart failed: " + e); }
    }

    static String buildIyu(PageBuf p) {
        String rawUi = p.ui == null ? "" : p.ui.trim();
        String fixedUi = repairViewClosures(cleanIyuFileBody(rawUi)).trim();

        String viewPart = fixedUi;
        String eventsFromUi = "";
        int uiOpen = indexOfIgnoreCase(fixedUi, "<UIEventset", 0);
        if (uiOpen >= 0) {
            viewPart = fixedUi.substring(0, uiOpen).trim();
            int gt = fixedUi.indexOf('>', uiOpen);
            int uiClose = indexOfIgnoreCase(fixedUi, "</UIEventset>", gt < 0 ? uiOpen : gt);
            if (gt >= 0 && uiClose >= 0) eventsFromUi = fixedUi.substring(gt + 1, uiClose).trim();
            else if (gt >= 0) eventsFromUi = fixedUi.substring(gt + 1).trim();
        }

        String loading = normalizeEventItems(p.loading, "loading");
        String event = normalizeEventItems(p.event, null);
        String script = normalizeEventItems(p.script, "loading");

        // iApp V3 的 .iyu 不是 XML 嵌套树：控件必须平铺在文件前半段，父子关系只靠 did。
        // 全局 loading/restart/onactivityresult 等才放到末尾的 <UIEventset> 里。
        StringBuilder out = new StringBuilder();
        appendNonEmpty(out, viewPart);
        out.append("<UIEventset>\n");
        appendNonEmpty(out, eventsFromUi);
        appendNonEmpty(out, loading);
        appendNonEmpty(out, event);
        appendNonEmpty(out, script);
        out.append("</UIEventset>\n");
        return out.toString();
    }

    static void dumpFunctionMap(String pkg, Class<?> hClass, String sig) {
        try {
            ClassLoader cl = hClass.getClassLoader();
            if (cl == null) return;
            Class<?> rCls = cl.loadClass("com.b.a.a.r");
            Field f = rCls.getDeclaredField("c");
            f.setAccessible(true);
            Object obj = f.get(null);
            if (!(obj instanceof Map)) return;
            Map map = (Map)obj;
            Iterator it = map.keySet().iterator();
            int count = 0;
            while (it.hasNext()) {
                Object k = it.next();
                if (k == null) continue;
                Object v = map.get(k);
                if (v == null) continue;
                String key = String.valueOf(k);
                String val = String.valueOf(v);
                String[] sp = key.split("\\.");
                String file = normalizeIappName(sp.length > 0 ? sp[0] : key, ".myu");
                if (!file.endsWith(".myu")) file = baseNameNoExt(file) + ".myu";
                String fnText = "fn " + val + "\nend fn\n";
                appendTextUnique(pkg, file, fnText);
                count++;
            }
            // 函数文件由 appendTextUnique 单独记录，这里不再输出汇总日志。
        } catch(Throwable e) { log("dumpFunctionMap failed: " + e); }
    }

    static void appendStandalone(String pkg, String sig, String text) {
        try {
            String file = normalizeIappName(inferFileFromSig(sig), ".iyu");
            String t = text == null ? "" : text;
            // 泛型动态捕获分支经常拿到的是完整/半完整 UI 源码。
            // 之前这里直接 appendTextUnique() 追加原文，绕过了 buildIyu()，所以不会补 </View>。
            if (isIyuFile(file) && t.indexOf("<View") >= 0) {
                appendPagePart(pkg, sig, file, "ui", t);
                return;
            }
            appendTextUnique(pkg, file, text);
        } catch(Throwable e) { log("appendStandalone failed: " + e); }
    }

    static void appendTextUnique(String pkg, String rel, String text) {
        if (text == null || text.length() == 0) return;
        String file = normalizeIappName(rel, ".iyu");
        String clean = normalizeDynamicText(file, "standalone", text);
        clean = applyIappFuncRules(pkg, file, clean);
        if (clean == null || clean.trim().length() == 0) return;
        if (isIyuFile(file) && clean.indexOf("<View") >= 0) {
            clean = buildLooseIyuDump(clean);
        }
        String h = sha1(file + "\n" + clean);
        synchronized (WRITTEN_HASH) {
            if (WRITTEN_HASH.contains(h)) return;
            if (WRITTEN_HASH.size() > 1200) WRITTEN_HASH.clear();
            WRITTEN_HASH.add(h);
        }
        String path = providerWriteText(pkg, file, clean, true);
        log("append dump provider " + path);
        reportDynamicFile(pkg, "iAPT-DUMP", file, clean, path);
    }

    static String writeTextFile(String pkg, String rel, String text, boolean append) {
        String path = providerWriteText(pkg, rel, text, append);
        log("dynamic dump provider " + path);
        return path;
    }

    static String providerWriteText(String pkg, String rel, String text, boolean append) {
        try {
            if (text == null) text = "";
            String r = normalizeDumpRelPath(rel);
            if (isIyuFile(r) && text.indexOf("<View") >= 0) {
                text = buildLooseIyuDump(text);
            }
            String displayPath = DUMP_ROOT + safePathPart(pkg) + "/" + r;
            int len = text.length();
            if (len <= MAX_DUMP_CHARS) {
                providerWriteChunk(pkg, r, text, append);
                return displayPath;
            }
            int pos = 0;
            boolean first = true;
            while (pos < len) {
                int to = pos + MAX_DUMP_CHARS;
                if (to > len) to = len;
                String chunk = text.substring(pos, to);
                providerWriteChunk(pkg, r, chunk, first ? append : true);
                first = false;
                pos = to;
            }
            return displayPath;
        } catch(Throwable e) {
            log("providerWriteText failed: " + e);
            return "write_failed:" + e.getClass().getName();
        }
    }

    static void providerWriteChunk(String pkg, String rel, String text, boolean append) {
        try {
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", "iAPT-DUMP");
            cv.put("stage", "dynamic_dump");
            cv.put("args_json", "rel=" + rel);
            cv.put("result_text", "");
            cv.put("result_b64", "");
            cv.put("dump_rel", rel);
            cv.put("dump_text", text == null ? "" : text);
            cv.put("dump_append", append ? "1" : "0");
            insertDump(pkg, cv);
        } catch(Throwable e) { log("providerWriteChunk failed: " + e); }
    }

    static File dumpDir(String pkg) {
        return new File(DUMP_ROOT + safePathPart(pkg));
    }

    static File ensureDumpDir(String pkg) {
        File d = dumpDir(pkg);
        try { d.mkdirs(); } catch(Throwable ignored) {}
        return d;
    }

    static File safeOutFile(String pkg, String rel) {
        File base = ensureDumpDir(pkg);
        String r = normalizeRelPath(rel);
        File out = new File(base, r);
        try {
            String bp = base.getCanonicalPath();
            String op = out.getCanonicalPath();
            if (!op.startsWith(bp + File.separator) && !op.equals(bp)) out = new File(base, safePathPart(new File(r).getName()));
        } catch(Throwable ignored) {}
        return out;
    }

    static String normalizeIappName(String name, String defExt) {
        String x = name == null ? "" : name.trim();
        if (x.length() == 0 || "null".equalsIgnoreCase(x)) x = "mian";
        x = x.replace('\\', '/');
        int q = x.indexOf('?'); if (q >= 0) x = x.substring(0, q);
        while (x.startsWith("/")) x = x.substring(1);
        if (x.indexOf('\n') >= 0) x = x.substring(0, x.indexOf('\n'));
        if (x.indexOf('\r') >= 0) x = x.substring(0, x.indexOf('\r'));
        x = normalizeRelPath(x);
        String lower = x.toLowerCase(Locale.US);
        if (!(lower.endsWith(".iyu") || lower.endsWith(".myu") || lower.endsWith(".mjava") || lower.endsWith(".mjs") || lower.endsWith(".mlua") || lower.endsWith(".ijs") || lower.endsWith(".ilua") || lower.endsWith(".ijava") || lower.endsWith(".java") || lower.endsWith(".js") || lower.endsWith(".lua"))) {
            x = x + (defExt == null ? ".iyu" : defExt);
        }
        return x;
    }

    static String normalizeRelPath(String s) {
        if (s == null) return "mian.iyu";
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

    static String mergeUnique(String old, String add) {
        if (add == null || add.length() == 0) return old == null ? "" : old;
        String a = add.trim();
        if (a.length() == 0) return old == null ? "" : old;
        String o = old == null ? "" : old;
        if (o.indexOf(a) >= 0) return o;
        if (o.length() == 0) return a + "\n";
        return o + (o.endsWith("\n") ? "" : "\n") + a + "\n";
    }


    static boolean isIyuFile(String f) {
        if (f == null) return false;
        return f.toLowerCase(Locale.US).endsWith(".iyu");
    }

    static boolean isKnownSourceFile(String f) {
        if (f == null) return false;
        String x = f.toLowerCase(Locale.US);
        return x.endsWith(".iyu") || x.endsWith(".myu") || x.endsWith(".mjava") || x.endsWith(".mjs") || x.endsWith(".mlua") || x.endsWith(".ijs") || x.endsWith(".ilua") || x.endsWith(".ijava") || x.endsWith(".java") || x.endsWith(".js") || x.endsWith(".lua");
    }

    static void appendNonEmpty(StringBuilder sb, String x) {
        if (x == null) return;
        String t = x.trim();
        if (t.length() == 0) return;
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
        sb.append(t).append('\n');
    }

    static String normalizeDynamicText(String file, String type, String text) {
        if (text == null) return "";
        String f = normalizeIappName(file, ".iyu");
        String x = text;
        if (!isIyuFile(f)) {
            return cleanScriptFileBody(x);
        }
        return cleanIyuFileBody(x);
    }

    static String cleanScriptFileBody(String text) {
        if (text == null) return "";
        String x = stripXmlDecl(text).trim();
        ArrayList blocks = cdataBlocks(x);
        if (blocks.size() > 0) {
            String best = "";
            for (int i=0;i<blocks.size();i++) {
                String b = String.valueOf(blocks.get(i));
                if (isSyntheticIappHelper(b)) b = stripSyntheticIappHelper(b);
                if (b == null || b.trim().length() == 0) continue;
                if (best.length() == 0 || b.length() > best.length()) best = b;
            }
            if (best.length() > 0) x = best;
        }
        x = removeSimpleWrapperTags(x);
        x = stripSyntheticIappHelper(x);
        return ensureOneNewline(removeBadUnicodeControls(x).trim());
    }

    static String cleanIyuFileBody(String text) {
        if (text == null) return "";
        String x = stripXmlDecl(text).trim();
        ArrayList blocks = cdataBlocks(x);
        if (blocks.size() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<blocks.size();i++) {
                String b = String.valueOf(blocks.get(i));
                if (isSyntheticIappHelper(b)) continue;
                if (!(b.indexOf("<View") >= 0 || b.indexOf("<eventItme") >= 0 || looksLikeIappSource(b))) continue;
                if (sb.length() > 0) sb.append('\n');
                sb.append(b.trim()).append('\n');
            }
            if (sb.length() > 0) x = sb.toString();
        }
        x = removeSimpleWrapperTags(x);
        x = stripXmlDecl(x).trim();
        x = stripSyntheticIappHelper(x).trim();
        return removeBadUnicodeControls(x);
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

    static ArrayList cdataBlocks(String s) {
        ArrayList list = new ArrayList();
        if (s == null) return list;
        int pos = 0;
        while (true) {
            int a = s.indexOf("<![CDATA[", pos);
            if (a < 0) break;
            int b = s.indexOf("]]>", a + 9);
            if (b < 0) break;
            list.add(s.substring(a + 9, b));
            pos = b + 3;
        }
        return list;
    }

    static String removeSimpleWrapperTags(String s) {
        if (s == null) return "";
        String x = s;
        x = x.replaceAll("(?s)<xxbj\\b[^>]*>", "");
        x = x.replace("</xxbj>", "");
        x = x.replaceAll("(?s)<_Yu5Src\\b[^>]*>", "");
        x = x.replace("</_Yu5Src>", "");
        x = x.replaceAll("(?s)<mjava>\\s*<mjava>", "");
        x = x.replaceAll("(?s)</mjava>\\s*</mjava>", "");
        x = x.replaceAll("(?s)<eventItme>\\s*<eventItme>", "");
        x = x.replaceAll("(?s)</eventItme>\\s*</eventItme>", "");
        x = x.replaceAll("(?s)<on_loading>\\s*<on_loading>", "");
        x = x.replaceAll("(?s)</on_loading>\\s*</on_loading>", "");
        return x.trim();
    }

    static boolean isSyntheticIappHelper(String s) {
        if (s == null) return false;
        return s.indexOf("import com.iapp.interfaces.*;") >= 0 && s.indexOf("private void syso(Object o)") >= 0 && s.indexOf("i.syso(o)") >= 0;
    }

    static String stripSyntheticIappHelper(String s) {
        if (s == null) return "";
        String x = s;
        int idx = x.indexOf("import com.iapp.interfaces.*;");
        if (idx >= 0) {
            String tail = x.substring(idx);
            if (tail.indexOf("private void syso(Object o)") >= 0 && tail.indexOf("i.syso(o)") >= 0) {
                x = x.substring(0, idx);
            }
        }
        return x;
    }

    static String ensureOneNewline(String s) {
        if (s == null) return "";
        String x = s.trim();
        return x.length() == 0 ? "" : x + "\n";
    }

    static String buildLooseIyuDump(String s) {
        if (s == null) return "";
        String x = cleanIyuFileBody(s);
        x = repairViewClosures(x).trim();
        if (x.length() == 0) return "";
        if (x.indexOf("<View") >= 0 || x.indexOf("<view") >= 0) {
            return x.endsWith("\n") ? x : x + "\n";
        }
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
        // 只保留真正游离的事件/源码片段，过滤空白和残余包装标签。
        if (t.indexOf("<eventItme") >= 0 || t.indexOf("<eventitme") >= 0 || looksLikeIappSource(t) || looksLikeIappRuntimeCode(t)) {
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
            sb.append(t).append('\n');
        }
    }

    static int indexOfIgnoreCase(String s, String needle, int from) {
        if (s == null || needle == null) return -1;
        String a = s.toLowerCase(Locale.US);
        String b = needle.toLowerCase(Locale.US);
        return a.indexOf(b, from < 0 ? 0 : from);
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
            if (a >= 0) {
                a += p.length();
                int b = tag.indexOf('"', a);
                return b >= 0 ? tag.substring(a, b) : tag.substring(a);
            }
            p = name + "='";
            a = tag.indexOf(p);
            if (a >= 0) {
                a += p.length();
                int b = tag.indexOf('\'', a);
                return b >= 0 ? tag.substring(a, b) : tag.substring(a);
            }
        } catch(Throwable ignored) {}
        return "";
    }

    static String nextNonEmpty(String[] lines, int from) {
        if (lines == null) return "";
        for (int i=from;i<lines.length;i++) {
            String t = lines[i] == null ? "" : lines[i].trim();
            if (t.length() > 0) return t;
        }
        return "";
    }

    static String extractUIEventsetInner(String s) {
        if (s == null) return "";
        int a = s.indexOf("<UIEventset>");
        int b = s.lastIndexOf("</UIEventset>");
        if (a < 0 || b < 0 || b <= a) return "";
        return s.substring(a + "<UIEventset>".length(), b).trim();
    }

    static String removeUIEventsetBlock(String s) {
        if (s == null) return "";
        int a = s.indexOf("<UIEventset>");
        int b = s.lastIndexOf("</UIEventset>");
        if (a < 0 || b < 0 || b <= a) return s;
        return (s.substring(0, a) + s.substring(b + "</UIEventset>".length())).trim();
    }

    static String normalizeEventItems(String text, String defType) {
        if (text == null) return "";
        String x = cleanIyuFileBody(text).trim();
        if (x.length() == 0) return "";
        if (x.indexOf("<UIEventset") >= 0) x = extractUIEventsetInner(x);
        x = removeSimpleWrapperTags(x).trim();
        if (x.length() == 0) return "";
        if (x.indexOf("<eventItme") >= 0) return x.endsWith("\n") ? x : x + "\n";
        String type = defType == null ? "loading" : defType;
        return "<eventItme type=\"" + xmlSafe(type) + "\">\n" + x + "\n</eventItme>\n";
    }

    static String cleanBlock(String s) {
        if (s == null) return "";
        String x = s.trim();
        x = x.replace("]]>", "]] >");
        return x;
    }

    static String baseNameNoExt(String s) {
        if (s == null || s.length() == 0) return "mian";
        String x = s.replace('\\', '/');
        int slash = x.lastIndexOf('/'); if (slash >= 0) x = x.substring(slash + 1);
        int dot = x.lastIndexOf('.'); if (dot > 0) x = x.substring(0, dot);
        if (x.length() == 0) x = "mian";
        return safePathPart(x);
    }

    static String inferFileFromSig(String sig) {
        if (sig == null) return "mian.iyu";
        String x = sig;
        int p = x.lastIndexOf('.');
        if (p >= 0) x = x.substring(p + 1);
        p = x.indexOf('('); if (p >= 0) x = x.substring(0, p);
        if (x.length() == 0) x = "mian";
        return x + ".iyu";
    }

    static String xmlSafe(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String argString(Object[] args, int idx) {
        try {
            if (args == null || idx < 0 || idx >= args.length || args[idx] == null) return null;
            return String.valueOf(args[idx]);
        } catch(Throwable e) { return null; }
    }

    static String getObjectFieldText(Object obj, String name) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            Object v = f.get(obj);
            return v == null ? null : String.valueOf(v);
        } catch(Throwable e) { return null; }
    }

    static String objectToText(Object o) {
        try {
            if (o == null) return null;
            if (o instanceof String) return (String)o;
            if (o instanceof byte[]) return bytesToText((byte[])o);
            if (o instanceof char[]) return new String((char[])o);
            if (o instanceof Reader) return readerToStringSafe((Reader)o);
            return null;
        } catch(Throwable e) { return null; }
    }

    static String readerToStringSafe(Reader r) {
        if (r == null) return null;
        try {
            if (!r.markSupported()) return null;
            r.mark(1024 * 1024 * 3);
            char[] buf = new char[4096];
            StringBuilder sb = new StringBuilder();
            int total = 0;
            while (true) {
                int n = r.read(buf);
                if (n <= 0) break;
                sb.append(buf, 0, n);
                total += n;
                if (total > 1024 * 1024 * 3) break;
            }
            try { r.reset(); } catch(Throwable ignored) {}
            return sb.toString();
        } catch(Throwable e) {
            try { r.reset(); } catch(Throwable ignored) {}
            return null;
        }
    }

    static boolean looksLikeIappSource(String s) {
        if (s == null) return false;
        if (s.length() < 6) return false;
        if (s.length() > 1024 * 1024 * 3) return false;
        String t = s.toLowerCase(Locale.US);
        int hit = 0;
        String[] keys = new String[]{"uigo(", "java ", "java(", "tw(", "t(", "s(", "ss(", "fn ", "for(", "if(", "syso", "end", "_yu5src", "on_loading", "on_click", "eventitme", "载入事件", "点击事件", ".iyu", ".myu", "mian.iyu", "<xxbj", "<event", "<view", "bsh.interpreter"};
        for (int i=0;i<keys.length;i++) if (t.indexOf(keys[i].toLowerCase(Locale.US)) >= 0) hit++;
        if (hit <= 0) return false;
        return s.indexOf('\n') >= 0 || s.indexOf(';') >= 0 || s.indexOf('(') >= 0 || s.indexOf('<') >= 0 || (s.length() > 20 && hit >= 2);
    }

    static boolean isFbEnabled(String pkg) {
        refreshConfig(pkg);
        return FB_ENABLED;
    }

    static boolean isDynamicEnabled(String pkg) {
        refreshConfig(pkg);
        return DYNAMIC_ENABLED;
    }

    static boolean isFuncEnabled(String pkg) {
        refreshConfig(pkg);
        return FUNC_ENABLED;
    }

    static boolean isRuntimeScriptControlEnabled(String pkg) {
        refreshConfig(pkg);
        return DYNAMIC_ENABLED || FUNC_ENABLED;
    }

    static boolean shouldDumpDynamic(String pkg) {
        refreshConfig(pkg);
        return DYNAMIC_ENABLED;
    }

    static void refreshConfig(String pkg) {
        try {
            long now = System.currentTimeMillis();
            if (now - CONFIG_LAST_MS < 250L) return;

            Context c = APP_CONTEXT;
            if (c == null) c = getCurrentApplication();
            if (c == null) {
                // Normal before Application.attach. Bootstrap will call us again with a Context.
                return;
            }

            android.database.Cursor cur = null;
            boolean ok = false;
            boolean fb = false;
            boolean dyn = false;
            boolean func = false;
            String rules = "";
            try {
                cur = c.getContentResolver().query(
                        Uri.parse("content://com.iapt.client.hook/config"),
                        null, null, null, null);
                if (cur != null) {
                    while (cur.moveToNext()) {
                        String k = cur.getString(0);
                        String v = cur.getString(1);
                        if ("hook_fb_enabled".equals(k)) fb = "1".equals(v);
                        else if ("hook_dynamic_enabled".equals(k)) dyn = "1".equals(v);
                        else if ("hook_func_enabled".equals(k)) func = "1".equals(v);
                        else if ("hook_func_rules".equals(k)) rules = v == null ? "" : v;
                        ok = true;
                    }
                }
            } finally {
                try { if (cur != null) cur.close(); } catch (Throwable ignored) {}
            }

            if (ok) {
                FB_ENABLED = fb;
                DYNAMIC_ENABLED = dyn;
                FUNC_ENABLED = func;
                setFuncRulesRaw(rules);
                CONFIG_LAST_MS = now;
                log("provider config pkg=" + pkg + " fb=" + FB_ENABLED
                        + " dynamic=" + DYNAMIC_ENABLED + " func=" + FUNC_ENABLED
                        + " rules=" + copyFuncRules().size());
            } else {
                log("provider config unavailable pkg=" + pkg);
            }
        } catch(Throwable e) { log("refreshConfig failed: " + e); }
    }


    static void setFuncRulesRaw(String raw) {
        try {
            if (raw == null) raw = "";
            if (raw.equals(FUNC_RULES_RAW)) return;
            FUNC_RULES_RAW = raw;
            ArrayList parsed = parseFuncRules(raw);
            synchronized (FUNC_RULES) {
                FUNC_RULES.clear();
                FUNC_RULES.addAll(parsed);
            }
            synchronized (FUNC_HOOKED) { FUNC_HOOKED.clear(); }
        } catch(Throwable e) { log("setFuncRulesRaw failed: " + e); }
    }

    static ArrayList copyFuncRules() {
        ArrayList out = new ArrayList();
        synchronized (FUNC_RULES) { out.addAll(FUNC_RULES); }
        return out;
    }


    static boolean isIappRuntimeFile(String file) {
        if (file == null) return true;
        String x = file.toLowerCase(Locale.US);
        return x.endsWith(".iyu") || x.endsWith(".myu") || x.endsWith(".ijs") || x.endsWith(".ilua") || x.endsWith(".ijava");
    }

    static boolean isAuxTextRule(FuncRule r) {
        try {
            return r != null && ("text_delete".equals(r.mode) || "text_replace".equals(r.mode));
        } catch(Throwable e) { return false; }
    }

    static String applyAuxTextRules(String pkg, String text, ArrayList rules) {
        try {
            if (text == null || text.length() == 0 || rules == null || rules.size() == 0) return text;
            String out = text;
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (!isAuxTextRule(r)) continue;
                String from = r.method == null ? "" : r.method;
                if (from.length() == 0) continue;
                String before = out;
                if ("text_delete".equals(r.mode)) {
                    out = out.replace(from, "");
                    if (!out.equals(before)) reportIappFuncOnce(pkg, "内容删除", from, "成功", "");
                } else if ("text_replace".equals(r.mode)) {
                    String to = r.value == null ? "" : r.value;
                    out = out.replace(from, to);
                    if (!out.equals(before)) reportIappFuncOnce(pkg, "内容替换", from, "成功", to);
                }
            }
            return out;
        } catch(Throwable e) { log("applyAuxTextRules failed: " + e); return text; }
    }

    static String applyIappFuncRulesForExecutor(String pkg, String file, String text) {
        try {
            if (text == null || text.length() == 0) return text;
            if (!isFuncEnabled(pkg)) return text;
            if (!isIappRuntimeFile(file)) return text;
            ArrayList rules = copyFuncRules();
            if (rules.size() == 0) return text;
            String aux = applyAuxTextRules(pkg, text, rules);
            boolean changed = aux != null && !aux.equals(text);
            if (aux != null) text = aux;
            String[] lines = text.split("\\n", -1);
            StringBuilder out = new StringBuilder();
            for (int i=0;i<lines.length;i++) {
                String oldLine = lines[i];
                String newLine = transformIappExecutorLine(pkg, oldLine, rules);
                if (newLine == null) newLine = "";
                if (!newLine.equals(oldLine)) changed = true;
                out.append(newLine);
                if (i < lines.length - 1) out.append('\n');
            }
            return changed ? out.toString() : text;
        } catch(Throwable e) { log("applyIappFuncRulesForExecutor failed: " + e); return text; }
    }

    static String transformIappExecutorLine(String pkg, String line, ArrayList rules) {
        try {
            if (line == null) return "";
            String trim = line.trim();
            if (trim.length() == 0) return line;
            if (trim.startsWith("//") || trim.startsWith("#")) return line;
            String out = line;
            boolean blocked = false;
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r == null || r.method == null || r.method.length() == 0) continue;
                if (isAuxTextRule(r)) continue;
                if ("disable".equals(r.mode)) {
                    if (containsIappFuncCall(out, r.method)) {
                        blocked = true;
                        reportIappFuncOnce(pkg, "拦截", r.method, trim, "");
                    }
                } else if ("replace".equals(r.mode) && r.toMethod != null && r.toMethod.length() > 0) {
                    String before = out;
                    out = replaceIappFuncCallName(out, r.method, r.toMethod);
                    if (!out.equals(before)) reportIappFuncOnce(pkg, "伪造", r.method, trim, r.toMethod);
                }
            }
            if (blocked) return commentOutIappRuntimeLine(line);
            return out;
        } catch(Throwable e) { return line; }
    }

    static String commentOutIappRuntimeLine(String line) {
        try {
            if (line == null) return "//iapt_blocked";
            int i = 0;
            while (i < line.length() && Character.isWhitespace(line.charAt(i))) i++;
            return line.substring(0, i) + "//iapt_blocked " + line.substring(i);
        } catch(Throwable e) { return "//iapt_blocked"; }
    }

    static boolean looksLikeIappRuntimeCode(String s) {
        try {
            if (s == null) return false;
            String x = s.trim();
            if (x.length() == 0) return false;
            ArrayList rules = copyFuncRules();
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (isAuxTextRule(r)) {
                    if (r.method != null && r.method.length() > 0 && x.indexOf(r.method) >= 0) return true;
                    if (r.value != null && r.value.length() > 0 && x.indexOf(r.value) >= 0) return true;
                    continue;
                }
                if (r != null && r.method != null && r.method.length() > 0 && containsIappFuncCall(x, r.method)) return true;
                if (r != null && r.toMethod != null && r.toMethod.length() > 0 && containsIappFuncCall(x, r.toMethod)) return true;
            }
            // 兜底：V3/Yu 常见源码片段，避免只靠固定函数名。
            return x.indexOf("<eventItme") >= 0 || x.indexOf("tw(") >= 0 || x.indexOf("uigo(") >= 0 || x.indexOf("syso(") >= 0 || x.indexOf("ss(") >= 0;
        } catch(Throwable e) { return false; }
    }

    static String previewOneLine(String s) {
        try {
            if (s == null) return "";
            String x = s.replace('\n', ' ').replace('\r', ' ').trim();
            if (x.length() > 120) x = x.substring(0, 120) + "...";
            return x;
        } catch(Throwable e) { return ""; }
    }

    static String applyIappFuncRules(String pkg, String file, String text) {
        try {
            if (text == null || text.length() == 0) return text;
            if (!isFuncEnabled(pkg)) return text;
            if (!isIappRuntimeFile(file)) return text;
            ArrayList rules = copyFuncRules();
            if (rules.size() == 0) return text;
            String aux = applyAuxTextRules(pkg, text, rules);
            boolean changed = aux != null && !aux.equals(text);
            if (aux != null) text = aux;
            String[] lines = text.split("\\n", -1);
            StringBuilder out = new StringBuilder();
            for (int i=0;i<lines.length;i++) {
                String oldLine = lines[i];
                String newLine = transformIappLine(pkg, oldLine, rules);
                if (newLine == null) newLine = "";
                if (!newLine.equals(oldLine)) changed = true;
                out.append(newLine);
                if (i < lines.length - 1) out.append('\n');
            }
            return changed ? out.toString() : text;
        } catch(Throwable e) { log("applyIappFuncRules failed: " + e); return text; }
    }

    static String transformIappLine(String pkg, String line, ArrayList rules) {
        try {
            if (line == null) return "";
            String trim = line.trim();
            if (trim.length() == 0) return line;
            if (trim.startsWith("//") || trim.startsWith("#")) return line;

            String out = line;
            for (int i=0;i<rules.size();i++) {
                FuncRule r = (FuncRule)rules.get(i);
                if (r == null || r.method == null || r.method.length() == 0) continue;
                if (isAuxTextRule(r)) continue;
                String before = out;
                if ("disable".equals(r.mode)) {
                    out = removeIappFuncCallLine(out, r.method);
                    if (!out.equals(before)) reportIappFuncOnce(pkg, "拦截", r.method, trim, "");
                } else if ("replace".equals(r.mode) && r.toMethod != null && r.toMethod.length() > 0) {
                    out = replaceIappFuncCallName(out, r.method, r.toMethod);
                    if (!out.equals(before)) reportIappFuncOnce(pkg, "伪造", r.method, trim, r.toMethod);
                }
            }
            return out;
        } catch(Throwable e) { return line; }
    }

    static String removeIappFuncCallLine(String line, String name) {
        try {
            if (line == null || name == null || name.length() == 0) return line;
            StringBuilder sb = new StringBuilder();
            int pos = 0;
            boolean changed = false;
            while (pos < line.length()) {
                int idx = findIappFuncCall(line, name, pos);
                if (idx < 0) break;
                int end = iappCallEnd(line, idx, name);
                if (end <= idx) { pos = idx + name.length(); continue; }

                if (isStandaloneIappStatement(line, idx, end)) {
                    int removeStart = idx;
                    int removeEnd = end;
                    while (removeStart > pos && Character.isWhitespace(line.charAt(removeStart - 1))) removeStart--;
                    int t = removeEnd;
                    while (t < line.length() && Character.isWhitespace(line.charAt(t))) t++;
                    if (t < line.length() && isIappStatementSep(line.charAt(t))) removeEnd = t + 1;
                    sb.append(line.substring(pos, removeStart));
                    pos = removeEnd;
                } else {
                    // 目标调用被嵌在表达式/参数里时，不能删除整行；替成 null，避免后续源码结构被破坏。
                    sb.append(line.substring(pos, idx));
                    sb.append("null");
                    pos = end;
                }
                changed = true;
            }
            if (!changed) return line;
            sb.append(line.substring(pos));
            return cleanupIappLineAfterRemove(sb.toString());
        } catch(Throwable e) { return line; }
    }

    static String replaceIappFuncCallName(String line, String oldName, String newName) {
        try {
            if (line == null || oldName == null || newName == null || oldName.length() == 0 || newName.length() == 0) return line;
            StringBuilder sb = new StringBuilder();
            int pos = 0;
            while (pos < line.length()) {
                int idx = findIappFuncCall(line, oldName, pos);
                if (idx < 0) { sb.append(line.substring(pos)); break; }
                sb.append(line.substring(pos, idx));
                sb.append(newName);
                pos = idx + oldName.length();
            }
            return sb.toString();
        } catch(Throwable e) { return line; }
    }

    static int findIappFuncCall(String text, String name, int from) {
        try {
            if (text == null || name == null || name.length() == 0) return -1;
            int i = Math.max(0, from);
            int n = text.length();
            while (i < n) {
                char c = text.charAt(i);
                if (c == '"' || c == '\'') { i = skipQuoted(text, i); continue; }
                if (c == '/' && i + 1 < n && text.charAt(i + 1) == '/') return -1;
                if (c == name.charAt(0) && i + name.length() <= n && text.regionMatches(i, name, 0, name.length()) && isIappFuncCallAt(text, i, name)) return i;
                i++;
            }
        } catch(Throwable e) {}
        return -1;
    }

    static boolean isIappFuncCallAt(String text, int pos, String name) {
        try {
            if (text == null || name == null) return false;
            if (pos < 0 || pos + name.length() > text.length()) return false;
            if (pos > 0 && isIappNameChar(text.charAt(pos - 1))) return false;
            int end = pos + name.length();
            if (end >= text.length()) return true;
            char rc = text.charAt(end);
            if (rc == '(' || rc == '（' || isIappStatementSep(rc) || rc == ':' || rc == '{' || rc == '}') return true;
            if (Character.isWhitespace(rc)) return true;
            return false;
        } catch(Throwable e) { return false; }
    }

    static int iappCallEnd(String line, int start, String name) {
        try {
            int n = line.length();
            int p = start + name.length();
            while (p < n && Character.isWhitespace(line.charAt(p))) p++;
            if (p < n && (line.charAt(p) == '(' || line.charAt(p) == '（')) {
                int m = findMatchingParen(line, p);
                if (m >= 0) return m + 1;
                return n;
            }
            // 支持 java xxx、end、else 等空格/裸命令形式，走到语句分隔符或块边界为止。
            while (p < n) {
                char c = line.charAt(p);
                if (c == '"' || c == '\'') { p = skipQuoted(line, p); continue; }
                if (isIappStatementSep(c) || c == '{' || c == '}') break;
                p++;
            }
            return p;
        } catch(Throwable e) { return start + (name == null ? 0 : name.length()); }
    }

    static int findMatchingParen(String s, int open) {
        try {
            char oc = s.charAt(open);
            char cc = oc == '（' ? '）' : ')';
            int depth = 0;
            for (int i=open;i<s.length();i++) {
                char c = s.charAt(i);
                if (c == '"' || c == '\'') { i = skipQuoted(s, i) - 1; continue; }
                if (c == oc) depth++;
                else if (c == cc) {
                    depth--;
                    if (depth <= 0) return i;
                }
            }
        } catch(Throwable e) {}
        return -1;
    }

    static int skipQuoted(String s, int start) {
        try {
            char q = s.charAt(start);
            int i = start + 1;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == '\\') { i += 2; continue; }
                if (c == q) return i + 1;
                i++;
            }
            return s.length();
        } catch(Throwable e) { return start + 1; }
    }

    static boolean isStandaloneIappStatement(String line, int start, int end) {
        try {
            int l = start - 1;
            while (l >= 0 && Character.isWhitespace(line.charAt(l))) l--;
            boolean leftOk = l < 0 || isIappStatementSep(line.charAt(l)) || line.charAt(l) == '{' || line.charAt(l) == '}';
            int r = end;
            while (r < line.length() && Character.isWhitespace(line.charAt(r))) r++;
            boolean rightOk = r >= line.length() || isIappStatementSep(line.charAt(r)) || line.charAt(r) == '}';
            return leftOk && rightOk;
        } catch(Throwable e) { return false; }
    }

    static boolean isIappStatementSep(char c) {
        return c == ';' || c == '；' || c == '♧' || c == '☪' || c == '。';
    }

    static boolean isIappNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c >= 128;
    }

    static String cleanupIappLineAfterRemove(String s) {
        try {
            if (s == null || s.length() == 0) return s == null ? "" : s;
            String x = s;
            for (int i=0;i<4;i++) {
                x = x.replace(";;", ";").replace("；；", "；").replace("♧♧", "♧").replace("☪☪", "☪").replace("。。", "。");
                x = x.replace("{;", "{").replace("{；", "{").replace("{♧", "{").replace("{☪", "{").replace("{。", "{");
                x = x.replace(";}", "}").replace("；}", "}").replace("♧}", "}").replace("☪}", "}").replace("。}", "}");
            }
            return x;
        } catch(Throwable e) { return s; }
    }

    static boolean isFuncBoundary(String text, int pos, String name) {
        try {
            if (text == null || name == null) return false;
            if (pos < 0 || pos + name.length() > text.length()) return false;
            if (pos > 0) {
                char lc = text.charAt(pos - 1);
                if (Character.isLetterOrDigit(lc) || lc == '_' || lc >= 128) return false;
            }
            int end = pos + name.length();
            if (end >= text.length()) return true;
            char rc = text.charAt(end);
            return rc == '(' || rc == '（' || Character.isWhitespace(rc) || rc == ';' || rc == ':' || rc == '{';
        } catch(Throwable e) { return false; }
    }

    static void tryRewriteReturnedIappSource(String pkg, String sig, XC_MethodHook.MethodHookParam param) {
        try {
            Object r = param.getResult();
            if (!(r instanceof String) && !(r instanceof CharSequence)) return;
            String old = String.valueOf(r);
            if (old == null || old.length() == 0) return;
            if (!looksLikeIappSource(old)) return;
            String file = CURRENT_SCRIPT_FILE == null ? (CURRENT_EVENT_FILE == null ? (CURRENT_UI_FILE == null ? "mian.iyu" : CURRENT_UI_FILE) : CURRENT_EVENT_FILE) : CURRENT_SCRIPT_FILE;
            String fixed = applyIappFuncRules(pkg, file, old);
            if (fixed != null && !fixed.equals(old)) {
                param.setResult(fixed);
                reportFunc(pkg, "运行时", sig, "已修改返回事件");
            }
        } catch(Throwable e) { log("tryRewriteReturnedIappSource failed: " + e); }
    }

    static String iappFuncName(String trim) {
        if (trim == null) return "";
        int n = trim.length();
        int i = 0;
        while (i < n) {
            char c = trim.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c >= 128) i++;
            else break;
        }
        if (i <= 0) return "";
        String name = trim.substring(0, i);
        if (i < n) {
            char next = trim.charAt(i);
            if (!(next == '(' || Character.isWhitespace(next) || next == '{' || next == ';' || next == ':')) return "";
        }
        return name;
    }

    static String replaceIappFuncName(String trim, String oldName, String newName) {
        try {
            if (trim == null) return "";
            if (oldName == null || oldName.length() == 0) return trim;
            if (newName == null || newName.length() == 0) return trim;
            if (trim.startsWith(oldName)) return newName + trim.substring(oldName.length());
            return trim;
        } catch(Throwable e) { return trim; }
    }

    static void reportIappFuncOnce(String pkg, String action, String name, String oldLine, String toName) {
        try {
            String h = sha1(pkg + "|" + action + "|" + name + "|" + oldLine + "|" + toName);
            synchronized (FUNC_RULE_REPORTED) {
                if (FUNC_RULE_REPORTED.contains(h)) return;
                if (FUNC_RULE_REPORTED.size() > 500) FUNC_RULE_REPORTED.clear();
                FUNC_RULE_REPORTED.add(h);
            }
            String result = "成功";
            if (toName != null && toName.length() > 0) result = previewOneLine(name) + " => " + previewOneLine(toName) + "\n成功";
            reportFunc(pkg, action, "iApp运行时函数：" + previewOneLine(name), result);
        } catch(Throwable e) { log("reportIappFuncOnce failed: " + e); }
    }

    static String normalizeRuleFuncName(String raw) {
        try {
            if (raw == null) return "";
            String x = raw.trim();
            if (x.endsWith("()")) x = x.substring(0, x.length() - 2).trim();
            int p1 = x.indexOf('(');
            int p2 = x.indexOf('（');
            int p = -1;
            if (p1 >= 0 && p2 >= 0) p = Math.min(p1, p2);
            else if (p1 >= 0) p = p1;
            else if (p2 >= 0) p = p2;
            if (p > 0) x = x.substring(0, p).trim();
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<x.length();i++) {
                char c = x.charAt(i);
                if (Character.isLetterOrDigit(c) || c == '_' || c >= 128) sb.append(c);
                else break;
            }
            return sb.toString().trim();
        } catch(Throwable e) { return raw == null ? "" : raw.trim(); }
    }

    static boolean looksLikeFuncRuleClassToken(String token) {
        try {
            if (token == null) return false;
            String x = token.trim();
            if (x.length() == 0) return false;
            if (x.indexOf('.') >= 0) return true;
            return isIappAidRuntimeRuleClassToken(x);
        } catch(Throwable ignored) {}
        return false;
    }

    static String decodeRuleText(String raw) {
        try {
            if (raw == null) return "";
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<raw.length();i++) {
                char c = raw.charAt(i);
                if (c == '\\' && i + 1 < raw.length()) {
                    char n = raw.charAt(++i);
                    if (n == 'n') sb.append('\n');
                    else if (n == 'r') sb.append('\r');
                    else if (n == 't') sb.append('\t');
                    else if (n == 'p') sb.append('|');
                    else if (n == '\\') sb.append('\\');
                    else { sb.append('\\'); sb.append(n); }
                } else sb.append(c);
            }
            return sb.toString();
        } catch(Throwable e) { return raw == null ? "" : raw; }
    }

    static ArrayList parseFuncRules(String raw) {
        ArrayList out = new ArrayList();
        if (raw == null) return out;
        String[] lines = raw.split("\\n");
        for (int i=0;i<lines.length;i++) {
            String line = lines[i] == null ? "" : lines[i].trim();
            if (line.length() == 0 || line.startsWith("#") || line.startsWith("//")) continue;
            String[] p = line.split("\\|", -1);
            if (p.length < 2) continue;
            String mode = p[0].trim();
            FuncRule r = new FuncRule();
            if ("内容删除".equals(mode) || "text_delete".equalsIgnoreCase(mode)) {
                r.mode = "text_delete";
                r.method = p.length >= 2 ? decodeRuleText(p[1]) : "";
                r.raw = line;
                if (r.method != null && r.method.length() > 0) out.add(r);
            } else if ("内容替换".equals(mode) || "text_replace".equalsIgnoreCase(mode)) {
                r.mode = "text_replace";
                r.method = p.length >= 2 ? decodeRuleText(p[1]) : "";
                r.value = p.length >= 3 ? decodeRuleText(p[2]) : "";
                r.raw = line;
                if (r.method != null && r.method.length() > 0) out.add(r);
            } else if ("关闭".equals(mode) || "拦截".equals(mode) || "禁用".equals(mode) || "disable".equalsIgnoreCase(mode) || "block".equalsIgnoreCase(mode)) {
                r.mode = "disable";
                if (p.length == 2) {
                    // iApp内置函数规则：拦截|uigo
                    r.cls = "";
                    r.method = normalizeRuleFuncName(p[1]);
                    r.value = "";
                    r.raw = line;
                    if (r.method.length() > 0) out.add(r);
                } else if (p.length == 3 && looksLikeFuncRuleClassToken(p[1])) {
                    r.cls = p[1].trim();
                    r.method = normalizeRuleFuncName(p[2]);
                    r.value = "";
                    r.raw = line;
                    if (r.cls.length() > 0 && r.method.length() > 0) out.add(r);
                } else if (p.length >= 4) {
                    // 兼容旧Java方法规则：关闭|类名|方法名|返回值
                    r.cls = p[1].trim();
                    r.method = normalizeRuleFuncName(p[2]);
                    r.value = p[3].trim();
                    r.raw = line;
                    if (r.cls.length() > 0 && r.method.length() > 0) out.add(r);
                }
            } else if ("伪造".equals(mode) || "替换".equals(mode) || "replace".equalsIgnoreCase(mode) || "fake".equalsIgnoreCase(mode)) {
                r.mode = "replace";
                if (p.length == 3) {
                    // iApp内置函数规则：伪造|uigo|tw
                    r.cls = "";
                    r.method = normalizeRuleFuncName(p[1]);
                    r.toMethod = normalizeRuleFuncName(p[2]);
                    r.raw = line;
                    if (r.method.length() > 0 && r.toMethod.length() > 0) out.add(r);
                } else if (p.length == 4 && looksLikeFuncRuleClassToken(p[1])) {
                    r.cls = p[1].trim();
                    r.method = normalizeRuleFuncName(p[2]);
                    r.toCls = r.cls;
                    r.toMethod = normalizeRuleFuncName(p[3]);
                    r.raw = line;
                    if (r.cls.length() > 0 && r.method.length() > 0 && r.toMethod.length() > 0) out.add(r);
                } else if (p.length >= 5) {
                    // 兼容旧Java方法规则：伪造|原类名|原方法名|新类名|新方法名
                    r.cls = p[1].trim();
                    r.method = normalizeRuleFuncName(p[2]);
                    r.toCls = p[3].trim();
                    r.toMethod = normalizeRuleFuncName(p[4]);
                    r.raw = line;
                    if (r.cls.length() > 0 && r.method.length() > 0 && r.toCls.length() > 0 && r.toMethod.length() > 0) out.add(r);
                }
            }
        }
        return out;
    }

    static final Object FUNC_NO_RESULT = new Object();

    static Object invokeSameClassReplacement(String pkg, FuncRule rule, Method original, XC_MethodHook.MethodHookParam param) {
        try {
            if (rule == null || rule.toMethod == null || rule.toMethod.length() == 0 || original == null) return FUNC_NO_RESULT;
            Class c = original.getDeclaringClass();
            Method[] ms = c.getDeclaredMethods();
            for (int i=0;i<ms.length;i++) {
                Method m = ms[i];
                if (!rule.toMethod.equals(m.getName())) continue;
                if (shouldSkipHookMethod(m)) continue;
                Object[] args = buildReplacementArgs(m, param);
                if (args == null) continue;
                try { m.setAccessible(true); } catch(Throwable ignored) {}
                Object target = null;
                if (!Modifier.isStatic(m.getModifiers())) {
                    if (param != null && param.thisObject != null && c.isInstance(param.thisObject)) target = param.thisObject;
                    else continue;
                }
                return m.invoke(target, args);
            }
        } catch(Throwable e) { log("invokeSameClassReplacement failed: " + e); }
        return FUNC_NO_RESULT;
    }

    static Object invokeReplacement(String pkg, FuncRule rule, Method original, XC_MethodHook.MethodHookParam param) {
        try {
            ClassLoader cl = original.getDeclaringClass().getClassLoader();
            if (cl == null && APP_CONTEXT != null) cl = APP_CONTEXT.getClassLoader();
            if (cl == null) return FUNC_NO_RESULT;
            Class<?> c = cl.loadClass(rule.toCls);
            Method[] ms = c.getDeclaredMethods();
            for (int i=0;i<ms.length;i++) {
                Method m = ms[i];
                if (!rule.toMethod.equals(m.getName())) continue;
                Object[] args = buildReplacementArgs(m, param);
                if (args == null) continue;
                try { m.setAccessible(true); } catch(Throwable ignored) {}
                Object target = null;
                if (!Modifier.isStatic(m.getModifiers())) {
                    if (param != null && param.thisObject != null && c.isInstance(param.thisObject)) target = param.thisObject;
                    else continue;
                }
                return m.invoke(target, args);
            }
        } catch(Throwable e) { log("invokeReplacement failed: " + e); }
        return FUNC_NO_RESULT;
    }

    static Object[] buildReplacementArgs(Method m, XC_MethodHook.MethodHookParam param) {
        try {
            Class<?>[] ps = m.getParameterTypes();
            Object[] old = (param == null || param.args == null) ? new Object[0] : param.args;
            if (ps.length == 0) return new Object[0];
            if (ps.length != old.length) return null;
            Object[] out = new Object[ps.length];
            for (int i=0;i<ps.length;i++) {
                Object v = old[i];
                if (v == null) { out[i] = null; continue; }
                if (!box(ps[i]).isInstance(v)) return null;
                out[i] = v;
            }
            return out;
        } catch(Throwable e) { return null; }
    }

    static Class box(Class c) {
        if (c == null) return Object.class;
        if (!c.isPrimitive()) return c;
        if (c == Integer.TYPE) return Integer.class;
        if (c == Boolean.TYPE) return Boolean.class;
        if (c == Long.TYPE) return Long.class;
        if (c == Float.TYPE) return Float.class;
        if (c == Double.TYPE) return Double.class;
        if (c == Short.TYPE) return Short.class;
        if (c == Byte.TYPE) return Byte.class;
        if (c == Character.TYPE) return Character.class;
        if (c == Void.TYPE) return Void.class;
        return Object.class;
    }

    static Object parseReturnValue(String raw, Class rt) {
        try {
            if (rt == null || rt == Void.TYPE || rt == Void.class) return null;
            String v = raw == null ? "" : raw.trim();
            if ("null".equalsIgnoreCase(v)) return null;
            if (rt == Boolean.TYPE || rt == Boolean.class) return Boolean.valueOf("true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v));
            if (rt == Integer.TYPE || rt == Integer.class) return Integer.valueOf(parseIntSafe(v));
            if (rt == Long.TYPE || rt == Long.class) return Long.valueOf(parseLongSafe(v));
            if (rt == Float.TYPE || rt == Float.class) return Float.valueOf(parseFloatSafe(v));
            if (rt == Double.TYPE || rt == Double.class) return Double.valueOf(parseDoubleSafe(v));
            if (rt == Short.TYPE || rt == Short.class) return Short.valueOf((short)parseIntSafe(v));
            if (rt == Byte.TYPE || rt == Byte.class) return Byte.valueOf((byte)parseIntSafe(v));
            if (rt == Character.TYPE || rt == Character.class) return Character.valueOf(v.length() == 0 ? '\0' : v.charAt(0));
            if (rt == String.class || rt == CharSequence.class) return v;
            return null;
        } catch(Throwable e) { return null; }
    }

    static int parseIntSafe(String s) { try { return Integer.parseInt(s); } catch(Throwable e) { return 0; } }
    static long parseLongSafe(String s) { try { return Long.parseLong(s); } catch(Throwable e) { return 0L; } }
    static float parseFloatSafe(String s) { try { return Float.parseFloat(s); } catch(Throwable e) { return 0f; } }
    static double parseDoubleSafe(String s) { try { return Double.parseDouble(s); } catch(Throwable e) { return 0d; } }

    static void reportFunc(String pkg, String action, String sig, String result) {
        try {
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", "函数控制");
            cv.put("stage", "func");
            cv.put("args_json", "");
            cv.put("result_text", action + "：" + sig + "\n结果：" + (result == null ? "" : result));
            cv.put("result_b64", "");
            insert(pkg, cv);
        } catch(Throwable e) { log("reportFunc failed: " + e); }
    }

    static void reportDexKeyOnce(String pkg, Object result) {
        try {
            if (result == null) return;
            String v = valueText(result);
            if (v == null) return;
            v = v.trim();
            if (v.length() == 0 || "null".equalsIgnoreCase(v)) return;
            synchronized (FB_DEXKEY_REPORTED) {
                String key = pkg + ":" + v;
                if (FB_DEXKEY_REPORTED.contains(key)) return;
                FB_DEXKEY_REPORTED.add(key);
            }
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", "动态获取dexkey");
            cv.put("stage", "获取");
            cv.put("args_json", "");
            cv.put("result_text", v);
            cv.put("result_b64", "");
            insert(pkg, cv);
        } catch(Throwable e) { log("report dexkey failed: " + e); }
    }

    static void reportDynamicFile(String pkg, String sig, String rel, String text, String path) {
        try {
            if (rel == null || rel.length() == 0) rel = "mian.iyu";
            String r = normalizeRelPath(rel);
            if (text == null) text = "";
            String h = sha1(r + "\n" + text);
            synchronized (DYNAMIC_FILE_HASH) {
                String old = DYNAMIC_FILE_HASH.get(pkg + ":" + r);
                if (h.equals(old)) return;
                if (DYNAMIC_FILE_HASH.size() > 1200) DYNAMIC_FILE_HASH.clear();
                DYNAMIC_FILE_HASH.put(pkg + ":" + r, h);
            }
            int bytes = 0;
            try { bytes = text.getBytes("UTF-8").length; } catch(Throwable ignored) { bytes = text.length(); }
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", "动态解密");
            cv.put("stage", "dynamic");
            cv.put("args_json", "");
            cv.put("result_text", "文件：" + r + "\n大小：" + formatBytes(bytes));
            cv.put("result_b64", "");
            insert(pkg, cv);
        } catch(Throwable e) { log("report dynamic file failed: " + e); }
    }

    static String formatBytes(int n) {
        try {
            if (n < 1024) return n + " B";
            if (n < 1024 * 1024) return String.format(Locale.US, "%.1f KB", n / 1024.0);
            return String.format(Locale.US, "%.2f MB", n / 1024.0 / 1024.0);
        } catch(Throwable e) { return String.valueOf(n); }
    }

    static String bytesToText(byte[] b) {
        if (b == null || b.length < 3) return null;
        try { return new String(b, "UTF-8"); } catch(Throwable ignored) {}
        try { return new String(b, "GBK"); } catch(Throwable ignored) {}
        try { return new String(b); } catch(Throwable ignored) {}
        return null;
    }

    static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int i=0;i<d.length;i++) {
                String x = Integer.toHexString(d[i] & 0xff);
                if (x.length() == 1) sb.append('0');
                sb.append(x);
            }
            return sb.toString();
        } catch(Throwable e) { return String.valueOf(s == null ? 0 : s.hashCode()); }
    }

    static String methodSig(Method m) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(m.getDeclaringClass().getName()).append(".").append(m.getName()).append("(");
            Class<?>[] ps = m.getParameterTypes();
            for (int i=0;i<ps.length;i++) { if (i > 0) sb.append(","); sb.append(ps[i] == null ? "?" : ps[i].getName()); }
            sb.append(")");
            Class<?> rt = m.getReturnType();
            sb.append(":").append(rt == null ? "void" : rt.getName());
            if (Modifier.isStatic(m.getModifiers())) sb.append(" static");
            return sb.toString();
        } catch(Throwable e) { return String.valueOf(m); }
    }

    static void reportStatus(String pkg, String title, String detail) {
        // Quiet mode: suppress module/bootstrap/config/class-resolution diagnostics.
        // Keep only the actual dynamic-decryption success record used by the feature UI.
        if (!"动态解密".equals(title)) return;
        try {
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", "iAPT-LSP");
            cv.put("stage", "status");
            cv.put("args_json", detail == null ? "" : detail);
            cv.put("result_text", title);
            insert(pkg, cv);
        } catch(Throwable ignored) {}
    }

    static void reportCall(String pkg, String sig, String stage, Object[] args, Object result) {
        try {
            ContentValues cv = new ContentValues();
            cv.put("package_name", pkg);
            cv.put("method_name", sig);
            cv.put("stage", stage);
            cv.put("args_json", argsText(args));
            cv.put("result_text", valueText(result));
            if (result instanceof byte[]) cv.put("result_b64", Base64.encodeToString((byte[])result, Base64.NO_WRAP));
            insert(pkg, cv);
        } catch(Throwable e) { log("report call outer failed: " + e); }
    }

    static void insert(String pkg, ContentValues cv) {
        try {
            Context c = APP_CONTEXT;
            if (c == null) c = getCurrentApplication();
            if (c == null) { log("report no context pkg=" + pkg); return; }
            try {
                Intent it = new Intent("com.iapt.client.hook.EVENT");
                it.setComponent(new ComponentName(SELF, "com.iapt.client.hook.IaptHookReceiver"));
                it.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES | Intent.FLAG_RECEIVER_FOREGROUND);
                it.putExtra("package_name", pkg);
                it.putExtra("method_name", val(cv, "method_name"));
                it.putExtra("stage", val(cv, "stage"));
                it.putExtra("args_json", val(cv, "args_json"));
                it.putExtra("result_text", val(cv, "result_text"));
                it.putExtra("result_b64", val(cv, "result_b64"));
                c.sendBroadcast(it);
                log("report explicit broadcast sent pkg=" + pkg);
            } catch(Throwable e) { log("broadcast report failed: " + e); }
            try {
                Uri r = c.getContentResolver().insert(URI, cv);
                log("report provider insert pkg=" + pkg + " uri=" + r);
            } catch(Throwable e) {
                log("provider insert failed: " + e);
            }
        } catch(Throwable e) { log("report insert outer failed: " + e); }
    }

    static String val(ContentValues cv, String k) {
        try { Object o = cv.get(k); return o == null ? "" : String.valueOf(o); }
        catch(Throwable e) { return ""; }
    }

    static String argsText(Object[] args) {
        try {
            JSONArray arr = new JSONArray();
            if (args != null) for (int i=0;i<args.length;i++) arr.put(valueText(args[i]));
            return arr.toString();
        } catch(Throwable e) { return "[]"; }
    }

    static String valueText(Object v) {
        try {
            if (v == null) return "null";
            if (v instanceof byte[]) return Base64.encodeToString((byte[])v, Base64.NO_WRAP);
            if (v.getClass().isArray()) return arrayText(v);
            return String.valueOf(v);
        } catch(Throwable e) { return "?"; }
    }

    static String arrayText(Object arr) {
        try {
            int n = java.lang.reflect.Array.getLength(arr);
            JSONArray ja = new JSONArray();
            for (int i=0;i<Math.min(n, 20);i++) ja.put(valueText(java.lang.reflect.Array.get(arr, i)));
            if (n > 20) ja.put("..." + n);
            return ja.toString();
        } catch(Throwable e) { return "[]"; }
    }

    static void insertDump(String pkg, ContentValues cv) {
        try {
            Context c = APP_CONTEXT;
            if (c == null) c = getCurrentApplication();
            if (c == null) { log("dump no context pkg=" + pkg); return; }
            try { Uri r = c.getContentResolver().insert(DUMP_URI, cv); log("dump provider insert pkg=" + pkg + " uri=" + r); }
            catch(Throwable e) { log("dump provider insert failed: " + e); }
        } catch(Throwable ignored) {}
    }

    static void log(String s) {
        // Runtime diagnostics intentionally disabled in quiet mode.
    }
}
