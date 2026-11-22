package com.iapt.client.hook;

import android.app.Application;
import android.content.Context;

import java.lang.reflect.Method;
import java.util.HashSet;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Quiet legacy-Xposed entry point.
 *
 * Runtime diagnostic/heartbeat output is intentionally disabled. The bootstrap
 * only connects Application.attach to the business hook implementation.
 */
public final class IaptXposedBootstrap implements IXposedHookLoadPackage {
    private static final String SELF = "com.iapt.client";
    private static final HashSet<String> ATTACH_HOOKED = new HashSet<String>();
    private static volatile Object delegate;

    public IaptXposedBootstrap() {}

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.packageName == null) return;
        if (!SELF.equals(lpparam.packageName)) installAttachBridge(lpparam);
        try {
            Object d = getDelegate();
            Method m = d.getClass().getMethod("handleLoadPackage", XC_LoadPackage.LoadPackageParam.class);
            m.invoke(d, lpparam);
        } catch (Throwable ignored) {}
    }

    private static Object getDelegate() throws Throwable {
        Object d = delegate;
        if (d != null) return d;
        synchronized (IaptXposedBootstrap.class) {
            d = delegate;
            if (d == null) {
                ClassLoader cl = IaptXposedBootstrap.class.getClassLoader();
                Class<?> c = Class.forName("com.iapt.client.hook.IaptHookEntry", true, cl);
                d = c.getDeclaredConstructor().newInstance();
                delegate = d;
            }
        }
        return d;
    }

    private static void installAttachBridge(final XC_LoadPackage.LoadPackageParam lpparam) {
        final String key = String.valueOf(lpparam.packageName) + "@" + String.valueOf(lpparam.processName);
        synchronized (ATTACH_HOOKED) {
            if (ATTACH_HOOKED.contains(key)) return;
            ATTACH_HOOKED.add(key);
        }
        try {
            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            XposedBridge.hookMethod(attach, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Context context = null;
                        if (param != null && param.args != null && param.args.length > 0
                                && param.args[0] instanceof Context) {
                            context = (Context) param.args[0];
                        }
                        if (context == null && param != null && param.thisObject instanceof Application) {
                            context = ((Application) param.thisObject).getApplicationContext();
                        }
                        notifyDelegateAttach(context, lpparam, "Application.attach");
                    } catch (Throwable ignored) {}
                }
            });
        } catch (Throwable ignored) {
            synchronized (ATTACH_HOOKED) { ATTACH_HOOKED.remove(key); }
        }
    }

    private static void notifyDelegateAttach(Context context,
                                             XC_LoadPackage.LoadPackageParam lpparam,
                                             String stage) {
        if (context == null || lpparam == null) return;
        try {
            Object d = getDelegate();
            Method m = d.getClass().getMethod("onBootstrapAttach",
                    XC_LoadPackage.LoadPackageParam.class, Context.class, String.class);
            m.invoke(d, lpparam, context, stage);
        } catch (Throwable ignored) {}
    }
}
