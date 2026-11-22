package com.iapt.client;

import android.app.Application;

import dalvik.system.DexClassLoader;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.LinkedHashSet;

/** Stand-alone ART entry point used by the optional dalvikvm fallback. */
public final class DexKeyCliMain {
    private DexKeyCliMain() {}

    public static void main(String[] args) {
        String targetApk = args != null && args.length > 0 ? args[0] : "";
        String optimizedDir = args != null && args.length > 1 ? args[1] : "";
        String libraryPath = args != null && args.length > 2 ? args[2] : "";
        String className = args != null && args.length > 3 ? args[3] : "com.iapp.app.f";
        String methodName = args != null && args.length > 4 ? args[4] : "b";
        String applicationClass = args != null && args.length > 5 ? args[5] : "";
        try {
            if (!new File(targetApk).isFile()) throw new IllegalArgumentException("target APK not found");
            File opt = new File(optimizedDir);
            if (!opt.isDirectory() && !opt.mkdirs()) throw new IllegalStateException("cannot create optimized directory");
            ClassLoader loader = new DexClassLoader(targetApk, opt.getAbsolutePath(),
                    libraryPath == null || libraryPath.length() == 0 ? null : libraryPath,
                    DexKeyCliMain.class.getClassLoader());
            Thread.currentThread().setContextClassLoader(loader);

            LinkedHashSet<ClassLoader> loaders = new LinkedHashSet<ClassLoader>();
            loaders.add(loader);
            try {
                String direct = invoke(className, methodName, loaders);
                System.out.println("IAPT_DEXKEY=" + direct);
                return;
            } catch (Throwable ignored) {}

            Object application = null;
            if (applicationClass != null && applicationClass.length() > 0
                    && !"android.app.Application".equals(applicationClass)) {
                try {
                    Class<?> applicationType = Class.forName(applicationClass, true, loader);
                    application = applicationType.getDeclaredConstructor().newInstance();
                    if (application instanceof Application) {
                        try { ((Application) application).onCreate(); } catch (Throwable ignored) {}
                    }
                } catch (Throwable ignored) {}
            }
            collect(loaders, application);
            Throwable last = null;
            for (int attempt = 0; attempt < 20; attempt++) {
                try {
                    String value = invoke(className, methodName, loaders);
                    System.out.println("IAPT_DEXKEY=" + value);
                    return;
                } catch (Throwable error) {
                    last = error;
                    collect(loaders, application);
                    try { Thread.sleep(100L); }
                    catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
            }
            throw new ClassNotFoundException("runtime bootstrap did not restore " + className, last);
        } catch (Throwable error) {
            Throwable cause = error;
            while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
            String message = cause.getClass().getName() + ":" + String.valueOf(cause.getMessage());
            message = message.replace('\r', ' ').replace('\n', ' ');
            if (message.length() > 240) message = message.substring(0, 240);
            System.out.println("IAPT_DEXKEY_ERROR=" + message);
            System.exit(3);
        }
    }

    private static String invoke(String className, String methodName,
                                 Iterable<ClassLoader> loaders) throws Exception {
        Throwable last = null;
        for (ClassLoader loader : loaders) {
            if (loader == null) continue;
            try {
                Class<?> target = Class.forName(className, true, loader);
                Method method = target.getDeclaredMethod(methodName);
                if (!Modifier.isStatic(method.getModifiers()) || method.getParameterTypes().length != 0) {
                    throw new IllegalStateException("target method must be static and have no parameters");
                }
                method.setAccessible(true);
                String value = normalize(method.invoke(null));
                if (value.length() == 0) throw new IllegalStateException("target method returned a non-numeric value");
                return value;
            } catch (Throwable error) {
                last = error;
            }
        }
        if (last instanceof Exception) throw (Exception) last;
        throw new ClassNotFoundException(className, last);
    }

    private static void collect(LinkedHashSet<ClassLoader> loaders, Object application) {
        try { loaders.add(Thread.currentThread().getContextClassLoader()); } catch (Throwable ignored) {}
        try {
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (thread != null && thread.getContextClassLoader() != null) loaders.add(thread.getContextClassLoader());
            }
        } catch (Throwable ignored) {}
        if (application == null) return;
        try { loaders.add(application.getClass().getClassLoader()); } catch (Throwable ignored) {}
        Class<?> current = application.getClass();
        int levels = 0;
        while (current != null && levels++ < 8) {
            try {
                for (Field field : current.getDeclaredFields()) {
                    try {
                        if (!ClassLoader.class.isAssignableFrom(field.getType())) continue;
                        field.setAccessible(true);
                        Object owner = Modifier.isStatic(field.getModifiers()) ? null : application;
                        Object value = field.get(owner);
                        if (value instanceof ClassLoader) loaders.add((ClassLoader) value);
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
            current = current.getSuperclass();
        }
    }

    private static String normalize(Object value) {
        if (value == null) return "";
        if (value instanceof Number) return String.valueOf(((Number) value).longValue());
        String text = String.valueOf(value).trim();
        if (!text.matches("[-+]?[0-9]{1,18}")) return "";
        try { return String.valueOf(Long.parseLong(text)); }
        catch (NumberFormatException ignored) { return ""; }
    }
}
