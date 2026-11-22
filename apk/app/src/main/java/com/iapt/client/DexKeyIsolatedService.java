package com.iapt.client;

import android.app.Application;
import android.app.Service;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import dalvik.system.DexClassLoader;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Runs the selected APK's loader/bootstrap in a separate client process, then calls f.b(). */
public final class DexKeyIsolatedService extends Service {
    public static final int MSG_RUN = 1;
    public static final int MSG_RESULT = 2;
    public static final String EXTRA_APK_FD = "apk_fd";
    public static final String EXTRA_CLASS = "class_name";
    public static final String EXTRA_METHOD = "method_name";

    private static final long MAX_APK_BYTES = 512L * 1024L * 1024L;
    private static final long MAX_NATIVE_BYTES = 192L * 1024L * 1024L;

    private volatile Thread worker;
    private volatile boolean cancelled;

    private final Messenger messenger = new Messenger(new Handler(message -> {
        if (message.what != MSG_RUN) return false;
        final Messenger reply = message.replyTo;
        final Bundle data = message.getData();
        data.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
        final ParcelFileDescriptor apkFd = data.getParcelable(EXTRA_APK_FD);
        final String className = safeName(data.getString(EXTRA_CLASS), "com.iapp.app.f");
        final String methodName = safeName(data.getString(EXTRA_METHOD), "b");
        if (apkFd == null || reply == null) {
            send(reply, false, "", "runtime-bootstrap", "missing apk file descriptor");
            return true;
        }
        worker = new Thread(() -> {
            try {
                String result = execute(apkFd, className, methodName);
                if (!cancelled) send(reply, true, result, "runtime-bootstrap", "");
            } catch (Throwable error) {
                if (!cancelled) send(reply, false, "", "runtime-bootstrap", compactError(error));
            } finally {
                try { apkFd.close(); } catch (Exception ignored) {}
                stopSelf();
            }
        }, "iapt-dexkey-runtime");
        worker.setDaemon(true);
        worker.start();
        return true;
    }));

    @Override public IBinder onBind(Intent intent) { return messenger.getBinder(); }

    @Override public void onDestroy() {
        cancelled = true;
        Thread running = worker;
        if (running != null) running.interrupt();
        super.onDestroy();
    }

    private String execute(ParcelFileDescriptor descriptor, String className, String methodName) throws Exception {
        File root = new File(getCodeCacheDir(), "iapt_dexkey_" + System.nanoTime());
        File apk = new File(root, "target.apk");
        File optimized = new File(root, "odex");
        File nativeRoot = new File(root, "lib");
        if (!root.mkdirs() && !root.isDirectory()) throw new IllegalStateException("cannot create runtime directory");
        optimized.mkdirs();
        nativeRoot.mkdirs();
        try {
            copyApk(descriptor, apk);
            ArchiveInfo archive = inspectArchive(apk, nativeRoot);
            ClassLoader parent = DexKeyIsolatedService.class.getClassLoader();
            DexClassLoader loader = new DexClassLoader(
                    apk.getAbsolutePath(), optimized.getAbsolutePath(), archive.libraryPath, parent);
            Thread.currentThread().setContextClassLoader(loader);

            Object application = null;
            Throwable last = null;
            if (archive.applicationClass.length() > 0
                    && !"android.app.Application".equals(archive.applicationClass)) {
                try { application = bootstrapApplicationOnMain(archive, loader, root); }
                catch (Throwable bootstrapError) { last = bootstrapError; }
            }
            LinkedHashSet<ClassLoader> loaders = collectLoaders(loader, application);
            for (int attempt = 0; attempt < 30 && !cancelled; attempt++) {
                try {
                    return invokeTarget(className, methodName, loaders);
                } catch (Throwable error) {
                    last = error;
                    collectThreadLoaders(loaders);
                    collectObjectLoaders(application, loaders);
                    try { Thread.sleep(100L); }
                    catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
            }
            throw new ClassNotFoundException("runtime bootstrap completed but " + className
                    + " was not restored" + (last == null ? "" : ": " + compactError(last)));
        } finally {
            deleteTree(root);
        }
    }

    private Object bootstrapApplicationOnMain(final ArchiveInfo archive, final ClassLoader loader,
                                              final File root) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) return bootstrapApplication(archive, loader, root);
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<Object> result = new AtomicReference<Object>();
        final AtomicReference<Throwable> error = new AtomicReference<Throwable>();
        new Handler(Looper.getMainLooper()).post(new Runnable(){ public void run(){
            try { result.set(bootstrapApplication(archive, loader, root)); }
            catch (Throwable failure) { error.set(failure); }
            finally { done.countDown(); }
        }});
        if (!done.await(4000L, TimeUnit.MILLISECONDS)) {
            throw new IllegalStateException("application bootstrap timeout");
        }
        Throwable failure = error.get();
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure != null) throw new RuntimeException(failure);
        return result.get();
    }

    private Object bootstrapApplication(ArchiveInfo archive, ClassLoader loader, File root) throws Exception {
        if (archive.applicationClass.length() == 0
                || "android.app.Application".equals(archive.applicationClass)) return null;
        Class<?> applicationType = Class.forName(archive.applicationClass, true, loader);
        Object instance = applicationType.getDeclaredConstructor().newInstance();
        if (!(instance instanceof Application)) return instance;

        ApplicationInfo appInfo = archive.applicationInfo == null
                ? new ApplicationInfo() : new ApplicationInfo(archive.applicationInfo);
        appInfo.packageName = archive.packageName;
        appInfo.sourceDir = archive.apkPath;
        appInfo.publicSourceDir = archive.apkPath;
        appInfo.dataDir = new File(root, "data").getAbsolutePath();
        if (archive.firstLibraryDir.length() > 0) appInfo.nativeLibraryDir = archive.firstLibraryDir;
        new File(appInfo.dataDir).mkdirs();
        Context archiveContext = new ArchiveContext(this, archive.packageName, appInfo, loader, archive.apkPath);

        Method attach = findApplicationOverride(applicationType, "attachBaseContext", Context.class);
        if (attach != null) {
            try {
                attach.setAccessible(true);
                attach.invoke(instance, archiveContext);
            } catch (Throwable ignored) {
                // Some shells finish installing their payload class loader before
                // later context/package checks fail in this foreign host process.
            }
        }
        try { ((Application) instance).onCreate(); }
        catch (Throwable ignored) {
            // Many packers finish class-loader installation in attachBaseContext and
            // then fail in normal app initialization because this is not their package.
        }
        return instance;
    }

    private static Method findApplicationOverride(Class<?> type, String name, Class<?>... args) {
        Class<?> current = type;
        while (current != null && current != Application.class && current != ContextWrapper.class) {
            try { return current.getDeclaredMethod(name, args); }
            catch (NoSuchMethodException ignored) { current = current.getSuperclass(); }
        }
        return null;
    }

    private static String invokeTarget(String className, String methodName,
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
                Object value = method.invoke(null);
                String normalized = normalize(value);
                if (normalized.length() == 0) {
                    throw new IllegalStateException("target method returned a non-numeric value");
                }
                return normalized;
            } catch (Throwable error) {
                last = error;
            }
        }
        if (last instanceof Exception) throw (Exception) last;
        throw new ClassNotFoundException(className, last);
    }

    private static LinkedHashSet<ClassLoader> collectLoaders(ClassLoader primary, Object application) {
        LinkedHashSet<ClassLoader> out = new LinkedHashSet<ClassLoader>();
        addLoader(out, primary);
        addLoader(out, Thread.currentThread().getContextClassLoader());
        if (application != null) addLoader(out, application.getClass().getClassLoader());
        collectObjectLoaders(application, out);
        collectThreadLoaders(out);
        return out;
    }

    private static void collectThreadLoaders(Set<ClassLoader> out) {
        try {
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (thread != null) addLoader(out, thread.getContextClassLoader());
            }
        } catch (Throwable ignored) {}
    }

    private static void collectObjectLoaders(Object object, Set<ClassLoader> out) {
        if (object == null) return;
        Class<?> current = object.getClass();
        int levels = 0;
        while (current != null && levels++ < 8) {
            try {
                Field[] fields = current.getDeclaredFields();
                for (Field field : fields) {
                    try {
                        if (!ClassLoader.class.isAssignableFrom(field.getType())) continue;
                        field.setAccessible(true);
                        Object owner = Modifier.isStatic(field.getModifiers()) ? null : object;
                        Object value = field.get(owner);
                        if (value instanceof ClassLoader) addLoader(out, (ClassLoader) value);
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
            current = current.getSuperclass();
        }
    }

    private static void addLoader(Set<ClassLoader> out, ClassLoader loader) {
        if (out != null && loader != null) out.add(loader);
    }

    private ArchiveInfo inspectArchive(File apk, File nativeRoot) throws Exception {
        PackageInfo packageInfo = getPackageManager().getPackageArchiveInfo(
                apk.getAbsolutePath(), PackageManager.GET_META_DATA);
        String packageName = packageInfo == null ? "" : safeText(packageInfo.packageName);
        ApplicationInfo applicationInfo = packageInfo == null ? null : packageInfo.applicationInfo;
        String applicationClass = applicationInfo == null ? "" : safeText(applicationInfo.className);
        if (applicationClass.startsWith(".") && packageName.length() > 0) {
            applicationClass = packageName + applicationClass;
        } else if (applicationClass.length() > 0 && applicationClass.indexOf('.') < 0
                && packageName.length() > 0) {
            applicationClass = packageName + "." + applicationClass;
        }
        String libraryPath = extractNativeLibraries(apk, nativeRoot);
        String firstLibraryDir = "";
        if (libraryPath.length() > 0) {
            int split = libraryPath.indexOf(File.pathSeparatorChar);
            firstLibraryDir = split < 0 ? libraryPath : libraryPath.substring(0, split);
        }
        return new ArchiveInfo(apk.getAbsolutePath(), packageName, applicationClass,
                applicationInfo, libraryPath, firstLibraryDir);
    }

    private static void copyApk(ParcelFileDescriptor descriptor, File output) throws Exception {
        InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
        FileOutputStream stream = new FileOutputStream(output);
        byte[] buffer = new byte[128 * 1024];
        long total = 0L;
        try {
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAX_APK_BYTES) throw new IllegalStateException("APK exceeds runtime size limit");
                stream.write(buffer, 0, read);
            }
        } finally {
            try { input.close(); } catch (Exception ignored) {}
            try { stream.close(); } catch (Exception ignored) {}
        }
    }

    private static String extractNativeLibraries(File apk, File root) {
        ZipFile zip = null;
        try {
            String[] supported = android.os.Build.SUPPORTED_ABIS;
            if (supported == null || supported.length == 0) return "";
            zip = new ZipFile(apk);
            ArrayList<String> paths = new ArrayList<String>();
            byte[] buffer = new byte[64 * 1024];
            long all = 0L;
            for (String abi : supported) {
                if (abi == null || abi.length() == 0) continue;
                File abiDir = new File(root, abi.replaceAll("[^A-Za-z0-9_.-]", "_"));
                boolean wrote = false;
                Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry == null || entry.isDirectory()) continue;
                    String name = entry.getName().replace('\\', '/');
                    String prefix = "lib/" + abi + "/";
                    if (!name.startsWith(prefix) || !name.toLowerCase(Locale.US).endsWith(".so")) continue;
                    String simple = name.substring(name.lastIndexOf('/') + 1);
                    if (!simple.matches("[A-Za-z0-9_.+-]{1,160}\\.so")) continue;
                    long declared = entry.getSize();
                    if (declared > 64L * 1024L * 1024L) continue;
                    if (!abiDir.exists()) abiDir.mkdirs();
                    File target = new File(abiDir, simple);
                    InputStream input = new BufferedInputStream(zip.getInputStream(entry));
                    FileOutputStream output = new FileOutputStream(target);
                    long one = 0L;
                    try {
                        int read;
                        while ((read = input.read(buffer)) != -1) {
                            one += read;
                            if (one > 64L * 1024L * 1024L || all + one > MAX_NATIVE_BYTES) {
                                throw new IllegalStateException("native library size limit");
                            }
                            output.write(buffer, 0, read);
                        }
                    } finally {
                        try { input.close(); } catch (Exception ignored) {}
                        try { output.close(); } catch (Exception ignored) {}
                    }
                    all += one;
                    wrote = true;
                }
                if (wrote) paths.add(abiDir.getAbsolutePath());
            }
            StringBuilder joined = new StringBuilder();
            for (String path : paths) {
                if (joined.length() > 0) joined.append(File.pathSeparatorChar);
                joined.append(path);
            }
            return joined.toString();
        } catch (Throwable ignored) {
            return "";
        } finally {
            try { if (zip != null) zip.close(); } catch (Exception ignored) {}
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

    private static String safeName(String value, String fallback) {
        String text = value == null ? "" : value.trim();
        return text.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,180}") ? text : fallback;
    }

    private static String safeText(String value) { return value == null ? "" : value.trim(); }

    private static String compactError(Throwable error) {
        Throwable cause = error;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        String text = cause.getClass().getSimpleName() + ": " + String.valueOf(cause.getMessage());
        text = text.replace('\r', ' ').replace('\n', ' ');
        return text.length() > 320 ? text.substring(0, 320) : text;
    }

    private static void deleteTree(File file) {
        if (file == null || !file.exists()) return;
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) for (File child : children) deleteTree(child);
        }
        try { file.delete(); } catch (Throwable ignored) {}
    }

    private static void send(Messenger reply, boolean ok, String value, String backend, String error) {
        if (reply == null) return;
        Bundle result = new Bundle();
        result.putBoolean("ok", ok);
        result.putString("value", value == null ? "" : value);
        result.putString("backend", backend == null ? "" : backend);
        result.putString("error", error == null ? "" : error);
        Message message = Message.obtain(null, MSG_RESULT);
        message.setData(result);
        try { reply.send(message); } catch (RemoteException ignored) {}
    }

    private static final class ArchiveInfo {
        final String apkPath;
        final String packageName;
        final String applicationClass;
        final ApplicationInfo applicationInfo;
        final String libraryPath;
        final String firstLibraryDir;

        ArchiveInfo(String apkPath, String packageName, String applicationClass,
                    ApplicationInfo applicationInfo, String libraryPath, String firstLibraryDir) {
            this.apkPath = apkPath;
            this.packageName = packageName;
            this.applicationClass = applicationClass;
            this.applicationInfo = applicationInfo;
            this.libraryPath = libraryPath == null ? "" : libraryPath;
            this.firstLibraryDir = firstLibraryDir == null ? "" : firstLibraryDir;
        }
    }

    private static final class ArchiveContext extends ContextWrapper {
        private final String packageName;
        private final ApplicationInfo applicationInfo;
        private final ClassLoader classLoader;
        private final String apkPath;

        ArchiveContext(Context base, String packageName, ApplicationInfo applicationInfo,
                       ClassLoader classLoader, String apkPath) {
            super(base);
            this.packageName = packageName == null || packageName.length() == 0
                    ? base.getPackageName() : packageName;
            this.applicationInfo = applicationInfo;
            this.classLoader = classLoader;
            this.apkPath = apkPath;
        }

        @Override public String getPackageName() { return packageName; }
        @Override public ApplicationInfo getApplicationInfo() { return applicationInfo; }
        @Override public ClassLoader getClassLoader() { return classLoader; }
        @Override public String getPackageCodePath() { return apkPath; }
        @Override public String getPackageResourcePath() { return apkPath; }
    }
}
