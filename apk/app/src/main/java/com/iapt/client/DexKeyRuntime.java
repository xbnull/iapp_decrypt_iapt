package com.iapt.client;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Best-effort no-root runtime evaluation of com.iapp.app.f.b(). */
public final class DexKeyRuntime {
    private DexKeyRuntime() {}

    public static final class Result {
        public final boolean success;
        public final String value;
        public final String backend;
        public final String error;

        Result(boolean success, String value, String backend, String error) {
            this.success = success;
            this.value = value == null ? "" : value;
            this.backend = backend == null ? "" : backend;
            this.error = error == null ? "" : error;
        }
    }

    /** Lightweight check only; packed targets may restore the target class later at runtime. */
    public static final class Probe {
        public final int dexCount;
        public final boolean targetClassPresent;
        public final String targetDexEntry;
        public final String message;

        Probe(int dexCount, boolean targetClassPresent, String targetDexEntry, String message) {
            this.dexCount = Math.max(0, dexCount);
            this.targetClassPresent = targetClassPresent;
            this.targetDexEntry = targetDexEntry == null ? "" : targetDexEntry;
            this.message = message == null ? "" : message;
        }

        public static Probe failed(String message) {
            return new Probe(0, false, "", message == null ? "DEX 检查失败" : message);
        }

        public static Probe notRequired() {
            return new Probe(0, false, "", "已有精确 DexKey，不需要执行 DEX");
        }
    }

    public static Probe probe(File apk) {
        if (apk == null || !apk.isFile()) return Probe.failed("APK 文件不存在");
        ZipFile zip = null;
        try {
            zip = new ZipFile(apk);
            int dexCount = 0;
            long total = 0L;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry == null || entry.isDirectory() || !isRootDexEntry(entry.getName())) continue;
                long declared = entry.getSize();
                if (declared > 64L * 1024L * 1024L) continue;
                byte[] data = readZipEntryLimited(zip, entry, 64 * 1024 * 1024);
                total += data.length;
                if (total > 160L * 1024L * 1024L) return Probe.failed("classes*.dex 总大小超过限制");
                if (isDex(data)) dexCount++;
            }
            if (dexCount == 0) return new Probe(0, false, "", "APK 没有可启动的 classes*.dex");
            return new Probe(dexCount, false, "", "运行时将先启动 APK 壳，再解析目标类");
        } catch (Throwable error) {
            return Probe.failed(compactError(error));
        } finally {
            try { if (zip != null) zip.close(); } catch (Exception ignored) {}
        }
    }

    public static Result extract(Context context, File apk, long timeoutMs, boolean allowDalvikVm) {
        if (context == null || apk == null || !apk.isFile()) return fail("input", "APK file not found");
        Probe probe = probe(apk);
        if (probe.dexCount <= 0) return fail("runtime-preflight", probe.message);
        long budget = Math.max(2000L, Math.min(timeoutMs, 15000L));

        Result runtime = runRuntimeService(context.getApplicationContext(), apk, Math.min(budget, 10000L));
        if (runtime.success) return runtime;

        if (allowDalvikVm) {
            Result shell = runDalvikVm(context.getApplicationContext(), apk, Math.min(budget, 9000L));
            if (shell.success) return shell;
            return fail("runtime+dalvikvm", compact(runtime.error + " | " + shell.error, 420));
        }
        return runtime;
    }

    private static Result runRuntimeService(final Context context, final File apk, long timeoutMs) {
        if (Looper.myLooper() == Looper.getMainLooper()) return fail("runtime-bootstrap", "must not run on main thread");

        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<Result> result = new AtomicReference<Result>();
        final AtomicBoolean bound = new AtomicBoolean(false);
        final AtomicReference<ServiceConnection> connectionRef = new AtomicReference<ServiceConnection>();
        final AtomicReference<ParcelFileDescriptor> fdRef = new AtomicReference<ParcelFileDescriptor>();

        final Messenger reply = new Messenger(new Handler(Looper.getMainLooper(), message -> {
            if (message.what != DexKeyIsolatedService.MSG_RESULT) return false;
            Bundle data = message.getData();
            boolean ok = data.getBoolean("ok", false);
            result.set(new Result(ok, data.getString("value", ""),
                    data.getString("backend", "runtime-bootstrap"), data.getString("error", "")));
            done.countDown();
            return true;
        }));

        ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                try {
                    ParcelFileDescriptor fd = ParcelFileDescriptor.open(apk, ParcelFileDescriptor.MODE_READ_ONLY);
                    fdRef.set(fd);
                    Messenger remote = new Messenger(service);
                    Message request = Message.obtain(null, DexKeyIsolatedService.MSG_RUN);
                    Bundle data = new Bundle();
                    data.putParcelable(DexKeyIsolatedService.EXTRA_APK_FD, fd);
                    data.putString(DexKeyIsolatedService.EXTRA_CLASS, "com.iapp.app.f");
                    data.putString(DexKeyIsolatedService.EXTRA_METHOD, "b");
                    request.setData(data);
                    request.replyTo = reply;
                    remote.send(request);
                    try { fd.close(); } catch (Exception ignored) {}
                    fdRef.set(null);
                } catch (Throwable error) {
                    result.set(fail("runtime-bootstrap", compactError(error)));
                    done.countDown();
                }
            }

            @Override public void onServiceDisconnected(ComponentName name) {
                if (result.get() == null) {
                    result.set(fail("runtime-bootstrap", "runtime process disconnected"));
                    done.countDown();
                }
            }

            @Override public void onBindingDied(ComponentName name) {
                if (result.get() == null) {
                    result.set(fail("runtime-bootstrap", "runtime process binding died"));
                    done.countDown();
                }
            }

            @Override public void onNullBinding(ComponentName name) {
                if (result.get() == null) {
                    result.set(fail("runtime-bootstrap", "runtime service returned null binding"));
                    done.countDown();
                }
            }
        };
        connectionRef.set(connection);

        try {
            Intent intent = new Intent(context, DexKeyIsolatedService.class);
            boolean didBind = context.bindService(intent, connection, Context.BIND_AUTO_CREATE);
            bound.set(didBind);
            if (!didBind) return fail("runtime-bootstrap", "unable to bind runtime service");
            if (!done.await(Math.max(1000L, timeoutMs), TimeUnit.MILLISECONDS)) {
                return fail("runtime-bootstrap", "timeout");
            }
            Result value = result.get();
            return value == null ? fail("runtime-bootstrap", "empty result") : value;
        } catch (Throwable error) {
            return fail("runtime-bootstrap", compactError(error));
        } finally {
            ParcelFileDescriptor fd = fdRef.getAndSet(null);
            if (fd != null) try { fd.close(); } catch (Exception ignored) {}
            if (bound.get()) {
                try { context.unbindService(connectionRef.get()); } catch (Exception ignored) {}
            }
        }
    }

    private static Result runDalvikVm(Context context, File apk, long timeoutMs) {
        File root = new File(context.getCodeCacheDir(), "iapt_dexkey_runtime/" + Long.toHexString(System.nanoTime()));
        if (!root.mkdirs() && !root.isDirectory()) return fail("dalvikvm", "cannot create runtime directory");
        StringBuilder failures = new StringBuilder();
        try {
            ApplicationInfo info = context.getApplicationInfo();
            String clientApk = info == null ? "" : info.sourceDir;
            if (clientApk == null || clientApk.length() == 0 || !new File(clientApk).isFile()) return fail("dalvikvm", "client APK path unavailable");

            String applicationClass = archiveApplicationClass(context, apk);

            List<File> executables = findDalvikExecutables();
            if (executables.isEmpty()) return fail("dalvikvm", "dalvikvm executable not available to app UID");

            for (File executable : executables) {
                String bitness = executable.getName().contains("32") ? "32" : (executable.getName().contains("64") ? "64" : "any");
                File runDir = new File(root, bitness + "_" + Math.abs(executable.getAbsolutePath().hashCode()));
                File dataDir = new File(runDir, "data");
                File libRoot = new File(runDir, "lib");
                File optimizedDir = new File(runDir, "odex");
                dataDir.mkdirs();
                libRoot.mkdirs();
                optimizedDir.mkdirs();
                String libraryPath = extractNativeLibraries(apk, libRoot, bitness);

                ArrayList<String> command = new ArrayList<String>();
                command.add(executable.getAbsolutePath());
                command.add("-Djava.io.tmpdir=" + runDir.getAbsolutePath());
                if (libraryPath.length() > 0) command.add("-Djava.library.path=" + libraryPath);
                command.add("-cp");
                command.add(clientApk);
                command.add("com.iapt.client.DexKeyCliMain");
                command.add(apk.getAbsolutePath());
                command.add(optimizedDir.getAbsolutePath());
                command.add(libraryPath);
                command.add("com.iapp.app.f");
                command.add("b");
                command.add(applicationClass);

                Process process = null;
                final StringBuilder output = new StringBuilder();
                Thread reader = null;
                try {
                    ProcessBuilder builder = new ProcessBuilder(command);
                    builder.directory(runDir);
                    builder.redirectErrorStream(true);
                    builder.environment().put("ANDROID_DATA", dataDir.getAbsolutePath());
                    builder.environment().put("TMPDIR", runDir.getAbsolutePath());
                    process = builder.start();
                    final Process p = process;
                    reader = new Thread(() -> drain(p.getInputStream(), output), "iapt-dalvikvm-output");
                    reader.setDaemon(true);
                    reader.start();
                    boolean exited = process.waitFor(Math.max(1000L, timeoutMs), TimeUnit.MILLISECONDS);
                    if (!exited) {
                        process.destroy();
                        if (!process.waitFor(250L, TimeUnit.MILLISECONDS)) process.destroyForcibly();
                        appendFailure(failures, executable.getName() + ": timeout");
                        continue;
                    }
                    if (reader != null) try { reader.join(300L); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                    String value = parseMarker(output.toString(), "IAPT_DEXKEY=");
                    if (value.length() > 0) return new Result(true, value, "dalvikvm-" + bitness, "");
                    String error = parseMarker(output.toString(), "IAPT_DEXKEY_ERROR=");
                    appendFailure(failures, executable.getName() + ": " + (error.length() > 0 ? error : compact(output.toString(), 180)));
                } catch (Throwable error) {
                    appendFailure(failures, executable.getName() + ": " + compactError(error));
                } finally {
                    if (process != null) try { process.destroyForcibly(); } catch (Throwable ignored) {}
                }
            }
            return fail("dalvikvm", failures.length() == 0 ? "all runtimes failed" : compact(failures.toString(), 420));
        } finally {
            deleteTree(root);
        }
    }

    private static String archiveApplicationClass(Context context, File apk) {
        try {
            PackageInfo info = context.getPackageManager().getPackageArchiveInfo(
                    apk.getAbsolutePath(), PackageManager.GET_META_DATA);
            if (info == null || info.applicationInfo == null) return "";
            String pkg = info.packageName == null ? "" : info.packageName.trim();
            String name = info.applicationInfo.className == null ? "" : info.applicationInfo.className.trim();
            if (name.startsWith(".") && pkg.length() > 0) return pkg + name;
            if (name.length() > 0 && name.indexOf('.') < 0 && pkg.length() > 0) return pkg + "." + name;
            return name;
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static boolean isRootDexEntry(String name) {
        if (name == null || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) return false;
        return name.matches("classes(?:[0-9]+)?\\.dex");
    }

    private static byte[] readZipEntryLimited(ZipFile zip, ZipEntry entry, int limit) throws Exception {
        InputStream input = new BufferedInputStream(zip.getInputStream(entry));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[64 * 1024];
        int total = 0;
        try {
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > limit) throw new IllegalStateException("DEX entry exceeds size limit");
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } finally {
            try { input.close(); } catch (Exception ignored) {}
        }
    }

    private static boolean isDex(byte[] data) {
        return data != null && data.length >= 8
                && data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n'
                && data[7] == 0;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length) return false;
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (haystack[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }

    private static List<File> findDalvikExecutables() {
        String[] candidates = new String[]{
                "/apex/com.android.art/bin/dalvikvm64",
                "/apex/com.android.art/bin/dalvikvm32",
                "/system/bin/dalvikvm64",
                "/system/bin/dalvikvm32",
                "/system/bin/dalvikvm"
        };
        ArrayList<File> out = new ArrayList<File>();
        Set<String> seen = new HashSet<String>();
        for (String path : candidates) {
            File file = new File(path);
            if (file.isFile() && file.canExecute() && seen.add(file.getAbsolutePath())) out.add(file);
        }
        return out;
    }

    private static String extractNativeLibraries(File apk, File root, String bitness) {
        ZipFile zip = null;
        try {
            ArrayList<String> abis = new ArrayList<String>();
            String[] supported;
            if ("32".equals(bitness)) supported = Build.SUPPORTED_32_BIT_ABIS;
            else if ("64".equals(bitness)) supported = Build.SUPPORTED_64_BIT_ABIS;
            else supported = Build.SUPPORTED_ABIS;
            if (supported != null) for (String abi : supported) if (abi != null && abi.length() > 0) abis.add(abi);
            if (abis.isEmpty()) return "";

            zip = new ZipFile(apk);
            byte[] buffer = new byte[64 * 1024];
            ArrayList<String> paths = new ArrayList<String>();
            long total = 0;
            for (String abi : abis) {
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
                    if (declared > 64L * 1024L * 1024L || total + Math.max(0L, declared) > 192L * 1024L * 1024L) continue;
                    if (!abiDir.exists()) abiDir.mkdirs();
                    File output = new File(abiDir, simple);
                    InputStream input = new BufferedInputStream(zip.getInputStream(entry));
                    FileOutputStream stream = new FileOutputStream(output);
                    long count = 0;
                    try {
                        int read;
                        while ((read = input.read(buffer)) != -1) {
                            count += read;
                            if (count > 64L * 1024L * 1024L || total + count > 192L * 1024L * 1024L) throw new IllegalStateException("native library size limit");
                            stream.write(buffer, 0, read);
                        }
                    } finally {
                        try { input.close(); } catch (Exception ignored) {}
                        try { stream.close(); } catch (Exception ignored) {}
                    }
                    total += count;
                    wrote = true;
                }
                if (wrote) paths.add(abiDir.getAbsolutePath());
            }
            StringBuilder joined = new StringBuilder();
            for (String path : paths) {
                if (joined.length() > 0) joined.append(File.pathSeparator);
                joined.append(path);
            }
            return joined.toString();
        } catch (Throwable ignored) {
            return "";
        } finally {
            try { if (zip != null) zip.close(); } catch (Exception ignored) {}
        }
    }

    private static void drain(InputStream input, StringBuilder output) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, "UTF-8"));
            char[] buffer = new char[2048];
            int read;
            while ((read = reader.read(buffer)) != -1) {
                synchronized (output) {
                    if (output.length() < 32768) output.append(buffer, 0, Math.min(read, 32768 - output.length()));
                }
            }
        } catch (Throwable ignored) {}
    }

    private static String parseMarker(String output, String marker) {
        if (output == null) return "";
        int at = output.indexOf(marker);
        if (at < 0) return "";
        int start = at + marker.length();
        int end = start;
        while (end < output.length() && output.charAt(end) != '\r' && output.charAt(end) != '\n') end++;
        String value = output.substring(start, end).trim();
        if ("IAPT_DEXKEY=".equals(marker) && !value.matches("[-+]?[0-9]{1,18}")) return "";
        return compact(value, 320);
    }

    private static void appendFailure(StringBuilder builder, String text) {
        if (builder.length() > 0) builder.append(" | ");
        builder.append(compact(text, 180));
    }

    private static Result fail(String backend, String error) { return new Result(false, "", backend, error); }

    private static String compactError(Throwable error) {
        Throwable cause = error;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        return compact(cause.getClass().getSimpleName() + ": " + String.valueOf(cause.getMessage()), 320);
    }

    private static String compact(String text, int max) {
        String value = text == null ? "" : text.replace('\r', ' ').replace('\n', ' ').trim();
        while (value.contains("  ")) value = value.replace("  ", " ");
        return value.length() > max ? value.substring(0, max) : value;
    }

    private static void deleteTree(File file) {
        if (file == null || !file.exists()) return;
        File[] children = file.listFiles();
        if (children != null) for (File child : children) deleteTree(child);
        try { file.delete(); } catch (Throwable ignored) {}
    }
}
