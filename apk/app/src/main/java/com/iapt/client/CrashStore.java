package com.iapt.client;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Small process-safe crash log helper. It has no dependency on the Hook code. */
public final class CrashStore {
    private static final String FILE_NAME = "iapt_core_crash.txt";

    private CrashStore() {}

    public static void install(final Context context) {
        final Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable error) {
                try {
                    write(context, "uncaught", error);
                } catch (Throwable ignored) {
                }
                if (previous != null) {
                    previous.uncaughtException(thread, error);
                } else {
                    android.os.Process.killProcess(android.os.Process.myPid());
                }
            }
        });
    }

    public static void write(Context context, String stage, Throwable error) {
        if (context == null) return;
        StringWriter buffer = new StringWriter();
        PrintWriter out = new PrintWriter(buffer);
        out.println("time=" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(new Date()));
        out.println("stage=" + (stage == null ? "unknown" : stage));
        out.println("process=" + processName());
        out.println("sdk=" + android.os.Build.VERSION.SDK_INT);
        out.println("device=" + android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL);
        out.println();
        if (error != null) error.printStackTrace(out);
        out.flush();
        writeBytes(new File(context.getFilesDir(), FILE_NAME), utf8(buffer.toString()));
    }

    public static String read(Context context) {
        if (context == null) return "";
        File file = new File(context.getFilesDir(), FILE_NAME);
        if (!file.isFile()) return "";
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = in.read(buffer)) > 0 && bytes.size() < 512 * 1024) {
                bytes.write(buffer, 0, count);
            }
            return new String(bytes.toByteArray(), "UTF-8");
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (in != null) try { in.close(); } catch (Throwable ignored) {}
        }
    }

    public static void clear(Context context) {
        if (context == null) return;
        try { new File(context.getFilesDir(), FILE_NAME).delete(); } catch (Throwable ignored) {}
    }

    private static byte[] utf8(String value) {
        try { return value.getBytes("UTF-8"); }
        catch (Throwable ignored) { return value.getBytes(); }
    }

    private static void writeBytes(File file, byte[] data) {
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file, false);
            out.write(data);
            out.flush();
        } catch (Throwable ignored) {
        } finally {
            if (out != null) try { out.close(); } catch (Throwable ignored) {}
        }
    }

    private static String processName() {
        try {
            Object value = Class.forName("android.app.ActivityThread")
                    .getDeclaredMethod("currentProcessName")
                    .invoke(null);
            return value == null ? "unknown" : String.valueOf(value);
        } catch (Throwable ignored) {
            return "pid-" + android.os.Process.myPid();
        }
    }
}
