package com.iapt.client;

import android.app.Activity;
import android.os.Bundle;

/** Direct launcher: opens the complete iAPT UI without an intermediate safety page. */
public final class CoreActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        CrashStore.install(this);
        try {
            IaptMain.start(this);
            CrashStore.clear(this);
        } catch (Throwable error) {
            CrashStore.write(this, "CoreActivity.onCreate", error);
            if (error instanceof RuntimeException) throw (RuntimeException)error;
            if (error instanceof Error) throw (Error)error;
            throw new RuntimeException(error);
        }
    }
}
