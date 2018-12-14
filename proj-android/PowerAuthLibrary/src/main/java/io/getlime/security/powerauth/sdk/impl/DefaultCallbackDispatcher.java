package io.getlime.security.powerauth.sdk.impl;

import android.os.Handler;
import android.os.Looper;

/**
 * Default callback dispatcher dispatching all callbacks to the main thread.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class DefaultCallbackDispatcher implements ICallbackDispacher {

    private Handler mHandler = new Handler(Looper.getMainLooper());

    @Override
    public void dispatchCallback(Runnable runnable) {
        if (Looper.getMainLooper() == Looper.myLooper()) {
            // we are on the main thread
            runnable.run();
        } else {
            mHandler.post(runnable);
        }
    }
}
