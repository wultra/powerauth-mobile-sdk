package io.getlime.security.powerauth.sdk.impl;

import android.os.Looper;

/**
 * Dispatcher for callbacks for SDK public APIs.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public interface ICallbackDispacher {

    /**
     * Dispatches callback.
     *
     * @param runnable callback wrapped in a runnable to be dispatched.
     */
    void dispatchCallback(Runnable runnable);
}
