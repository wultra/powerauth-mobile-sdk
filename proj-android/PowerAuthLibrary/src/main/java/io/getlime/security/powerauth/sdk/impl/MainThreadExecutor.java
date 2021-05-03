/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.sdk.impl;

import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.Executor;

import androidx.annotation.NonNull;

/**
 * The {@code MainThreadExecutor} class implements {@link Executor} interface and executes all runnable
 * objects on the main thread. The class also implements {@link ICallbackDispatcher} interface providing
 * similar functionality. The difference between {@link #execute(Runnable)} and {@link #dispatchCallback(Runnable)}
 * is that second method, if called on the main thread, executes the runnable object immediately.
 */
public class MainThreadExecutor implements Executor, ICallbackDispatcher {

    // Singleton implementation.

    private MainThreadExecutor() {}

    private static MainThreadExecutor sInstance = null;

    /**
     * @return Shared instance of this class.
     */
    public static MainThreadExecutor getInstance() {
        synchronized (MainThreadExecutor.class) {
            if (sInstance == null) {
                sInstance = new MainThreadExecutor();
            }
            return sInstance;
        }
    }

    // Executor & ICallbackDispatcher implementation.

    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    public void execute(Runnable r) {
        handler.post(r);
    }

    @Override
    public void dispatchCallback(@NonNull Runnable runnable) {
        if (Looper.getMainLooper() == Looper.myLooper()) {
            // we are on the main thread
            runnable.run();
        } else {
            execute(runnable);
        }
    }
}
