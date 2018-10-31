/*
 * Copyright 2018 Wultra s.r.o.
 * Copyright (C) 2008 The Android Open Source Project
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

import android.os.AsyncTask;
import android.support.annotation.NonNull;

import java.util.ArrayDeque;
import java.util.concurrent.Executor;

import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;

/**
 * The {@code DefaultExecutorProvider} class implements {@link IExecutorProvider} interface.
 * The instance of this object is typically created internally in {@link io.getlime.security.powerauth.sdk.PowerAuthSDK}
 * object.
 */
public class DefaultExecutorProvider implements IExecutorProvider {

    private final Executor serialExecutor;

    public DefaultExecutorProvider() {
        this.serialExecutor = new SerialExecutor();
    }

    @NonNull
    @Override
    public Executor getSerialExecutor() {
        return serialExecutor;
    }

    @NonNull
    @Override
    public Executor getConcurrentExecutor() {
        return AsyncTask.THREAD_POOL_EXECUTOR;
    }

    /**
     * Implements serial executor which allows only one task to be executed at the same time.
     *
     * Note that the implementation is grabbed from android's private {@link AsyncTask}'s SerialExecutor.
     */
    private static class SerialExecutor implements Executor {
        final ArrayDeque<Runnable> mTasks = new ArrayDeque<Runnable>();
        Runnable mActive;

        public synchronized void execute(final Runnable r) {
            mTasks.offer(new Runnable() {
                public void run() {
                    try {
                        r.run();
                    } finally {
                        scheduleNext();
                    }
                }
            });
            if (mActive == null) {
                scheduleNext();
            }
        }

        protected synchronized void scheduleNext() {
            if ((mActive = mTasks.poll()) != null) {
                AsyncTask.THREAD_POOL_EXECUTOR.execute(mActive);
            }
        }
    }
}
