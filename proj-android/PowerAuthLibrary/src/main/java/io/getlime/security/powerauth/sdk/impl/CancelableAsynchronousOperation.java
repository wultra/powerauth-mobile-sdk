/*
 * Copyright 2018 Wultra s.r.o.
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

import android.support.annotation.NonNull;

import java.util.concurrent.Semaphore;

import io.getlime.security.powerauth.networking.interfaces.IAsyncOperation;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

/**
 * The {@code CancelableAsynchronousOperation} class allows execution of {@link IAsyncOperation}
 * on the background thread. The operation itself also implements {@link ICancelable} interface and
 * therefore the same instance is provided as parameter to the {@link IAsyncOperation#onExecution(ICancelable)}.
 *
 * @see ICancelable
 * @see IAsyncOperation
 */
public class CancelableAsynchronousOperation implements Runnable, ICancelable {

    private final @NonNull IAsyncOperation asyncOperation;
    private final Semaphore semaphore = new Semaphore(0, false);
    private boolean cancelled = false;

    /**
     * @param asyncOperation operation to be executed on the background thread.
     */
    public CancelableAsynchronousOperation(final @NonNull IAsyncOperation asyncOperation) {
        this.asyncOperation = asyncOperation;
    }

    @Override
    public void cancel() {
        // Release semaphore only for a first call
        final boolean releaseSemaphore = !cancelled;
        cancelled = true;
        if (releaseSemaphore) {
            semaphore.release();
        }
    }

    @Override
    public synchronized boolean isCancelled() {
        return cancelled;
    }

    @Override
    public void run() {
        // Check whether the operation has been already cancelled.
        if (isCancelled()) {
            return;
        }
        // Execute operation
        asyncOperation.onExecution(this);
        // And wait for cancellation signal
        try {
            semaphore.acquire();
        } catch (InterruptedException e) {
            // Do nothing...
        }
    }
}
