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

package io.getlime.security.powerauth.networking.interfaces;

import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;

/**
 * The {@code IAsyncOperation} provides a simple interface for cancellable asynchronous operation,
 * executed typically on the background thread.
 *
 * @see ICancelable
 */
public interface IAsyncOperation {

    /**
     * Called when operation is going to be executed on the worker thread.
     * The implementor has following responsibilities:
     * <ul>
     *     <li>
     *         Must call {@link ICancelable#cancel()} on provided {@code cancelable} object,
     *         when its asynchronous job is done.
     *     </li>
     *     <li>
     *         Optionally, can periodically check whether {@link ICancelable#isCancelled()}
     *         returns {@code true} to check if operation has been cancelled from an external code.
     *     </li>
     * </ul>
     *
     * It doesn't matter whether the job is really an asynchronous or is executed completely inside
     * the {@code onExecution()}, the {@code cancel()} method has to be called at some point.
     * Otherwise the worker thread will be blocked indefinitely.
     *
     * @param cancelable {@link ICancelable} object, implementor must call {@link ICancelable#cancel()}
     *                   after the operation is completed.
     */
    @WorkerThread
    void onExecution(@NonNull final ICancelable cancelable);
}
