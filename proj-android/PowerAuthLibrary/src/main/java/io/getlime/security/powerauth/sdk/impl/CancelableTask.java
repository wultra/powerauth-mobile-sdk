/*
 * Copyright 2019 Wultra s.r.o.
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

import android.os.CancellationSignal;
import androidx.annotation.NonNull;

import io.getlime.security.powerauth.networking.interfaces.ICancelable;

/**
 * The {@code CancelableTask} class provides a simple implementation of {@link ICancelable} interface
 * that allows call optional listener, when {@link #cancel()} method is invoked.
 */
public class CancelableTask implements ICancelable {

    /**
     * Contains true if this task has been canceled.
     */
    private boolean isCancelled;

    /**
     * Contains an optional listener. If set, then the listener will be informed about the task
     * cancellation.
     */
    private final OnCancelListener onCancelListener;

    /**
     * Contains an optional {@link CancellationSignal} object which will be informed about the
     * task cancellation. The value is lazily assigned in {@link #getCancellationSignal()} method.
     */
    private CancellationSignal cancellationSignal;


    /**
     * Listens for cancellation.
     */
    public interface OnCancelListener {
        /**
         * Called when {@link CancelableTask#cancel} is invoked.
         */
        void onCancel();
    }

    /**
     * Create {@code CancelableTask} with associated on-cancel listener.
     *
     * @param listener {@link OnCancelListener} to be called when {@link #cancel()} method is invoked.
     */
    public CancelableTask(@NonNull final OnCancelListener listener) {
        onCancelListener = listener;
    }

    /**
     * Create {@code CancelableTask} with no on-cancel listener.
     */
    public CancelableTask() {
        onCancelListener = null;
    }

    /**
     * Returns {@link CancellationSignal} associated with this cancelable task.
     *
     * The purpose of this method is to provide such signalling object for the system interfaces,
     * which requires this kind of cancel handling. The instance of signal is lazily created on the
     * first method call. You should not call {@code cancel()} method on the signal itself. If you
     * do such thing, then the {@link CancelableTask} owning the signal will not be informed
     * about the operation cancel.
     *
     * @return {@link CancellationSignal} associated with this cancelable task.
     */
    public CancellationSignal getCancellationSignal() {
        synchronized (this) {
            if (cancellationSignal == null) {
                cancellationSignal = new CancellationSignal();
            }
            return cancellationSignal;
        }
    }

    // ICancelable implementation

    @Override
    public void cancel() {
        CancellationSignal signal;
        OnCancelListener listener;
        synchronized (this) {
            if (isCancelled) {
                return;
            }
            isCancelled = true;
            signal = cancellationSignal;
            listener = onCancelListener;
        }
        if (signal != null) {
            signal.cancel();
        }
        if (listener != null) {
            listener.onCancel();
        }
    }

    @Override
    public boolean isCancelled() {
        synchronized (this) {
            return isCancelled;
        }
    }
}
