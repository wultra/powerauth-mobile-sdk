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

import android.support.annotation.NonNull;

import java.util.ArrayList;

import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code CompositeCancelableTask} is a simple implementation of {@link ICancelable} interface
 * that delegates {@code cancel()} calls to another cancelable objects. The object can work in two
 * basic modes:
 * <ol>
 *     <li>In the "exclusive mode", allows only one other {@link ICancelable} instance to be managed
 *     by this object.</li>
 *     <li>In the "non-exclusive mode", allows multiple instances of cancelables to be managed.</li>
 * </ol>
 * The class is used internally by PowerAuth Mobile SDK.
 */
public class CompositeCancelableTask implements ICancelable {

    private final boolean exclusiveMode;
    private boolean isCancelled;
    private final ArrayList<ICancelable> cancelables;

    /**
     * Construct composite cancelable task.
     * @param exclusiveMode If {@code true}, then instance will work in the exclusive mode.
     */
    public CompositeCancelableTask(boolean exclusiveMode) {
        this.exclusiveMode = exclusiveMode;
        this.cancelables = new ArrayList<>(1);
    }

    /**
     * Construct composite cancelable task with one pre-assigned cancelable object.
     * @param exclusiveMode If {@code true}, then instance will work in the exclusive mode.
     * @param cancelable {@link ICancelable} object to be assigned from the beginning.
     */
    public CompositeCancelableTask(boolean exclusiveMode, @NonNull ICancelable cancelable) {
        this.exclusiveMode = exclusiveMode;
        this.cancelables = new ArrayList<>(1);
        this.cancelables.add(cancelable);
    }

    /**
     * Add another cancelable object. If instance is in the exclusive mode, then removes previously
     * managed cancelable object.
     *
     * @param cancelable {@link ICancelable} object to be added.
     */
    public void addCancelable(@NonNull ICancelable cancelable) {
        synchronized (this) {
            if (!isCancelled) {
                if (exclusiveMode) {
                    cancelables.clear();
                }
                cancelables.add(cancelable);
            } else {
                PA2Log.d("CompositeCancelableTask is already canceled.");
                cancelable.cancel();
            }
        }
    }

    /**
     * Remove previously added cancelable object. If no such object is managed by this instance,
     * then does nothing.
     * @param cancelable {@link ICancelable} object to be removed.
     */
    public void removeCancelable(@NonNull ICancelable cancelable) {
        synchronized (this) {
            cancelables.remove(cancelable);
        }
    }

    @Override
    public void cancel() {
        synchronized (this) {
            if (isCancelled) {
                return;
            }
            isCancelled = true;
            for (ICancelable cancelable : cancelables) {
                cancelable.cancel();
            }
        }
    }

    @Override
    public boolean isCancelled() {
        synchronized (this) {
            return isCancelled;
        }
    }
}
