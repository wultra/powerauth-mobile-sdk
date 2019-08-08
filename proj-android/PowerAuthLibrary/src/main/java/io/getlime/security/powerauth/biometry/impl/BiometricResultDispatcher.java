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

package io.getlime.security.powerauth.biometry.impl;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import io.getlime.security.powerauth.biometry.IBiometricAuthenticationCallback;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.sdk.impl.ICallbackDispatcher;

/**
 * The {@code BiometricResultDispatcher} class helps with dispatching result to the {@link IBiometricAuthenticationCallback}.
 * The class implementation guarantees that only one call with the result is executed.
 */
public class BiometricResultDispatcher {

    private @NonNull final IBiometricAuthenticationCallback callback;
    private @NonNull final ICallbackDispatcher callbackDispatcher;
    private @NonNull final CancelableTask cancelable;
    private @Nullable CancelableTask.OnCancelListener onCancelListener;
    private boolean isDispatched = false;

    public BiometricResultDispatcher(@NonNull final IBiometricAuthenticationCallback callback, @NonNull final ICallbackDispatcher callbackDispatcher) {
        this.callback = callback;
        this.callbackDispatcher = callbackDispatcher;
        this.cancelable = new CancelableTask(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                // This is a special case. The CancelableTask has been cancelled from the application
                // so we should report that cancel back to the application with "userCancel" equal to false.
                callbackDispatcher.dispatchCallback(new Runnable() {
                    @Override
                    public void run() {
                        if (!isDispatched) {
                            isDispatched = true;
                            // Call additional on-cancel listener first
                            if (onCancelListener != null) {
                                onCancelListener.onCancel();
                            }
                            // Now call result callback
                            callback.onBiometricDialogCancelled(false);
                        }
                    }
                });
            }
        });
    }

    /**
     * Set additional on-cancel listener for "cancel" events.
     *
     * @param onCancelListener Additional cancel listener
     */
    public void setOnCancelListener(@NonNull CancelableTask.OnCancelListener onCancelListener) {
        this.onCancelListener = onCancelListener;
    }

    /**
     * @return {@link CancelableTask} object associated to this result dispatcher.
     */
    public @NonNull CancelableTask getCancelableTask() {
        return cancelable;
    }

    /**
     * Report success to the {@link IBiometricAuthenticationCallback}.
     *
     * @param encryptedKey Key encrypted with secret biometric key.
     */
    public void dispatchSuccess(@NonNull final byte[] encryptedKey) {
        dispatch(new Runnable() {
            @Override
            public void run() {
                callback.onBiometricDialogSuccess(encryptedKey);
            }
        });
    }

    /**
     * Report that user canceled the dialog operation.
     */
    public void dispatchUserCancel() {
        dispatch(new Runnable() {
            @Override
            public void run() {
                callback.onBiometricDialogCancelled(true);
            }
        });
    }

    /**
     * Report error to the {@link IBiometricAuthenticationCallback}.
     *
     * @param code Error code to be reported
     * @param message Error message to be reported
     */
    public void dispatchError(@PowerAuthErrorCodes final int code, @NonNull final String message) {
        dispatchError(new PowerAuthErrorException(code, message));
    }

    /**
     * Report exception to the {@link IBiometricAuthenticationCallback}.
     *
     * @param exception {@link PowerAuthErrorException} to be reported
     */
    public void dispatchError(@NonNull final PowerAuthErrorException exception) {
        dispatch(new Runnable() {
            @Override
            public void run() {
                callback.onBiometricDialogFailed(exception);
            }
        });
    }

    /**
     * Execute runnable task with result on the callback dispatcher. Only one task can be executed
     * from this result dispatcher. That means that if operation has been cancelled, or some other
     * task has been already dispatched, then the method does nothing.
     *
     * @param runnable Task to be executed once
     */
    private void dispatch(@NonNull final Runnable runnable) {
        callbackDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                // Only one result can be reported back to the application.
                if (!cancelable.isCancelled() && !isDispatched) {
                    isDispatched = true;
                    runnable.run();
                }
            }
        });
    }
}