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

package io.getlime.security.powerauth.biometry.impl.legacy;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.sdk.impl.DefaultCallbackDispatcher;
import io.getlime.security.powerauth.sdk.impl.ICallbackDispatcher;

/**
 * The {@code FingerprintAuthenticationHandler} class implements a bridge between {@link FingerprintManager}
 * and fingerprint dialog that shows authentication progress, via the {@link ProgressListener} interface.
 * Once the valid result is received form the fingerprint manager, then waits for the completion
 * report from the dialog. The final result is then reported back to the {@link ResultCallback}.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
class FingerprintAuthenticationHandler extends FingerprintManager.AuthenticationCallback {

    /**
     * The {@code ResultCallback}
     */
    public interface ResultCallback {
        /**
         * Called in case that fingerprint authentication succeeded.
         * @param result Result object
         */
        void onAuthenticationSuccess(@NonNull FingerprintManager.AuthenticationResult result);

        /**
         * Called in case that fingerprint authentication failed.
         * @param exception Exception with the reported error.
         */
        void onAuthenticationFailure(@NonNull PowerAuthErrorException exception);

        /**
         * Called in case that user or system did cancel the operation.
         * @param userCancel {@code true} in case that user did cancel the operation.
         */
        void onAuthenticationCancel(boolean userCancel);
    }

    /**
     * The {@code ProgressListener} that receives UI updates during the biometric authentication.
     */
    public interface ProgressListener {
        /**
         * Called when biometric authentication failed.
         * @param errorCode Error code, provided by fingerprint manager.
         * @param errString Error message, provided by fingerprint manager.
         */
        void onAuthenticationError(int errorCode, CharSequence errString);

        /**
         * Called when biometric authentication requires user interaction, like sensor cleanup.
         * @param helpCode Help code, provided by fingerprint manager.
         * @param helpString Error message, provided by fingerprint manager.
         */
        void onAuthenticationHelp(int helpCode, CharSequence helpString);

        /**
         * Called when biometric authentication did fail. This typically happens when fingerprint
         * is not recognized.
         */
        void onAuthenticationFailed();

        /**
         * Called when biometric authentication succeeded.
         */
        void onAuthenticationSuccess();
    }

    // Parameters from constructor

    private final @NonNull FingerprintManager fingerprintManager;
    private final @NonNull FingerprintManager.CryptoObject cryptoObject;
    private final @NonNull CancellationSignal cancellationSignal;
    private final @NonNull ResultCallback resultCallback;

    private final @NonNull ICallbackDispatcher progressDispatcher;
    private @Nullable ProgressListener progressListener;

    // State

    private boolean isInProgress;
    private boolean isInExit;
    private boolean resultIsReported;
    private FingerprintManager.AuthenticationResult resultSuccess;
    private PowerAuthErrorException resultError;


    public FingerprintAuthenticationHandler(
            @NonNull FingerprintManager fingerprintManager,
            @NonNull FingerprintManager.CryptoObject cryptoObject,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull ProgressListener progressListener,
            @NonNull ResultCallback resultCallback) {
        this.fingerprintManager = fingerprintManager;
        this.cryptoObject = cryptoObject;
        this.cancellationSignal = cancellationSignal;
        this.progressListener = progressListener;
        this.resultCallback = resultCallback;
        this.progressDispatcher = new DefaultCallbackDispatcher();
    }

    /**
     * Starts authentication.
     */
    void startListening() {
        synchronized (this) {
            if (isInProgress || isInExit || cancellationSignal.isCanceled()) {
                return;
            }
            isInProgress = true;
            // Start authentication
            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
        }
    }

    /**
     * Stop listening for the fingerprint manager's events.
     */
    void stopListening() {
        synchronized (this) {
            if (!isInProgress) {
                return;
            }
            isInProgress = false;
            isInExit = true;
            // Cancel the pending authentication
            cancellationSignal.cancel();
        }
    }

    // FingerprintManager.AuthenticationCallback

    @Override
    public void onAuthenticationError(final int errorCode, final CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        progressDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                if (progressListener != null) {
                    progressListener.onAuthenticationError(errorCode, errString);
                }
            }
        });
    }

    @Override
    public void onAuthenticationHelp(final int helpCode, final CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        progressDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                if (progressListener != null) {
                    progressListener.onAuthenticationHelp(helpCode, helpString);
                }
            }
        });
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        // In case of success, keep the result and report progress to the progress callback.
        setSuccessResult(result);
        progressDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                if (progressListener != null) {
                    progressListener.onAuthenticationSuccess();
                }
            }
        });
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        progressDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                if (progressListener != null) {
                    progressListener.onAuthenticationFailed();
                }
            }
        });
    }

    /**
     * @return {@code true} if object has already the result.
     */
    private boolean hasResult() {
        return resultSuccess != null || resultError != null;
    }

    /**
     * Set success result to the handler.
     * @param result Result object
     */
    private void setSuccessResult(@NonNull FingerprintManager.AuthenticationResult result) {
        synchronized (this) {
            if (!hasResult()) {
                resultSuccess = result;
            }
            stopListening();
        }
    }

    /**
     * Set failure result to the handler.
     * @param exception Exception with the failure.
     */
    private void setFailureResult(@NonNull PowerAuthErrorException exception) {
        synchronized (this) {
            if (!hasResult()) {
                resultError = exception;
            }
            stopListening();
        }
    }

    /**
     * Report result to the {@link ResultCallback}. The result can be result object or the exception.
     */
    void reportResult() {
        synchronized (this) {
            if (hasResult() && !resultIsReported) {
                resultIsReported = true;
                if (resultSuccess != null) {
                    resultCallback.onAuthenticationSuccess(resultSuccess);
                } else {
                    resultCallback.onAuthenticationFailure(resultError);
                }
            }
            stopListening();
        }
    }

    /**
     * Report cancel to the {@link ResultCallback}.
     */
    void reportCancel() {
        synchronized (this) {
            if (!resultIsReported) {
                resultIsReported = true;
                resultCallback.onAuthenticationCancel(true);
            }
            stopListening();
        }
    }

    /**
     * Removes reference to {@link ProgressListener} and breaks possible leak, due to cyclic reference
     * between UI and SDK callbacks.
     */
    void removeProgressListener() {
        progressListener = null;
    }
}
