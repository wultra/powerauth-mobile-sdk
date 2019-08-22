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

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.sdk.impl.DefaultCallbackDispatcher;
import io.getlime.security.powerauth.sdk.impl.ICallbackDispatcher;
import io.getlime.security.powerauth.system.PA2Log;

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

        /**
         * Called when biometric authentication is canceled by the system.
         */
        void onAuthenticationCancel();
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
    private boolean resultIsAcquired;
    private boolean resultIsReported;
    private boolean authenticationFailedBefore;
    private FingerprintManager.AuthenticationResult resultSuccess;
    private PowerAuthErrorException resultError;


    /**
     * Construct handler with all required parameters.
     *
     * @param fingerprintManager System provided {@link FingerprintManager} that provides fingerprint authentication.
     * @param cryptoObject Crypto object containing AES cipher, configured for encryption with the biometric key.
     * @param cancellationSignal Object allowing to cancel the pending authentication.
     * @param progressListener Object implementing {@link ProgressListener}. The instance of
     *                         {@link FingerprintAuthenticationDialogFragment} is typically provided.
     * @param resultCallback Object receiving events defined in {@link ResultCallback} interface.
     */
    FingerprintAuthenticationHandler(
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
            try {
                fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
            } catch (NullPointerException ex) {
                // This looks weird, but NPE really happens on some devices, when app's activity is resuming.
                // In this case, we should catch NPE and report the cancel.
                // Discussion: https://github.com/wultra/powerauth-mobile-sdk/issues/202
                PA2Log.d("FingerprintManager crashed at exception: " + ex.getMessage());
                onAuthenticationError(FingerprintManager.FINGERPRINT_ERROR_CANCELED, "Canceled due to an internal failure.");
            }
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

        boolean isCancel = errorCode == FingerprintManager.FINGERPRINT_ERROR_CANCELED;
        boolean isLockout = errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            isCancel |= errorCode == FingerprintManager.FINGERPRINT_ERROR_USER_CANCELED;
            isLockout |= errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT_PERMANENT;
        }

        if (isCancel) {
            // Canceled by system, due to user's action. This typically happens when user
            // hit the power button and lock the device during the authentication.
            setCancelResult();
        } else {
            // Build an error exception based on the error code.
            final PowerAuthErrorException result;
            if (isLockout && authenticationFailedBefore) {
                // Too many failed attempts, we should report the "not recognized" error after all.
                // This is also reported only when authentication failed before, to prevent
                // situations when user immediately wants to authenticate, while the biometry
                // is still locked out.
                result = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotRecognized, "Biometric image was not recognized.");
            } else {
                // Other error, we can use "not available" error code, due to that other
                // errors are mostly about an internal failures.
                result = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, errString.toString());
            }
            setFailureResult(result);
        }

        // Report error to the progress listener.
        final boolean doCancel = isCancel;
        progressDispatcher.dispatchCallback(new Runnable() {
            @Override
            public void run() {
                if (progressListener != null) {
                    if (doCancel) {
                        progressListener.onAuthenticationCancel();
                    } else {
                        progressListener.onAuthenticationError(errorCode, errString);
                    }
                } else {
                    // There's no progressListener (e.g. dialog was somehow dismissed), so just
                    // report the result.
                    reportResult();
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
                } else {
                    // If progress listener is not set, then be sure that result is reported
                    // back to the application.
                    reportResult();
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
                authenticationFailedBefore = true;
                if (progressListener != null) {
                    progressListener.onAuthenticationFailed();
                }
            }
        });
    }

    /**
     * Set success result to the handler.
     * @param result Result object
     */
    private void setSuccessResult(@NonNull FingerprintManager.AuthenticationResult result) {
        synchronized (this) {
            if (!resultIsAcquired) {
                resultIsAcquired = true;
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
            if (!resultIsAcquired) {
                resultIsAcquired = true;
                resultError = exception;
            }
            stopListening();
        }
    }

    /**
     * Set cancel result to the handler.
     */
    private void setCancelResult() {
        synchronized (this) {
            resultIsAcquired = true;
            stopListening();
        }
    }

    /**
     * Report result to the {@link ResultCallback}. The result can be result object or the exception.
     */
    void reportResult() {
        synchronized (this) {
            if (!resultIsReported) {
                resultIsReported = true;
                if (resultSuccess != null) {
                    // Report success
                    resultCallback.onAuthenticationSuccess(resultSuccess);
                } else if (resultError != null) {
                    // Report failure
                    resultCallback.onAuthenticationFailure(resultError);
                } else {
                    // No result, so report the cancel.
                    resultCallback.onAuthenticationCancel(true);
                }
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
