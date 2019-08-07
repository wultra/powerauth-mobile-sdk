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

import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v4.app.FragmentManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.sdk.impl.CompositeCancelableTask;

/**
 * The {@code BiometricAuthenticator} implements {@link IBiometricAuthenticator} interface with using new
 * {@link BiometricPrompt} facility. This implementation is automatically used on devices with
 * Android 9.0 and newer.
 */
@RequiresApi(api = Build.VERSION_CODES.P)
public class BiometricAuthenticator implements IBiometricAuthenticator {

    private final @NonNull Context context;
    private final @NonNull IBiometricKeystore keystore;
    private final @NonNull FingerprintManager legacyFingerprintManager;
    private byte[] alreadyProtectedKey;
    private boolean authenticationFailedBefore;

    /**
     * Creates a new instance of {@link BiometricAuthenticator}. The authenticator object is not created when
     * biometric hardware is not present on the device.
     *
     * @param context Android {@link Context} object
     * @param keystore Object implementing {@link IBiometricKeystore} which will manage lifetime of the biometric key.
     * @return {@link BiometricAuthenticator} or {@code null} in case that biometry is not supported on the device.
     */
    public static @Nullable IBiometricAuthenticator createAuthenticator(final Context context, IBiometricKeystore keystore) {
        if (!keystore.isKeystoreReady()) {
            return null;
        }
        if (!context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return null;
        }
        final FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        if (fingerprintManager == null) {
            return null;
        }
        return new BiometricAuthenticator(context, keystore, fingerprintManager);
    }

    /**
     * Construct {@link BiometricAuthenticator}. The constructor is private, so you have to use {@link #createAuthenticator(Context, IBiometricKeystore)} method
     * to get the instance of this class.
     *
     * @param keystore Object implementing {@link IBiometricKeystore} which will manage lifetime of the biometric key.
     * @param context Android {@link Context} object
     * @param legacyFingerprintManager {@link FingerprintManager} instance, which is required due to poorly designed {@link BiometricPrompt} interface.
     */
    private BiometricAuthenticator(@NonNull Context context, @NonNull IBiometricKeystore keystore, @NonNull FingerprintManager legacyFingerprintManager) {
        this.context = context;
        this.keystore = keystore;
        this.legacyFingerprintManager = legacyFingerprintManager;
    }

    // IBiometricAuthenticator methods

    @Override
    public boolean isAvailable() {
        return keystore.isKeystoreReady();
    }

    @Override
    public @BiometricStatus int canAuthenticate() {
        if (!isAvailable()) {
            return BiometricStatus.NOT_AVAILABLE;
        }
        // TODO: API level 29 will fix this with `canAuthenticate()` method.
        if (!legacyFingerprintManager.hasEnrolledFingerprints()) {
            return BiometricStatus.NOT_ENROLLED;
        }
        return BiometricStatus.OK;
    }

    @NonNull
    @Override
    public IBiometricKeystore getBiometricKeystore() {
        return keystore;
    }

    @NonNull
    @Override
    public ICancelable authenticate(@NonNull final Context context,
                                    @NonNull final FragmentManager fragmentManager,
                                    @NonNull final PrivateRequestData requestData) throws PowerAuthErrorException {
        // Get objects from request data
        final BiometricAuthenticationRequest request = requestData.getRequest();
        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        final CancelableTask cancelableTask = dispatcher.getCancelableTask();
        final CompositeCancelableTask compositeCancelableTask = new CompositeCancelableTask(true, cancelableTask);

        // Now construct AES cipher with the biometric key, wrapped in the crypto object.
        final BiometricPrompt.CryptoObject cryptoObject = getCryptoObject(requestData.getSecretKey());
        if (cryptoObject == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Cannot create CryptoObject for biometric authentication.");
        }

        final BiometricDialogResources resources = requestData.getResources();

        // Build BiometricPrompt with title & description
        final BiometricPrompt.Builder builder = new BiometricPrompt.Builder(context)
                .setTitle(request.getTitle())
                .setDescription(request.getDescription());
        // Setup optional subtitle
        final CharSequence subtitle = request.getSubtitle();
        if (subtitle != null) {
            builder.setSubtitle(subtitle);
        }
        // Setup cancel button
        builder.setNegativeButton(context.getText(resources.strings.close), context.getMainExecutor(), new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dispatcher.dispatchUserCancel();
            }
        });

        // Build the prompt and do the authentication
        final BiometricPrompt prompt = builder.build();
        prompt.authenticate(cryptoObject, cancelableTask.getCancellationSignal(), context.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int code, CharSequence errString) {
                super.onAuthenticationError(code, errString);
                if (errString == null) {
                    // Some Android devices simply doesn't provide error string at all. We should build our own message,
                    // just to do not crash on null pointer later.
                    errString = getFallbackErrorMessage(code, requestData.getResources());
                }
                final boolean isCancel = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED;
                final boolean isLockout = code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT || code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT;
                if (isCancel) {
                    // User pressed the cancel button, or authentication was canceled by the system.
                    // That may happen when user hit the power button and lock the device. We can
                    // both situations report as an user initiated cancel.
                    dispatcher.dispatchUserCancel();
                } else {
                    final PowerAuthErrorException exception;
                    if (isLockout && authenticationFailedBefore) {
                        // Too many failed attempts, we should report the "not recognized" error after all.
                        // This is also reported only when authentication failed before, to prevent
                        // situations when user immediately wants to authenticate, while the biometry
                        // is still locked out.
                        exception = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotRecognized, "Biometric image was not recognized.");
                    } else {
                        // Other error, we can use "not available" error code, due to that other
                        // errors are mostly about an internal failures.
                        exception = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, errString.toString());
                    }
                    if (shouldDisplayErrorDialog(requestData)) {
                        // The response from API was too quick. We should display our own UI.
                        showBiometricErrorDialog(errString, exception, fragmentManager, requestData, compositeCancelableTask);
                    } else {
                        // Otherwise dispatch the error.
                        dispatcher.dispatchError(exception);
                    }
                }
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
                biometricPromptIsProbablyVisible = true;
            }

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                biometricPromptIsProbablyVisible = true;
                // Acquire cipher from the result. This is a bit over-paranoid, but lets check everything
                // returned from the system.
                final Cipher cipher;
                if (result != null && result.getCryptoObject() != null) {
                    cipher = result.getCryptoObject().getCipher();
                } else {
                    cipher = null;
                }
                if (cipher != null) {
                    // Let's try to derive the final biometric key with using AES cipher.
                    final byte[] protectedKey = protectKeyWithCipher(request.getKeyToProtect(), cipher);
                    if (protectedKey != null) {
                        dispatcher.dispatchSuccess(protectedKey);
                    } else {
                        dispatcher.dispatchError(PowerAuthErrorCodes.PA2ErrorCodeEncryptionError, "Failed to encrypt biometric key.");
                    }
                } else {
                    dispatcher.dispatchError(PowerAuthErrorCodes.PA2ErrorCodeEncryptionError, "The device has broken biometric implementation.");
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                biometricPromptIsProbablyVisible = true;
                authenticationFailedBefore = true;
            }
        });
        // Return the cancellable
        return compositeCancelableTask;
    }

    /**
     * Construct an AES cipher with given secret key and return that cipher wrapped into {@link BiometricPrompt.CryptoObject}.
     *
     * @param secretKey A secret key that be used to AES cipher.
     * @return {@link BiometricPrompt.CryptoObject} created for AES cipher with given key or {@code null}
     *         in case of failure.
     */
    private @Nullable BiometricPrompt.CryptoObject getCryptoObject(@Nullable SecretKey secretKey) {
        // Test whether the key is null
        if (secretKey == null) {
            return null;
        }
        // Create AES cipher with given key
        final Cipher cipher = BiometricHelper.createAesCipher(secretKey);
        // Wrap cipher into required crypto object
        return cipher != null ? new BiometricPrompt.CryptoObject(cipher) : null;
    }

    /**
     * Protect key with Cipher initialized with the biometric key.
     *
     * @param keyToProtect Key which will be encrypted with biometric key.
     * @param cipher Cipher initialized with the biometric key.
     * @return Encrypted bytes or {@code null} in case that encryption fails.
     */
    private @Nullable byte[] protectKeyWithCipher(@NonNull byte[] keyToProtect, @Nullable Cipher cipher) {
        if (cipher == null) {
            return null;
        }
        synchronized (this) {
            if (alreadyProtectedKey == null) {
                alreadyProtectedKey = BiometricHelper.protectKeyWithCipher(keyToProtect, cipher);
                if (alreadyProtectedKey == null) {
                    // Failed to encrypt provided key. Allocating array with zero bytes we indicate
                    // that an attempt to encrypt key failed with the error.
                    alreadyProtectedKey = new byte[0];
                }
            }
            // If alreadyProtectedKey contains bytes, then return that bytes, otherwise null.
            return alreadyProtectedKey.length > 0 ? alreadyProtectedKey : null;
        }
    }

    /**
     * Property is set to {@code true} in case that there's a high probability, that biometric prompt
     * is visible on the screen.
     */
    private boolean biometricPromptIsProbablyVisible;

    /**
     * Minimum time in milliseconds that need BiometricPrompt to respond with the error.
     * Check {@link #shouldDisplayErrorDialog(PrivateRequestData)} documentation for more details.
     */
    private static final long PROMPT_API_MIN_RESPONSE_TIME = 2000;

    /**
     * Tolerance time in milliseconds to {@link #PROMPT_API_MIN_RESPONSE_TIME}.
     */
    private static final long PROMPT_API_RESPONSE_TOLERANCE = 200;

    /**
     * Determine whether we need to display our own error UI. This is required due to fact, that on
     * Android "P", we never knows whether the BiometricPrompt system UI was displayed or not.
     * It's also impossible to determine this situation in advance, for example for lock down state.
     *
     * So, the only option is to use this crappy hack with elapsed time...
     *
     * @param requestData Request data
     * @return {@code true} when custom error dialog should be displayed.
     */
    private boolean shouldDisplayErrorDialog(@NonNull PrivateRequestData requestData) {
        if (biometricPromptIsProbablyVisible) {
            // Looks like that some other callback was called before. That may indicate that dialog
            // UI was really visible.
            return false;
        }
        // Flipping this status guarantees that only one dialog will be displayed. This is prevention
        // against possible two error reports in one authentication session.
        biometricPromptIsProbablyVisible = true;

        // Get elapsed time from the request data.
        long elapsedTime = requestData.getElapsedTime();
        if (elapsedTime < PROMPT_API_RESPONSE_TOLERANCE) {
            // We're under 200ms, so the response was really quick. In this case, we should display
            // our own dialog.
            return true;
        }
        if (elapsedTime >= PROMPT_API_MIN_RESPONSE_TIME &&
                elapsedTime < PROMPT_API_MIN_RESPONSE_TIME + PROMPT_API_RESPONSE_TOLERANCE) {
            // The response time is between 2000 and 2200ms.
            // This is required due to a bug in BiometricPrompt on Android "P", where the error is always
            // reported after 2000ms, even if no prompt UI was visible.
            return true;
        }
        // Looks like that BiometricPrompt UI was really visible.
        return false;
    }

    /**
     * Show {@link BiometricErrorDialogFragment} with an appropriate error message.
     *
     * @param message Message displayed in the dialog alert.
     * @param exception Exception reported back to the application.
     * @param fragmentManager Fragment manager used to show the dialog.
     * @param requestData Object with all relevant information about the biometric authentication.
     * @param cancelable Composite cancelable object.
     */
    private void showBiometricErrorDialog(
            @NonNull CharSequence message,
            @NonNull final PowerAuthErrorException exception,
            @NonNull FragmentManager fragmentManager,
            @NonNull PrivateRequestData requestData,
            @NonNull CompositeCancelableTask cancelable) {
        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        final BiometricDialogResources resources = requestData.getResources();
        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(resources.strings.errorFingerprintDisabledTitle)
                .setMessage(message)
                .setCloseButton(resources.strings.ok, resources.colors.closeButtonText)
                .setIcon(resources.drawables.errorIcon)
                .setOnCloseListener(new BiometricErrorDialogFragment.OnCloseListener() {
                    @Override
                    public void onClose() {
                        dispatcher.dispatchError(exception);
                    }
                })
                .build();
        final CancelableTask dialogCancelable = new CancelableTask(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                dialogFragment.dismiss();
            }
        });
        cancelable.addCancelable(dialogCancelable);
        dialogFragment.show(fragmentManager, BiometricErrorDialogFragment.FRAGMENT_DEFAULT_TAG);
    }

    /**
     * Return fallback error message in case that implementation on device is broken and did not provide
     * a string with failure reason. That happens for example on Samsung S8 devices.
     *
     * @param code Error code returned from {@link BiometricPrompt} API.
     * @param resources Object with string resources.
     * @return Localized fallback string appropriate for that given error code.
     */
    private @NonNull CharSequence getFallbackErrorMessage(int code, @NonNull BiometricDialogResources resources) {
        if (code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT || code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT) {
            return context.getString(resources.strings.errorCodeLockout);
        }
        return context.getString(resources.strings.errorCodeGeneric);
    }
}
