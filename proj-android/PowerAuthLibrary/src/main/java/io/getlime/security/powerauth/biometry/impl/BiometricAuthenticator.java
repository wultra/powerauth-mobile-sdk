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
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.FragmentManager;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;

import android.text.TextUtils;
import android.util.Pair;

import javax.crypto.Cipher;

import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.BiometryType;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.sdk.impl.MainThreadExecutor;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code BiometricAuthenticator} implements {@link IBiometricAuthenticator} interface with using new
 * {@link BiometricPrompt} support library. This implementation is automatically used on devices with
 * Android 6.0 and newer.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class BiometricAuthenticator implements IBiometricAuthenticator {

    private final @NonNull Context context;
    private final @NonNull IBiometricKeystore keystore;
    private final @NonNull BiometricManager biometricManager;

    private BiometricKeyData processedBiometricKeyData;
    private boolean hasAlreadyProcessedBiometricKeyData;
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
        // Check whether the keystore can be used.
        if (!keystore.isKeystoreReady()) {
            return null;
        }
        final BiometricManager biometricManager = BiometricManager.from(context);
        // Looks like we can construct the final authenticator.
        return new BiometricAuthenticator(context, keystore, biometricManager);
    }

    /**
     * Construct {@link BiometricAuthenticator}. The constructor is private, so you have to use {@link #createAuthenticator(Context, IBiometricKeystore)} method
     * to get the instance of this class.
     *
     * @param keystore Object implementing {@link IBiometricKeystore} which will manage lifetime of the biometric key.
     * @param context Android {@link Context} object
     */
    private BiometricAuthenticator(@NonNull Context context, @NonNull IBiometricKeystore keystore, @NonNull BiometricManager biometricManager) {
        this.context = context;
        this.keystore = keystore;
        this.biometricManager = biometricManager;
    }

    // IBiometricAuthenticator methods

    @Override
    public boolean isAvailable() {
        return keystore.isKeystoreReady();
    }

    @Override
    public @BiometryType int getBiometryType(@NonNull Context context) {
        final PackageManager pm = context.getPackageManager();
        int featuresCount = 0;
        @BiometryType int biometryType = BiometryType.NONE;
        // Evaluate all currently supported biometry types.
        if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            biometryType = BiometryType.FINGERPRINT;
            featuresCount++;
        }
        if (pm.hasSystemFeature(PackageManager.FEATURE_FACE)) {
            biometryType = BiometryType.FACE;
            featuresCount++;
        }
        if (pm.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
            biometryType = BiometryType.IRIS;
            featuresCount++;
        }
        // Handle multiple features.
        return featuresCount > 1 ? BiometryType.GENERIC : biometryType;
    }

    @Override
    public @BiometricStatus int canAuthenticate() {
        if (!keystore.isKeystoreReady()) {
            return BiometricStatus.NOT_AVAILABLE;
        }
        final int status = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        switch (status) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return BiometricStatus.OK;

            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                return BiometricStatus.NOT_AVAILABLE;

            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return BiometricStatus.NOT_ENROLLED;

            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                return BiometricStatus.NOT_SUPPORTED;

            default:
                PA2Log.e("BiometricManager returned unknown status " + status);
                return BiometricStatus.NOT_SUPPORTED;
        }
    }

    @NonNull
    @Override
    public IBiometricKeystore getBiometricKeystore() {
        return keystore;
    }

    @NonNull
    @Override
    public ICancelable authenticate(@NonNull final Context context,
                                    @NonNull final PrivateRequestData requestData) throws PowerAuthErrorException {
        // Get objects from request data
        final BiometricAuthenticationRequest request = requestData.getRequest();
        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();

        // Now construct appropriate cipher with the biometric key, wrapped in the crypto object.
        final BiometricPrompt.CryptoObject cryptoObject = wrapCipherToCryptoObject(request.getBiometricKeyEncryptor().initializeCipher(request.isForceGenerateNewKey()));
        if (cryptoObject == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED, "Cannot create CryptoObject for biometric authentication.");
        }

        final BiometricDialogResources resources = requestData.getResources();

        // Build BiometricPrompt with title & description
        final BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(request.getTitle())
                .setDescription(request.getDescription());
        // Setup optional subtitle
        final CharSequence subtitle = request.getSubtitle();
        if (subtitle != null) {
            builder.setSubtitle(subtitle);
        }
        // Setup cancel button
        builder.setNegativeButtonText(context.getText(resources.strings.close));
        builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        builder.setConfirmationRequired(request.isUserConfirmationRequired());

        // Build authentication callback
        final BiometricPrompt.AuthenticationCallback authenticationCallback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                if (TextUtils.isEmpty(errString)) {
                    // Some Android devices simply doesn't provide error string at all. We should build our own message,
                    // just to do not crash on null pointer later.
                    errString = getFallbackErrorMessage(errorCode, requestData.getResources());
                }
                final boolean isCancel = errorCode == BiometricPrompt.ERROR_USER_CANCELED || errorCode == BiometricPrompt.ERROR_CANCELED ||
                                         errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON;
                final boolean isLockout = errorCode == BiometricPrompt.ERROR_LOCKOUT || errorCode == BiometricPrompt.ERROR_LOCKOUT_PERMANENT;
                if (isCancel) {
                    // User pressed the cancel button, or authentication was canceled by the system.
                    // That may happen when user hit the power button and lock the device. We can
                    // both situations report as an user initiated cancel.
                    dispatcher.dispatchUserCancel();
                } else {
                    final PowerAuthErrorException exception;
                    if (isLockout) {
                        if (authenticationFailedBefore) {
                            // Too many failed attempts, we should report the "not recognized" error after all.
                            // If `authenticationFailedBefore` is true, then it means that sensor did a multiple failed attempts
                            // in this round. So we're pretty sure that biometric authentication dialog was properly displayed.
                            exception = new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED, "Biometric image was not recognized.");
                        } else {
                            // Too many failed attempts, but no authentication dialog was displayed in this round. It looks like that
                            // the error was immediately reported back to us, so we can report "lockout" to the application.
                            exception = new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_LOCKOUT, "Too many failed attempts.");
                        }
                    } else {
                        // Other error, we can use "not available" error code, due to that other
                        // errors are mostly about an internal failures.
                        exception = new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, errString.toString());
                    }
                    if (shouldDisplayErrorDialog(requestData)) {
                        // The response from API was too quick. We should display our own UI.
                        showBiometricErrorDialog(errString, exception, requestData);
                    } else {
                        // Otherwise dispatch the error.
                        dispatcher.dispatchError(exception);
                    }
                }
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                biometricPromptIsProbablyVisible = true;
                // Acquire cipher from the result. This is a bit over-paranoid, but lets check everything
                // returned from the system.
                final Cipher cipher;
                if (result.getCryptoObject() != null) {
                    cipher = result.getCryptoObject().getCipher();
                } else {
                    cipher = null;
                }
                if (cipher != null) {
                    // Let's try to encrypt or decrypt the biometric key
                    final BiometricKeyData biometricKeyData = encryptOrDecryptRawKeyData(request);
                    if (biometricKeyData != null) {
                        dispatcher.dispatchSuccess(biometricKeyData);
                        return;
                    }
                    PA2Log.e("Failed to encrypt biometric key.");
                } else {
                    PA2Log.e("Failed to get Cipher from CryptoObject.");
                }
                // If the code ends here, it mostly means that the vendor's implementation is quite off the standard.
                // The device reports success, but we're unable to derive our cryptographic key, due to malfunction in cipher
                // or due to fact, that the previously constructed cipher is not available. The right response for this state
                // is to remove the biometric key from the keychain, show an error dialog and then, finally report "not available" state.
                dispatcher.reportBiometricKeyUnavailable();
                dispatcher.dispatchRunnable(new Runnable() {
                    @Override
                    public void run() {
                        final PowerAuthErrorException exception = new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Failed to encrypt biometric key.");
                        showErrorDialogAfterSuccess(requestData, exception);
                    }
                });
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                biometricPromptIsProbablyVisible = true;
                authenticationFailedBefore = true;
            }
        };

        // Build the prompt
        final BiometricPrompt prompt;
        if (request.getFragment() != null) {
            prompt = new BiometricPrompt(request.getFragment(), MainThreadExecutor.getInstance(), authenticationCallback);
        } else if (request.getFragmentActivity() != null) {
            prompt = new BiometricPrompt(request.getFragmentActivity(), MainThreadExecutor.getInstance(), authenticationCallback);
        } else {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Both Fragment and FragmentActivity for biometric prompt presentation are set.");
        }
        // Authenticate with the prompt
        prompt.authenticate(builder.build(), cryptoObject);
        // Handle cancel from application
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                prompt.cancelAuthentication();
            }
        });
        // Return composite cancelable object, that can handle cancel on various stages of authentication.
        return dispatcher.getCancelableTask();
    }

    /**
     * Wrap {@link Cipher} into {@link BiometricPrompt.CryptoObject}.
     *
     * @param cipher A cipher object that must be wrapped.
     * @return {@link BiometricPrompt.CryptoObject} created for given cipher.
     */
    private @Nullable BiometricPrompt.CryptoObject wrapCipherToCryptoObject(@Nullable Cipher cipher) {
        // Wrap cipher into required crypto object
        return cipher != null ? new BiometricPrompt.CryptoObject(cipher) : null;
    }

    /**
     * Encrypt or decrypt raw key data from biometric request.
     *
     * @param request Biometric request data.
     * @return Encrypted bytes or {@code null} in case that encryption fails.
     */
    private @Nullable BiometricKeyData encryptOrDecryptRawKeyData( @NonNull BiometricAuthenticationRequest request) {
        synchronized (this) {
            if (!hasAlreadyProcessedBiometricKeyData) {
                hasAlreadyProcessedBiometricKeyData = true;
                // Let's try to encrypt or decrypt the biometric key
                final byte[] rawKeyData = request.getRawKeyData();
                final IBiometricKeyEncryptor encryptor = request.getBiometricKeyEncryptor();
                if (request.isForceGenerateNewKey()) {
                    processedBiometricKeyData = encryptor.encryptBiometricKey(rawKeyData);
                } else {
                    processedBiometricKeyData = encryptor.decryptBiometricKey(rawKeyData);
                }
            }
            return processedBiometricKeyData;
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
            // our own dialog. This typically happens on Android 10s in case that biometry is
            // temporarily disabled for too many failed attempts.
            return true;
        }
        if (elapsedTime >= PROMPT_API_MIN_RESPONSE_TIME &&
                elapsedTime < PROMPT_API_MIN_RESPONSE_TIME + PROMPT_API_RESPONSE_TOLERANCE) {
            // The response time is between 2000 and 2200ms.
            // This is required due to a bug in BiometricPrompt on Android "P", where the error is always
            // reported after 2000ms, even if no prompt UI was visible.
            return true;
        }
        // Looks like that BiometricPrompt UI was really visible, so we don't need to display
        // our own dialog with error message.
        return false;
    }

    /**
     * Show {@link BiometricErrorDialogFragment} with an appropriate error message.
     *
     * @param message Message displayed in the dialog alert.
     * @param exception Exception reported back to the application.
     * @param requestData Object with all relevant information about the biometric authentication.
     */
    private void showBiometricErrorDialog(
            @NonNull CharSequence message,
            @NonNull final PowerAuthErrorException exception,
            @NonNull PrivateRequestData requestData) {
        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        if (dispatcher.getCancelableTask().isCancelled()) {
            // Do nothing. Looks like the whole operation was canceled from the application.
            return;
        }

        final BiometricDialogResources resources = requestData.getResources();
        final FragmentManager fragmentManager = requestData.getFragmentManager();

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(resources.strings.errorFingerprintDisabledTitle)
                .setMessage(message)
                .setCloseButton(resources.strings.ok)
                .setIcon(resources.drawables.errorIcon)
                .setOnCloseListener(new BiometricErrorDialogFragment.OnCloseListener() {
                    @Override
                    public void onClose() {
                        dispatcher.dispatchError(exception);
                    }
                })
                .build();
        // Handle cancel from the application. Note that this overrides the previous cancel listener.
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                dialogFragment.dismiss();
            }
        });
        dialogFragment.show(fragmentManager, BiometricErrorDialogFragment.FRAGMENT_DEFAULT_TAG);
    }

    /**
     * Return fallback error message in case that implementation on device is broken and did not provide
     * a string with failure reason. That happens for example on Samsung Galaxy S8 devices.
     *
     * @param code Error code returned from {@link BiometricPrompt} API.
     * @param resources Object with string resources.
     * @return Localized fallback string appropriate for that given error code.
     */
    private @NonNull CharSequence getFallbackErrorMessage(int code, @NonNull BiometricDialogResources resources) {
        if (code == BiometricPrompt.ERROR_LOCKOUT || code == BiometricPrompt.ERROR_LOCKOUT_PERMANENT) {
            return context.getString(resources.strings.errorCodeLockout);
        }
        return context.getString(resources.strings.errorCodeGeneric);
    }

    /**
     * Shows error dialog despite the fact, that biometric authentication succeeded. This might happen
     * in rare cases, when the vendor's implementation is unable to encrypt the provided biometric key.
     *
     * @param requestData Private request data.
     * @param exception Exception to be reported later to the operation's callback.
     */
    private void showErrorDialogAfterSuccess(
            @NonNull final PrivateRequestData requestData,
            @NonNull final PowerAuthErrorException exception) {

        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        if (dispatcher.getCancelableTask().isCancelled()) {
            // Do nothing. Looks like the whole operation was canceled from the application.
            return;
        }

        final BiometricDialogResources resources = requestData.getResources();
        final Pair<Integer, Integer> titleDescription = BiometricHelper.getErrorDialogStringsForBiometricStatus(BiometricStatus.NOT_AVAILABLE, resources);
        final FragmentManager fragmentManager = requestData.getFragmentManager();

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(titleDescription.first)
                .setMessage(titleDescription.second)
                .setCloseButton(resources.strings.ok)
                .setIcon(resources.drawables.errorIcon)
                .setOnCloseListener(new BiometricErrorDialogFragment.OnCloseListener() {
                    @Override
                    public void onClose() {
                        dispatcher.dispatchError(exception);
                    }
                })
                .build();
        // Handle cancel from the application. Note that this overrides the previous cancel listener.
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                dialogFragment.dismiss();
            }
        });

        // Show fragment
        dialogFragment.show(fragmentManager, BiometricErrorDialogFragment.FRAGMENT_DEFAULT_TAG);
    }
}
