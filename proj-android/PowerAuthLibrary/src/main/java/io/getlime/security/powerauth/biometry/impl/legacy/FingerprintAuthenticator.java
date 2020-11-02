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

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v4.app.FragmentManager;
import android.util.Pair;

import javax.crypto.Cipher;

import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.BiometryType;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.BiometricErrorDialogFragment;
import io.getlime.security.powerauth.biometry.impl.BiometricHelper;
import io.getlime.security.powerauth.biometry.impl.BiometricResultDispatcher;
import io.getlime.security.powerauth.biometry.impl.IBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.PrivateRequestData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code FingerprintAuthenticator} class implements {@link IBiometricAuthenticator} interface with using
 * an old {@link FingerprintManager} class.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintAuthenticator implements IBiometricAuthenticator {

    // Private properties

    private final @NonNull Context context;
    private final @NonNull FingerprintManager fingerprintManager;
    private final @NonNull IBiometricKeystore keystore;
    private byte[] alreadyProtectedKey;

    private BiometricKeyData processedBiometricKeyData;
    private boolean hasAlreadyProcessedBiometricKeyData;

    // Device construction

    /**
     * Create instance of {@link FingerprintAuthenticator}.
     *
     * @param context Android {@link Context} object.
     * @param keystore {@link IBiometricKeystore} managing biometric key.
     * @return Instance of {@link FingerprintAuthenticator} or {@code null} in case that fingerprint
     *         authentication is not supported on the system.
     */
    public static @Nullable IBiometricAuthenticator createAuthenticator(@NonNull Context context, @NonNull IBiometricKeystore keystore) {
        if (!keystore.isKeystoreReady()) {
            return null;
        }
        // Acquire FingerprintManager (API level 23 is slightly different than later SDKs)
        // This is inspired by the androidx.biometric fallback implementation.
        final FingerprintManager fingerprintManager;
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.M) {
            // Get service directly
            fingerprintManager = context.getSystemService(FingerprintManager.class);
        } else if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            // Get service only when there's FEATURE_FINGERPRINT
            fingerprintManager = context.getSystemService(FingerprintManager.class);
        } else {
            return null;
        }
        if (fingerprintManager == null) {
            return null;
        }
        // If hardware is not detected, then simply return null. The BiometricAuthentication class
        // will then use a dummy authenticator instead.
        if (!fingerprintManager.isHardwareDetected()) {
            return null;
        }
        return new FingerprintAuthenticator(context, keystore, fingerprintManager);
    }

    /**
     * Private constructor for this class.
     *
     * @param context Android {@link Context} object.
     * @param keystore {@link IBiometricKeystore} managing biometric key.
     * @param manager {@link FingerprintManager} providing fingerprint authentication.
     */
    private FingerprintAuthenticator(@NonNull Context context, @NonNull IBiometricKeystore keystore, @NonNull FingerprintManager manager) {
        this.context = context;
        this.fingerprintManager = manager;
        this.keystore = keystore;
    }


    // IBiometricAuthenticator methods

    @Override
    public boolean isAvailable() {
        return keystore.isKeystoreReady();
    }

    @Override
    public @BiometryType int getBiometryType(@NonNull Context context) {
        return fingerprintManager.isHardwareDetected() ? BiometryType.FINGERPRINT : BiometryType.NONE;
    }

    @Override
    public @BiometricStatus int canAuthenticate() {
        if (!isAvailable()) {
            return BiometricStatus.NOT_AVAILABLE;
        }
        if (!fingerprintManager.hasEnrolledFingerprints()) {
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

        // Now construct AES cipher with the biometric key, wrapped in the crypto object.
        final FingerprintManager.CryptoObject cryptoObject = wrapCipherToCryptoObject(request.getBiometricKeyEncryptor().initializeCipher(request.isForceGenerateNewKey()));
        if (cryptoObject == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Cannot create CryptoObject for biometric authentication.");
        }

        final CancellationSignal cancellationSignal = dispatcher.getCancelableTask().getCancellationSignal();

        // Prepare fingerprint dialog fragment
        final boolean shouldDisplayFingerprintDialog = !BiometricHelper.shouldHideFingerprintDialog(context);
        final FingerprintAuthenticationDialogFragment dialogFragment;
        if (shouldDisplayFingerprintDialog) {
            dialogFragment = new FingerprintAuthenticationDialogFragment.Builder(context)
                    .setTitle(request.getTitle())
                    .setDescription(request.getDescription())
                    .setDialogResources(requestData.getResources())
                    .build();
        } else {
            // Dialog fragment should not be displayed, because the device has its own overlay.
            dialogFragment = null;
        }

        final FingerprintAuthenticationHandler handler = new FingerprintAuthenticationHandler(fingerprintManager, cryptoObject, cancellationSignal, dialogFragment, new FingerprintAuthenticationHandler.ResultCallback() {
            @Override
            public void onAuthenticationSuccess(@NonNull FingerprintManager.AuthenticationResult result) {
                final Cipher cipher = result.getCryptoObject() != null ? result.getCryptoObject().getCipher() : null;
                if (cipher != null) {
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
                        final PowerAuthErrorException exception = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Failed to encrypt biometric key.");
                        showErrorDialogAfterSuccess(fragmentManager, requestData, exception);
                    }
                });
            }

            @Override
            public void onAuthenticationFailure(@NonNull PowerAuthErrorException exception) {
                if (shouldDisplayFingerprintDialog) {
                    // Fingerprint dialog was displayed, so the failure was already presented to the user.
                    // In this case it's enough just to report exception back to the application.
                    dispatcher.dispatchError(exception);
                } else {
                    // Fingerprint dialog was never displayed, so we should present a separate error
                    // dialog now to inform the user about the failure.
                    showErrorDialogFromException(fragmentManager, requestData, exception);
                }
            }

            @Override
            public void onAuthenticationCancel(boolean userCancel) {
                if (userCancel) {
                    dispatcher.dispatchUserCancel();
                }
            }

            @Override
            public @NonNull String getFallbackErrorMessage(int errorCode) {
                if (errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT || errorCode == FingerprintManager.FINGERPRINT_ERROR_LOCKOUT_PERMANENT) {
                    return context.getString(requestData.getResources().strings.errorCodeLockout);
                }
                return context.getString(requestData.getResources().strings.errorCodeGeneric);
            }
        });

        // Dismiss dialog when external cancel is requested.
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                if (dialogFragment != null) {
                    dialogFragment.dismiss();
                }
            }
        });

        if (shouldDisplayFingerprintDialog) {
            // The dialog presentation is required, so link the dialog with the handler and make it visible.
            dialogFragment.setFingerprintAuthenticationHandler(handler);
            dialogFragment.show(fragmentManager);
        } else {
            // In case that device has it's own overlay, then it's enough to just start listening
            // for the fingerprint manager's events.
            handler.startListening();
        }

        return dispatcher.getCancelableTask();
    }

    // Private methods

    /**
     * Wrap {@link Cipher} into {@link FingerprintManager.CryptoObject}.
     *
     * @param cipher A cipher object that must be wrapped.
     * @return {@link FingerprintManager.CryptoObject} created for given cipher.
     */
    private @Nullable FingerprintManager.CryptoObject wrapCipherToCryptoObject(@Nullable Cipher cipher) {
        // Wrap cipher into required crypto object
        return cipher != null ? new FingerprintManager.CryptoObject(cipher) : null;
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
     * Shows error dialog despite the fact, that biometric authentication succeeded. This might happen
     * in rare cases, when the vendor's implementation is unable to encrypt the provided biometric key.
     *
     * @param fragmentManager Fragment manager.
     * @param requestData Private request data.
     * @param exception Exception to be reported later to the operation's callback.
     */
    private void showErrorDialogAfterSuccess(
            @NonNull final FragmentManager fragmentManager,
            @NonNull final PrivateRequestData requestData,
            @NonNull final PowerAuthErrorException exception) {

        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        if (dispatcher.getCancelableTask().isCancelled()) {
            // Do nothing. Looks like the whole operation was canceled from the application.
            return;
        }

        final BiometricDialogResources resources = requestData.getResources();
        final Pair<Integer, Integer> titleDescription = BiometricHelper.getErrorDialogStringsForBiometricStatus(BiometricStatus.NOT_AVAILABLE, resources);

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(titleDescription.first)
                .setMessage(titleDescription.second)
                .setCloseButton(resources.strings.ok, resources.colors.closeButtonText)
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

    /**
     * Shows error dialog with message from provided exception.
     *
     * @param fragmentManager Fragment manager.
     * @param requestData Private request data.
     * @param exception Exception to be reported later to the operation's callback.
     */
    private void showErrorDialogFromException(
            @NonNull final FragmentManager fragmentManager,
            @NonNull final PrivateRequestData requestData,
            @NonNull final PowerAuthErrorException exception) {

        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();
        if (dispatcher.getCancelableTask().isCancelled()) {
            // Do nothing. Looks like the whole operation was canceled from the application.
            return;
        }

        final BiometricDialogResources resources = requestData.getResources();
        final Pair<Integer, Integer> titleDescription = BiometricHelper.getErrorDialogStringsForBiometricStatus(BiometricStatus.NOT_AVAILABLE, resources);
        final String errorMessage = exception.getMessage() != null ? exception.getMessage() : context.getString(titleDescription.second);

        final BiometricErrorDialogFragment dialogFragment = new BiometricErrorDialogFragment.Builder(context)
                .setTitle(titleDescription.first)
                .setMessage(errorMessage)
                .setCloseButton(resources.strings.ok, resources.colors.closeButtonText)
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
