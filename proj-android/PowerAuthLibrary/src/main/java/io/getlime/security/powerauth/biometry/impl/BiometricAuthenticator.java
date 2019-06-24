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

import android.Manifest;
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
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.FingerprintDialogResources;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;

/**
 * The {@code BiometricAuthenticator} implements {@link IBiometricAuthenticator} interface with using new
 * {@link BiometricPrompt} facility. This implementation is automatically used on devices with
 * Android 9.0 and newer.
 */
@RequiresApi(api = Build.VERSION_CODES.P)
public class BiometricAuthenticator implements IBiometricAuthenticator {

    private final @NonNull Context context;
    private final @NonNull
    IBiometricKeystore keystore;
    private final @NonNull FingerprintManager legacyFingerprintManager;
    private byte[] alreadyProtectedKey;

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
            return BiometricStatus.NOT_SUPPORTED;
        }
        // TODO: Do we need to do this? This kind of permission is implicitly granted, right?
        if (context.checkSelfPermission(Manifest.permission.USE_BIOMETRIC) != PackageManager.PERMISSION_GRANTED) {
            return BiometricStatus.PERMISSION_NOT_GRANTED;
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

        // Now construct AES cipher with the biometric key, wrapped in the crypto object.
        final BiometricPrompt.CryptoObject cryptoObject = getCryptoObject(requestData.getSecretKey());
        if (cryptoObject == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Cannot create CryptoObject for biometric authentication.");
        }

        final FingerprintDialogResources resources = requestData.getResources();

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
                dialog.dismiss();
            }
        });

        // Build the prompt and do the authentication
        final BiometricPrompt prompt = builder.build();
        prompt.authenticate(cryptoObject, cancelableTask.getCancellationSignal(), context.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED) {
                    // User pressed the cancel button
                    dispatcher.dispatchUserCancel();
                } else if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) {
                    // Technically, this is not a cancel by the user, but the meaning is similar.
                    // The device is locked out, or user has been changed, so we can report this as
                    // a cancel to the application.
                    dispatcher.dispatchUserCancel();
                } else {
                    // Otherwise dispatch the error
                    dispatcher.dispatchError(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotRecognized, "Biometric authentication failure.");
                }
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
                // Do nothing...
            }

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                final Cipher cipher = result.getCryptoObject().getCipher();
                if (cipher != null) {
                    final byte[] protectedKey;
                    synchronized (this) {
                        if (alreadyProtectedKey == null) {
                            protectedKey = BiometricHelper.protectKeyWithCipher(request.getKeyToProtect(), cipher);
                            alreadyProtectedKey = protectedKey;
                        } else {
                            protectedKey = alreadyProtectedKey;
                        }
                    }
                    if (protectedKey != null) {
                        dispatcher.dispatchSuccess(protectedKey);
                        return;
                    }
                }
                dispatcher.dispatchError(PowerAuthErrorCodes.PA2ErrorCodeEncryptionError, "Failed to encrypt biometric key.");
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                // Do nothing...
            }
        });
        // Return the cancellable
        return cancelableTask;
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
        if (cipher == null) {
            return null;
        }
        // Wrap cipher into required crypto object
        return new BiometricPrompt.CryptoObject(cipher);
    }
}
