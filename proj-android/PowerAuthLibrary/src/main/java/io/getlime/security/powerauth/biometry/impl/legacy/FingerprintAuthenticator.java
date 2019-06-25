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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.biometry.impl.BiometricHelper;
import io.getlime.security.powerauth.biometry.impl.BiometricResultDispatcher;
import io.getlime.security.powerauth.biometry.impl.IBiometricAuthenticator;
import io.getlime.security.powerauth.biometry.impl.PrivateRequestData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.impl.CancelableTask;

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

    // Device construction

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

    @Nullable
    @Override
    public ICancelable authenticate(@NonNull final Context context,
                                    @NonNull final FragmentManager fragmentManager,
                                    @NonNull final PrivateRequestData requestData) throws PowerAuthErrorException {

        // Get objects from request data
        final BiometricAuthenticationRequest request = requestData.getRequest();
        final BiometricResultDispatcher dispatcher = requestData.getDispatcher();

        // Now construct AES cipher with the biometric key, wrapped in the crypto object.
        final FingerprintManager.CryptoObject cryptoObject = getCryptoObject(requestData.getSecretKey());
        if (cryptoObject == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Cannot create CryptoObject for biometric authentication.");
        }

        final CancellationSignal cancellationSignal = dispatcher.getCancelableTask().getCancellationSignal();

        final FingerprintAuthenticationDialogFragment dialogFragment = new FingerprintAuthenticationDialogFragment.Builder(context)
                .setTitle(request.getTitle())
                .setDescription(request.getDescription())
                .setDialogResources(requestData.getResources())
                .build();

        final FingerprintAuthenticationHandler handler = new FingerprintAuthenticationHandler(fingerprintManager, cryptoObject, cancellationSignal, dialogFragment, new FingerprintAuthenticationHandler.ResultCallback() {
            @Override
            public void onAuthenticationSuccess(@NonNull FingerprintManager.AuthenticationResult result) {
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
            public void onAuthenticationFailure(@NonNull PowerAuthErrorException exception) {
                dispatcher.dispatchError(exception);
            }

            @Override
            public void onAuthenticationCancel(boolean userCancel) {
                if (userCancel) {
                    dispatcher.dispatchUserCancel();
                }
            }
        });

        // Dismiss dialog when external cancel is requested.
        dispatcher.setOnCancelListener(new CancelableTask.OnCancelListener() {
            @Override
            public void onCancel() {
                dialogFragment.dismiss();
            }
        });

        dialogFragment.setFingerprintAuthenticationHandler(handler);
        dialogFragment.show(fragmentManager);

        return dispatcher.getCancelableTask();
    }

    // Private methods

    /**
     * Construct an AES cipher with given secret key and return that cipher wrapped into {@link FingerprintManager.CryptoObject}.
     *
     * @param secretKey A secret key that be used to AES cipher.
     * @return {@link FingerprintManager.CryptoObject} created for AES cipher with given key or {@code null}
     *         in case of failure.
     */
    private @Nullable FingerprintManager.CryptoObject getCryptoObject(@Nullable SecretKey secretKey) {
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
        return new FingerprintManager.CryptoObject(cipher);
    }
}
