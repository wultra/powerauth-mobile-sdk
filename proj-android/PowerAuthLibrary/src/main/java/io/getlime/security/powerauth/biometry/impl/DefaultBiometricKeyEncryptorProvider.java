/*
 * Copyright 2021 Wultra s.r.o.
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

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code DefaultBiometricKeyEncryptorProvider} class provides a default {@link IBiometricKeyEncryptor}
 * implementation based on Android KeyStore.
 */
public class DefaultBiometricKeyEncryptorProvider implements IBiometricKeyEncryptorProvider {

    private final @NonNull BiometricAuthenticationRequest request;
    private final @NonNull IBiometricKeystore keystore;
    private IBiometricKeyEncryptor encryptor;

    /**
     * Construct object with request and keystore
     * @param request Authentication request.
     * @param keystore Keystore implementation.
     */
    public DefaultBiometricKeyEncryptorProvider(@NonNull BiometricAuthenticationRequest request, @NonNull IBiometricKeystore keystore) {
        this.request = request;
        this.keystore = keystore;
        this.encryptor = request.getBiometricKeyEncryptor();
    }

    @Override
    public boolean isAuthenticationRequiredOnEncryption() {
        return request.isUseSymmetricCipher();
    }

    @NonNull
    @Override
    public IBiometricKeyEncryptor getBiometricKeyEncryptor() throws PowerAuthErrorException {
        if (encryptor == null) {
            if (request.isForceGenerateNewKey()) {
                encryptor = keystore.createBiometricKeyEncryptor(request.isInvalidateByBiometricEnrollment(), request.isUseSymmetricCipher());
                if (encryptor == null) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED, "Keystore failed to generate a new biometric key.");
                }
            } else {
                encryptor = keystore.getBiometricKeyEncryptor();
                if (encryptor == null) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Cannot get biometric key from the keystore.");
                }
            }
        }
        return encryptor;
    }
}
