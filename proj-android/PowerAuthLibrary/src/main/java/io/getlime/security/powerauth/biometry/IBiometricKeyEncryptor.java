/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.biometry;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import static io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor.EncryptorType.*;

import androidx.annotation.IntDef;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;

import java.lang.annotation.Retention;

import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

import javax.crypto.Cipher;

/**
 * The {@code IBiometricKeyEncryptor} provides encryption and decryption of KEK that protects
 * PowerAuth biometric factor. The underlying implementation use Android KeyStore to store
 * the encryption key that is protected with the biometric authentication.
 * <p>
 * Instance of this object can be typically used only for once, per encryption or decryption task.
 * Calling methods from this interface for multiple times produce {@code IllegalStateException}.
 */
public interface IBiometricKeyEncryptor {

    @Retention(SOURCE)
    @IntDef({AES, RSA, HMAC})
    @interface EncryptorType {
        /**
         * Symmetric key for AES.
         */
        int AES = 0;
        /**
         * Asymmetric RSA key.
         */
        int RSA = 1;
        /**
         * Symmetric key for HMAC-SHA384
         */
        int HMAC = 2;
    }

    /**
     * @return Type of this encryptor.
     */
    @EncryptorType int getEncryptorType();

    /**
     * @return {@code true} if biometric authentication is required in {@link #encryptBiometricKey(SecureData)} method.
     *         If {@code false} is returned, then typically the setup of biometric factor doesn't require
     *         biometric authentication.
     */
    boolean isAuthenticationRequiredOnEncryption();

    /**
     * Initialize {@link Cipher} and keep it internally for later key encryption or decryption. The method can
     * be used only for once, during the encryptor's lifecycle.
     *
     * @param encryptMode Tells whether object will be later used for key encryption or decryption.
     *
     * @return Instance of {@link BiometricPrompt.CryptoObject} object
     * @throws PowerAuthErrorException in case of failure.
     */
    @NonNull
    BiometricPrompt.CryptoObject initializeCryptoObject(boolean encryptMode) throws PowerAuthErrorException;

    /**
     * Encrypt biometric key and return object that contains encrypted key and data to store to permanent storage.
     * The values may differ in case that encryption and decryption actually implement KDF, so the source sequence
     * of bytes must be saved.
     * <p>
     * The method can be used only for once during the encryptor's lifecycle.
     *
     * @param key Biometric KEK to encrypt.
     * @return {@link BiometricKeyData} with key derivation and data to store to persistent storage.
     */
    @Nullable
    BiometricKeyData encryptBiometricKey(@NonNull SecureData key);

    /**
     * Decrypt biometric key from previously stored value.
     * <p>
     * The method can be used only for once during the encryptor's lifecycle.
     *
     * @param encryptedKey Previously stored encrypted key.
     * @return {@link BiometricKeyData} with restored key derivation.
     */
    @Nullable
    BiometricKeyData decryptBiometricKey(@NonNull SecureData encryptedKey);
}
