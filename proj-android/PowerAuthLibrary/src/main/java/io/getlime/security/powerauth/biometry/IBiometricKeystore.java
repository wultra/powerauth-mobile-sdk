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

package io.getlime.security.powerauth.biometry;

import android.support.annotation.Nullable;

/**
 * Interface wrapping a key stored in Android KeyStore and providing {@link IBiometricKeyEncryptor}
 * that can encrypt and decrypt biometry related keys for PowerAuth protocol.
 */
public interface IBiometricKeystore {

    /**
     * Check if the Keystore is ready.
     *
     * @return {@code true} if KeyStore is ready, false otherwise.
     */
    boolean isKeystoreReady();

    /**
     * Check if a key for biometric key encryptor is present in Keystore and {@link IBiometricKeyEncryptor}
     * can be acquired.
     *
     * @return {@code true} in case a key for biometric key encryptor is present, false otherwise.
     *         Method returns false in case Keystore is not properly initialized (call {@link #isKeystoreReady()}).
     */
    boolean containsBiometricKeyEncryptor();

    /**
     * Generate a new biometry related Keystore key and return object that provide KEK encryption and decryption.
     *
     * The key that is created during this process is used to encrypt KEK stored in shared preferences,
     * in order to derive key used for biometric authentication.
     *
     * @param invalidateByBiometricEnrollment Sets whether the new key should be invalidated on biometric enrollment.
     * @param useSymmetricKey Sets whether symmetric key should be created.
     *
     * @return New generated {@link IBiometricKeyEncryptor} key or {@code null} in case of failure.
     */
    @Nullable
    IBiometricKeyEncryptor createBiometricKeyEncryptor(boolean invalidateByBiometricEnrollment, boolean useSymmetricKey);

    /**
     * Removes an encryption key from Keystore.
     */
    void removeBiometricKeyEncryptor();

    /**
     * @return {@link IBiometricKeyEncryptor} constructed with key stored in KeyStore or {@code null}
     *         if no such key is stored.
     */
    @Nullable
    IBiometricKeyEncryptor getBiometricKeyEncryptor();
}
