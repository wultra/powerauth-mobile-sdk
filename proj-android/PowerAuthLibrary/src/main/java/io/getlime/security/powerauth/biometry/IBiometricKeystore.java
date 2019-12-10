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

import javax.crypto.SecretKey;

/**
 * Interface representing a Keystore used to store biometry related key.
 */
public interface IBiometricKeystore {

    /**
     * Check if the Keystore is ready.
     *
     * @return True if Keystore is ready, false otherwise.
     */
    boolean isKeystoreReady();

    /**
     * Check if a default key is present in Keystore
     *
     * @return True in case a default key is present, false otherwise. Method returns false in case Keystore is not properly initialized (call {@link #isKeystoreReady()}).
     */
    boolean containsDefaultKey();

    /**
     * Generate a new biometry related Keystore key with default key name.
     *
     * The key that is created during this process is used to encrypt key stored in shared preferences,
     * in order to derive key used for biometric authentication.
     *
     * @param invalidateByBiometricEnrollment Sets whether the new key should be invalidated on biometric enrollment.
     * @return New generated {@link SecretKey} key or {@code null} in case of failure.
     */
    @Nullable SecretKey generateDefaultKey(boolean invalidateByBiometricEnrollment);

    /**
     * Removes an encryption key from Keystore.
     *
     * @return True in case key was removed, false otherwise.
     */
    boolean removeDefaultKey();

    /**
     * @return Default biometry related key, stored in KeyStore or null if no such key is stored.
     */
    @Nullable SecretKey getDefaultKey();
}
