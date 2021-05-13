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
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code IBiometricKeyEncryptorProvider} interface provides an instance of {@link IBiometricKeyEncryptor}
 * on demand, when the encryptor is required during the biometric authentication process.
 */
public interface IBiometricKeyEncryptorProvider {
    /**
     * Determine whether biometric authentication is required in {@link IBiometricKeyEncryptor#encryptBiometricKey(byte[])} method.
     * Be aware that an actual implementation should determine this information without creating the encryptor. This is due the fact,
     * that the encryptor creation may be a heavy computational task and the type of encryptor is typically needed on the main thread.
     *
     * @return {@code true} if biometric authentication is required in {@link IBiometricKeyEncryptor#encryptBiometricKey(byte[])} method.
     *         If {@code false} is returned, then typically the setup of biometric factor doesn't require
     *         biometric authentication.
     */
    boolean isAuthenticationRequiredOnEncryption();

    /**
     * Create an instance of {@link IBiometricKeyEncryptor} class.
     *
     * @return {@link IBiometricKeyEncryptor} instance.
     * @throws PowerAuthErrorException In case of encryptor creation failure.
     */
    @NonNull IBiometricKeyEncryptor getBiometricKeyEncryptor() throws PowerAuthErrorException;
}
