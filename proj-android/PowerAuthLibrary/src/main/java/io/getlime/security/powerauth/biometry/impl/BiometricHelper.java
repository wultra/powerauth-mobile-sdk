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

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code BiometricHelper} class provides helper methods for PowerAuth Mobile SDK. The class
 * is suppose to be used only by the SDK itself.
 */
public class BiometricHelper {
    /**
     * Translate {@link BiometricStatus} into appropriate {@link PowerAuthErrorException}.
     *
     * @param status Status to be translated to the exception.
     * @return Exception created for the error status. If status is {@link BiometricStatus#OK},
     *         then {@code IllegalArgumentException} is produced.
     */
    public static @NonNull PowerAuthErrorException getExceptionForBiometricStatus(@BiometricStatus int status) {
        switch (status) {
            case BiometricStatus.LOCKED_DOWN:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Too many failed attempts. The sensor is locked down.");
            case BiometricStatus.NOT_ENROLLED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Biometric data is not enrolled on the device.");
            case BiometricStatus.PERMISSION_NOT_GRANTED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotGranted, "Permission for the biometry usage is not granted.");
            case BiometricStatus.NOT_SUPPORTED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Biometry is not supported on the device.");
            case BiometricStatus.OK:
                throw new IllegalArgumentException("Cannot get exception for success status.");
            default:
                throw new IllegalArgumentException("Unknown status.");
        }
    }

    /**
     * Create AES/CBC with PKCS7 padding cipher with given secret key.
     *
     * @param key Key to be used for encryption and decryption.
     * @return {@link Cipher} object or null in case of error.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public static @Nullable Cipher createAesCipher(@NonNull SecretKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            final byte[] zero_iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            AlgorithmParameterSpec algorithmSpec = new IvParameterSpec(zero_iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
            return cipher;
        } catch (NoSuchPaddingException e) {
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (InvalidKeyException e) {
            return null;
        }
    }

    /**
     * Encrypt provided key bytes with using cipher.
     *
     * @param keyToProtect Bytes containing key to be protected with the cipher.
     * @param cipher Cipher for the key encryption.
     * @return Encrypted bytes, or {@code null} in case of encryption error.
     */
    public static @Nullable byte[] protectKeyWithCipher(@NonNull byte[] keyToProtect, @NonNull Cipher cipher) {
        try {
            return cipher.doFinal(keyToProtect);
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }
    }
}
