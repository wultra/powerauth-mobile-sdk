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

package io.getlime.security.powerauth.biometry.impl;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.system.PA2Log;

public class BiometricKeyEncryptorAes implements IBiometricKeyEncryptor {

    private final @NonNull Key key;
    private @Nullable Cipher cipher;
    private boolean cipherIsInitialized;
    private boolean encryptorIsUsed;
    private boolean encryptMode;

    private static final String AES_CIPHER = "AES/CBC/PKCS7Padding";

    public BiometricKeyEncryptorAes(@NonNull Key key) {
        this.key = key;
    }

    @Override
    public boolean isAuthenticationRequiredOnEncryption() {
        return true;
    }

    @Nullable
    @Override
    public Cipher initializeCipher(boolean encryptMode) {
        try {
            if (cipherIsInitialized) {
                throw new IllegalStateException("Cipher is already initialized");
            }
            cipher = Cipher.getInstance(AES_CIPHER);
            if (cipher != null) {
                final byte[] zero_iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                AlgorithmParameterSpec algorithmSpec = new IvParameterSpec(zero_iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
                this.encryptMode = encryptMode;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            PA2Log.e("BiometricKeyEncryptorAes.initializeCipher failed: " + e.getMessage());
            this.cipher = null;
        } finally {
            this.cipherIsInitialized = true;
        }
        return cipher;
    }

    @Nullable
    @Override
    public BiometricKeyData encryptBiometricKey(@NonNull byte[] key) {
        final byte[] derivedKey = aesKdf(key, true);
        // TODO: explain why we're returning different data.
        return derivedKey != null ? new BiometricKeyData(key, derivedKey) : null;
    }

    @Nullable
    @Override
    public BiometricKeyData decryptBiometricKey(@NonNull byte[] encryptedKey) {
        final byte[] derivedKey = aesKdf(encryptedKey, false);
        // TODO: explain why we're returning different data.
        return derivedKey != null ? new BiometricKeyData(encryptedKey, derivedKey) : null;
    }

    @Nullable
    private byte[] aesKdf(@NonNull byte[] keyToDerive, boolean encryptMode) {
        try {
            // State checks
            if (cipher == null) {
                throw new IllegalStateException("Cipher is not initialized");
            }
            if (this.encryptMode != encryptMode) {
                throw new IllegalStateException("Encryptor is not configured for " + (encryptMode ? "encryption" : "decryption"));
            }
            if (encryptorIsUsed) {
                throw new IllegalStateException("Encryptor cannot be used for twice");
            }
            encryptorIsUsed = true;

            // Derive the key
            return cipher.doFinal(keyToDerive);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("BiometricKeyEncryptorAes.aesKdf failed: " + e.getMessage());
            return null;
        }
    }

    @Nullable
    public static IBiometricKeyEncryptor createAesEncryptor(@NonNull String providerName, @NonNull String keyName, boolean invalidateByBiometricEnrollment) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", providerName);
            final KeyGenParameterSpec.Builder keySpecBuilder = new KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(false)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keySpecBuilder.setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment);
            }
            keyGenerator.init(keySpecBuilder.build());
            final Key key = keyGenerator.generateKey();
            return new BiometricKeyEncryptorAes(key);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | ProviderException e) {
            PA2Log.e("BiometricKeyEncryptorAes.createAesEncryptor failed: " + e.getMessage());
            return null;
        }
    }
}
