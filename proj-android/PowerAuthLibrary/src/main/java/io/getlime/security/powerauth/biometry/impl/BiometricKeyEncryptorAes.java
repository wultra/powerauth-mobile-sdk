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
import android.support.annotation.RequiresApi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code BiometricKeyEncryptorAes} implements {@link IBiometricKeyEncryptor} and provides
 * protection of PowerAuth biometric factor with using symmetric AES cipher. The key is stored in
 * Android KeyStore and the biometric authentication is required for both data encryption and decryption.
 * <p>
 * The cipher configuration is compatible with previous versions of PowerAuth SDK (1.4.3 and older).
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class BiometricKeyEncryptorAes implements IBiometricKeyEncryptor {

    /**
     * Symmetric AES key.
     */
    private final @NonNull SecretKey key;
    /**
     * Symmetric AES cipher
     */
    private @Nullable Cipher cipher;
    /**
     * If true, then internal cipher is already initialized.
     */
    private boolean cipherIsInitialized;
    /**
     * If true, then encryptor object was already used, so no subsequent calls are allowed.
     */
    private boolean encryptorIsUsed;
    /**
     * If true, then encrypt operation is expected.
     */
    private boolean encryptMode;

    /**
     * AES cipher configuration.
     */
    private static final String AES_CIPHER = "AES/CBC/PKCS7Padding";

    /**
     * Initialize encryptor with symmetric {@link SecretKey}.
     * @param key Encryption and decryption key.
     */
    public BiometricKeyEncryptorAes(@NonNull SecretKey key) {
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
                // We always initialize cipher to encrypt mode, because AES cipher is later used
                // as KDF function. We don't actually encrypt and decrypt the raw biometric key.
                final byte[] zero_iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                AlgorithmParameterSpec algorithmSpec = new IvParameterSpec(zero_iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, algorithmSpec);
                // Keep encrypt mode flag to be validated later in encrypt / decrypt methods.
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
        // We use AES as KDF, so we must return the provided key back to the application
        // to save it to the persistent storage, to be able to perform the same KDF in decryption.
        return derivedKey != null ? new BiometricKeyData(key, derivedKey, true) : null;
    }

    @Nullable
    @Override
    public BiometricKeyData decryptBiometricKey(@NonNull byte[] encryptedKey) {
        // Note that "encryptedKey" is actually the same key as was provided to "encryptBiometricKey"
        // method. This is due to fact, that we use AES as KDF.
        final byte[] derivedKey = aesKdf(encryptedKey, false);
        // It's not required to store "dataToSave" after the decryption. We return the same data
        // just for convenience.
        return derivedKey != null ? new BiometricKeyData(encryptedKey, derivedKey, false) : null;
    }

    /**
     * Private method that implements AES KDF.
     *
     * @param keyToDerive Key material to be derived with KDF.
     * @param encryptMode Encrypt / Decrypt flag, to test API usage.
     * @return Derived data or {@code null} in case of failure.
     */
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
                throw new IllegalStateException("Encryptor cannot be used for the second time");
            }
            encryptorIsUsed = true;

            // Derive the key
            return cipher.doFinal(keyToDerive);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("BiometricKeyEncryptorAes.aesKdf failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Create a new instance of this class with given parameters.
     *
     * @param providerName KeyStore provider name.
     * @param keyName KeyStore key alias.
     * @param invalidateByBiometricEnrollment If {@code true}, then key will be invalidated on
     *                                        new biometric enrollment.
     * @return New instance of {@link BiometricKeyEncryptorAes} or {@code null} in case of failure.
     */
    @Nullable
    public static IBiometricKeyEncryptor createAesEncryptor(@NonNull String providerName, @NonNull String keyName, boolean invalidateByBiometricEnrollment) {
        try {
            // Acquire AES key generator
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", providerName);
            // Configure AES key generator
            final KeyGenParameterSpec.Builder keySpecBuilder = new KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(false)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keySpecBuilder.setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment);
            }
            // Initialize generator and generate a new AES key in the KeyStore.
            keyGenerator.init(keySpecBuilder.build());
            final SecretKey key = keyGenerator.generateKey();
            // Create a new instance of encryptor.
            return new BiometricKeyEncryptorAes(key);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | ProviderException e) {
            PA2Log.e("BiometricKeyEncryptorAes.createAesEncryptor failed: " + e.getMessage());
            return null;
        }
    }
}
