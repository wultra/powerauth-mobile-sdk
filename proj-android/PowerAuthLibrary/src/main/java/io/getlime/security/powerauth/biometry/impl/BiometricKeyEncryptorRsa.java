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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.system.PA2Log;

public class BiometricKeyEncryptorRsa implements IBiometricKeyEncryptor {

    private final @Nullable PublicKey publicKey;
    private final @Nullable Key privateKey;
    private @Nullable Cipher cipher;
    private boolean cipherIsInitialized;
    private boolean encryptorIsUsed;
    private boolean encryptMode;

    private static final String RSA_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public BiometricKeyEncryptorRsa(@NonNull PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = null;
    }

    public BiometricKeyEncryptorRsa(@NonNull Key privateKey) {
        this.publicKey = null;
        this.privateKey = privateKey;
    }

    @Override
    public boolean isAuthenticationRequiredOnEncryption() {
        return false;
    }

    @Nullable
    @Override
    public Cipher initializeCipher(boolean encryptMode) {
        try {
            if (cipherIsInitialized) {
                throw new IllegalStateException("Cipher is already initialized");
            }
            // Get instance of RSA cipher
            cipher = Cipher.getInstance(RSA_CIPHER);
            if (cipher != null) {
                if (encryptMode) {
                    // Initialize for encryption with public key.
                    if (publicKey == null) {
                        throw new IllegalStateException("Initializing cipher for encryption, but public key is missing");
                    }
                    // Initialize RSA parameters (OAEP with SHA-256 and MGF1)
                    final PublicKey unrestrictedPublicKey = KeyFactory.getInstance(publicKey.getAlgorithm()).generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
                    final OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                    // Initialize cipher for data encryption
                    cipher.init(Cipher.ENCRYPT_MODE, unrestrictedPublicKey, spec);
                } else {
                    // Initialize for decryption with private key.
                    if (privateKey == null) {
                        throw new IllegalStateException("Initializing cipher for decryption, but private key is missing");
                    }
                    // Initialize cipher for data decryption.
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                }
                this.encryptMode = encryptMode;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            PA2Log.e("BiometricKeyEncryptorRsa.initializeCipher failed: " + e.getMessage());
            this.cipher = null;
        } finally {
            cipherIsInitialized = true;
        }
        return cipher;
    }

    @Nullable
    @Override
    public BiometricKeyData encryptBiometricKey(@NonNull byte[] key) {
        try {
            // State checks
            if (cipher == null) {
                throw new IllegalStateException("Cipher is not initialized");
            }
            if (!encryptMode) {
                throw new IllegalStateException("Encryptor is not configured for encryption.");
            }
            if (encryptorIsUsed) {
                throw new IllegalStateException("Encryptor cannot be used for twice");
            }
            encryptorIsUsed = true;

            // Encrypt data
            final byte[] encryptedBiometricKey = cipher.doFinal(key);
            // RSA encryptor really needs to store encrypted data. So, we're returned the same
            // array of bytes in BiometricKeyData object.
            return new BiometricKeyData(encryptedBiometricKey, encryptedBiometricKey);

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("BiometricKeyEncryptorRsa.encryptBiometricKey failed: " + e.getMessage());
            return null;
        }
    }

    @Nullable
    @Override
    public BiometricKeyData decryptBiometricKey(@NonNull byte[] encryptedKey) {
        try {
            // State checks
            if (cipher == null) {
                throw new IllegalStateException("Cipher is not initialized");
            }
            if (encryptMode) {
                throw new IllegalStateException("Encryptor is not used for decryption");
            }
            if (encryptorIsUsed) {
                throw new IllegalStateException("Encryptor cannot be used for twice");
            }
            encryptorIsUsed = true;

            // Decrypt data
            final byte[] decryptedKey = cipher.doFinal(encryptedKey);
            return new BiometricKeyData(encryptedKey, decryptedKey);

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("BiometricKeyEncryptorRsa.decryptBiometricKey failed: " + e.getMessage());
            return null;
        }
    }

    @Nullable
    public static IBiometricKeyEncryptor createRsaEncryptor(@NonNull String providerName, @NonNull String keyName, boolean invalidateByBiometricEnrollment) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, providerName);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment);
            }
            keyPairGenerator.initialize(builder.build());
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            final PublicKey publicKey = keyPair.getPublic();
            return new BiometricKeyEncryptorRsa(publicKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            PA2Log.e("BiometricKeyEncryptorRsa.createRsaEncryptor failed: " + e.getMessage());
            return null;
        }
    }
}
