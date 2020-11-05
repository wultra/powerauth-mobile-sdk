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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
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

/**
 * The {@code BiometricKeyEncryptorRsa} implements {@link IBiometricKeyEncryptor} and provides
 * protection of PowerAuth biometric factor with using asymmetric RSA cipher. The RSA key-pair
 * is stored in Android KeyStore and the biometric authentication is required only for data
 * decryption.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class BiometricKeyEncryptorRsa implements IBiometricKeyEncryptor {

    /**
     * Public key, required for encrypt operation.
     */
    private final @Nullable PublicKey publicKey;
    /**
     * Private key, required for decrypt operation.
     */
    private final @Nullable PrivateKey privateKey;
    /**
     * Initialized cipher.
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
     * RSA cipher configuration.
     */
    private static final String RSA_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Initialize encryptor for encrypt operation.
     * @param publicKey RSA public key.
     */
    public BiometricKeyEncryptorRsa(@NonNull PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = null;
    }

    /**
     * Initialize encryptor for decrypt operation.
     * @param privateKey RSA private key.
     */
    public BiometricKeyEncryptorRsa(@NonNull PrivateKey privateKey) {
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
                    // Initialize RSA parameters (OAEP with SHA-256 and MGF1).
                    // Note that MGF1 configured with SHA-256 is not supported, so that's why we still use SHA-1.
                    final PublicKey unrestrictedPublicKey = KeyFactory.getInstance(publicKey.getAlgorithm()).generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
                    final OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
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
            // RSA encryptor really encrypts and decrypts data. That means that 'key' on input is
            // already the key, that will protect biometric factor for PowerAuth protocol.
            return new BiometricKeyData(encryptedBiometricKey, key, true);

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
            // The decrypted key is the key that was previously used to lock PowerAuth biometric
            // factor. Just for convenience, we'll return the same data as we received on input.
            return new BiometricKeyData(encryptedKey, decryptedKey, false);

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            PA2Log.e("BiometricKeyEncryptorRsa.decryptBiometricKey failed: " + e.getMessage());
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
     * @return New instance of {@link BiometricKeyEncryptorRsa} or {@code null} in case of failure.
     */
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
