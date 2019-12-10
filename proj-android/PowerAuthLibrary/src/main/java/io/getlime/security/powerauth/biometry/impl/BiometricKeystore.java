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
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.IBiometricKeystore;

/**
 * Class representing a Keystore used to store biometry related key.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class BiometricKeystore implements IBiometricKeystore {

    private static final String KEY_NAME = "io.getlime.PowerAuthKeychain.KeyStore.BiometryKeychain";
    private static final String PROVIDER_NAME = "AndroidKeyStore";

    private KeyStore mKeyStore;

    public BiometricKeystore() {
        try {
            mKeyStore = KeyStore.getInstance(PROVIDER_NAME);
            mKeyStore.load(null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            mKeyStore = null;
        }
    }

    /**
     * Check if the Keystore is ready.
     * @return True if Keystore is ready, false otherwise.
     */
    @Override
    public boolean isKeystoreReady() {
        return mKeyStore != null;
    }

    /**
     * Check if a default key is present in Keystore
     *
     * @return True in case a default key is present, false otherwise. Method returns false in case Keystore is not properly initialized (call {@link #isKeystoreReady()}).
     */
    @Override
    public boolean containsDefaultKey() {
        if (!isKeystoreReady()) {
            return false;
        }
        try {
            return mKeyStore.containsAlias(KEY_NAME);
        } catch (KeyStoreException e) {
            return false;
        }
    }

    /**
     * Generate a new biometry related Keystore key with default key name.
     *
     * The key that is created during this process is used to encrypt key stored in shared preferences,
     * in order to derive key used for biometric authentication.
     *
     * @return New generated {@link SecretKey} key or {@code null} in case of failure.
     */
    @Override
    public @Nullable SecretKey generateDefaultKey(boolean invalidateByBiometricEnrollment) {
        try {
            removeDefaultKey();
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER_NAME);
            final KeyGenParameterSpec.Builder keySpecBuilder = new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(false)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                keySpecBuilder.setInvalidatedByBiometricEnrollment(invalidateByBiometricEnrollment);
            }
            keyGenerator.init(keySpecBuilder.build());
            return keyGenerator.generateKey();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | ProviderException e) {
            return null;
        }
    }

    /**
     * Removes an encryption key from Keystore.
     * @return True in case key was removed, false otherwise.
     */
    @Override
    public boolean removeDefaultKey() {
        try {
            if (containsDefaultKey()) {
                mKeyStore.deleteEntry(KEY_NAME);
            }
            return true;
        } catch (KeyStoreException e) {
            return false;
        }
    }

    /**
     * @return Default biometry related key, stored in KeyStore.
     */
    @Override
    public @Nullable SecretKey getDefaultKey() {
        if (!isKeystoreReady()) {
            return null;
        }
        try {
            mKeyStore.load(null);
            return (SecretKey) mKeyStore.getKey(KEY_NAME, null);
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException e) {
            return null;
        }
    }

}
