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
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.IBiometricKeyEncryptor;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.system.PA2Log;

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
            PA2Log.e("BiometricKeystore constructor failed: " + e.getMessage());
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
    public boolean containsBiometricKeyEncryptor() {
        if (!isKeystoreReady()) {
            return false;
        }
        try {
            return mKeyStore.containsAlias(KEY_NAME);
        } catch (KeyStoreException e) {
            PA2Log.e("BiometricKeystore.containsBiometricKeyEncryptor failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Generate a new biometry related Keystore key with default key name.
     *
     * The key that is created during this process is used to encrypt key stored in shared preferences,
     * in order to derive key used for biometric authentication.
     * @param invalidateByBiometricEnrollment If true, then internal key stored in KeyStore will be invalidated on next biometric enrollment.
     * @param useSymmetricKey If true, then symmetric key will be created.
     * @return New generated {@link SecretKey} key or {@code null} in case of failure.
     */
    @Override
    public @Nullable
    IBiometricKeyEncryptor createBiometricKeyEncryptor(boolean invalidateByBiometricEnrollment, boolean useSymmetricKey) {
        removeBiometricKeyEncryptor();
        if (useSymmetricKey) {
            return BiometricKeyEncryptorAes.createAesEncryptor(PROVIDER_NAME, KEY_NAME, invalidateByBiometricEnrollment);
        } else {
            return BiometricKeyEncryptorRsa.createRsaEncryptor(PROVIDER_NAME, KEY_NAME, invalidateByBiometricEnrollment);
        }
    }

    /**
     * Removes an encryption key from Keystore.
     */
    @Override
    public void removeBiometricKeyEncryptor() {
        try {
            if (containsBiometricKeyEncryptor()) {
                mKeyStore.deleteEntry(KEY_NAME);
            }
        } catch (KeyStoreException e) {
            PA2Log.e("BiometricKeystore.removeBiometricKeyEncryptor failed: " + e.getMessage());
        }
    }

    /**
     * @return Default biometry related key, stored in KeyStore.
     */
    @Override
    @Nullable
    public IBiometricKeyEncryptor getBiometricKeyEncryptor() {
        if (!isKeystoreReady()) {
            return null;
        }
        try {
            mKeyStore.load(null);
            if (mKeyStore.isCertificateEntry(KEY_NAME)) {
                // RSA key-pair
                final Key key = mKeyStore.getKey(KEY_NAME, null);
                if (key instanceof PrivateKey) {
                    return new BiometricKeyEncryptorRsa(key);
                }
            } else {
                // AES key
                final Key key = mKeyStore.getKey(KEY_NAME, null);
                if (key instanceof SecretKey) {
                    return new BiometricKeyEncryptorAes(key);
                }
            }
            return null;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException e) {
            return null;
        }
    }

}
