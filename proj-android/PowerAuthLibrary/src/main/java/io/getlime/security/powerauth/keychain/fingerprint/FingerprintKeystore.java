/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.keychain.fingerprint;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Class representing a Keystore used to store fingerprint related key.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class FingerprintKeystore {

    private static final String KEY_NAME = "io.getlime.PowerAuthKeychain.KeyStore.BiometryKeychain";
    private static final String PROVIDER_NAME = "AndroidKeyStore";

    private KeyStore mKeyStore;

    public FingerprintKeystore() {
        if (mKeyStore == null) {
            try {
                mKeyStore = KeyStore.getInstance(PROVIDER_NAME);
                mKeyStore.load(null);
            } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                mKeyStore = null;
            }
        }
    }

    /**
     * Check if the Keystore is ready.
     * @return True if Keystore is ready, false otherwise.
     */
    public boolean isKeystoreReady() {
        return mKeyStore != null;
    }

    /**
     * Check if a default key is present in Keystore
     *
     * @return True in case a default key is present, false otherwise. Method returns false in case Keystore is not properly initialized (call 'isKeystore' ready).
     */
    public boolean containsDefaultKey() {
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
     * @return True in case a key was created, false otherwise.
     */
    public boolean generateDefaultKey() {
        try {
            removeDefaultKey();
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER_NAME);
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setRandomizedEncryptionRequired(false)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build();
            keyGenerator.init(keySpec);
            keyGenerator.generateKey();
            return true;
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;
        }
    }

    /**
     * Removes an encryption key from Keystore.
     * @return True in case key was removed, false otherwise.
     */
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

    public SecretKey getDefaultKey() {
        try {
            mKeyStore.load(null);
            return (SecretKey) mKeyStore.getKey(KEY_NAME, null);
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException e) {
            return null;
        }
    }

}
