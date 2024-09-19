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
import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Class representing a Keystore used to store biometry related key.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class BiometricKeystore implements IBiometricKeystore {

    private static final String KEY_NAME_PREFIX = "com.wultra.powerauth.biometricKey.";
    private static final String LEGACY_KEY_NAME = "io.getlime.PowerAuthKeychain.KeyStore.BiometryKeychain";
    private static final String PROVIDER_NAME = "AndroidKeyStore";

    private KeyStore mKeyStore;

    public BiometricKeystore() {
        try {
            mKeyStore = KeyStore.getInstance(PROVIDER_NAME);
            mKeyStore.load(null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            PowerAuthLog.e("BiometricKeystore constructor failed: " + e.getMessage());
            mKeyStore = null;
        }
    }

    @Override
    public boolean isKeystoreReady() {
        return mKeyStore != null;
    }

    @Override
    public boolean containsBiometricKeyEncryptor(@NonNull String keyId) {
        if (!isKeystoreReady()) {
            return false;
        }
        try {
            return mKeyStore.containsAlias(getKeystoreAlias(keyId));
        } catch (KeyStoreException e) {
            PowerAuthLog.e("BiometricKeystore.containsBiometricKeyEncryptor failed: " + e.getMessage());
            return false;
        }
    }

    @Override
    public @Nullable
    IBiometricKeyEncryptor createBiometricKeyEncryptor(@NonNull String keyId, boolean invalidateByBiometricEnrollment, boolean useSymmetricKey) {
        removeBiometricKeyEncryptor(keyId);
        if (useSymmetricKey) {
            return BiometricKeyEncryptorAes.createAesEncryptor(PROVIDER_NAME, getKeystoreAlias(keyId), invalidateByBiometricEnrollment);
        } else {
            return BiometricKeyEncryptorRsa.createRsaEncryptor(PROVIDER_NAME, getKeystoreAlias(keyId), invalidateByBiometricEnrollment);
        }
    }

    @Override
    public void removeBiometricKeyEncryptor(@NonNull String keyId) {
        try {
            if (containsBiometricKeyEncryptor(keyId)) {
                mKeyStore.deleteEntry(getKeystoreAlias(keyId));
            }
        } catch (KeyStoreException e) {
            PowerAuthLog.e("BiometricKeystore.removeBiometricKeyEncryptor failed: " + e.getMessage());
        }
    }

    /**
     * @return Default biometry related key, stored in KeyStore.
     */
    @Override
    @Nullable
    public IBiometricKeyEncryptor getBiometricKeyEncryptor(@NonNull String keyId) {
        if (!isKeystoreReady()) {
            return null;
        }
        try {
            mKeyStore.load(null);
            final Key key = mKeyStore.getKey(getKeystoreAlias(keyId), null);
            if (key instanceof SecretKey) {
                // AES symmetric key
                return new BiometricKeyEncryptorAes((SecretKey)key);
            } else if (key instanceof PrivateKey) {
                // RSA private key
                return new BiometricKeyEncryptorRsa((PrivateKey)key);
            } else if (key != null) {
                PowerAuthLog.e("BiometricKeystore.getBiometricKeyEncryptor unknown key type: " + key.toString());
            }
            return null;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException e) {
            PowerAuthLog.e("BiometricKeystore.getBiometricKeyEncryptor failed: " + e.getMessage());
            return null;
        }
    }

    @Override
    @NonNull
    public String getLegacySharedKeyId() {
        return LEGACY_KEY_NAME;
    }

    /**
     * Function return alias for key stored in KeyStore for given key identifier. If the key identifier is equal to
     * legacy key name, then the alias is legacy key name. Otherwise, the key alias is calculated as
     * {@code KEY_NAME_PREFIX + SHA256(keyId)}.
     * @param keyId Key identifier.
     * @return Key alias to key stored in KeyStore.
     */
    @NonNull
    private String getKeystoreAlias(@NonNull String keyId) {
        if (LEGACY_KEY_NAME.equals(keyId)) {
            return LEGACY_KEY_NAME;
        }
        final String keyIdHash = Base64.encodeToString(
                CryptoUtils.hashSha256(keyId.getBytes(StandardCharsets.UTF_8)),
                Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
        return KEY_NAME_PREFIX + keyIdHash;
    }
}
