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

package io.getlime.security.powerauth.keychain.impl;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.keychain.SymmetricKeyProvider;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * The {@code EncryptedKeychain} class implements {@link Keychain} interface with content
 * encryption. The class is used on all devices that supports KeyStore reliably (e.g.
 * on all systems newer or equal than Android "M".)
 *
 * The "AES/GCM/NoPadding" scheme is used for encryption and decryption.
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class EncryptedKeychain implements Keychain {

    /**
     * Keychain identifier.
     */
    private final @NonNull String identifier;
    /**
     * Android application context.
     */
    private final @NonNull Context context;
    /**
     * Secret key provider.
     */
    private final @NonNull SymmetricKeyProvider keyProvider;
    /**
     * Encoder that helps with the keychain value serialization and deserialization.
     */
    private final @NonNull KeychainValueEncoder valueEncoder;

    /**
     * * Default constructor, initialize keychain with given identifier and symmetric key provider.
     *
     * @param context Android application context.
     * @param identifier String with the keychain identifier.
     * @param secretKeyProvider Object that provides secret encryption and decryption key.
     */
    public EncryptedKeychain(@NonNull Context context, @NonNull String identifier, @NonNull SymmetricKeyProvider secretKeyProvider) {
        this.identifier = identifier;
        this.context = context;
        this.keyProvider = secretKeyProvider;
        this.valueEncoder = new KeychainValueEncoder();
    }

    @NonNull
    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public boolean isEncrypted() {
        return true;
    }

    @Override
    public boolean isReservedKey(@NonNull String key) {
        return ReservedKeyImpl.isReservedKey(key);
    }

    // Byte array accessors

    @Override
    public synchronized boolean contains(@NonNull String key) {
        return getRawValue(key) != null;
    }

    @Override
    public synchronized void remove(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        getSharedPreferences()
                .edit()
                .remove(key)
                .apply();
    }

    @Override
    public synchronized void removeAll() {
        getSharedPreferences()
                .edit()
                .clear()
                .putInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, ENCRYPTED_KEYCHAIN_VERSION)
                .apply();
    }

    @Nullable
    @Override
    public synchronized byte[] getData(@NonNull String key) {
        final byte[] encoded = getRawValue(key);
        if (encoded == null) {
            return null;
        }
        final byte[] decoded = valueEncoder.decodeBytes(encoded);
        return decoded.length > 0 ? decoded : null;
    }

    @Override
    public synchronized void putData(@Nullable byte[] data, @NonNull String key) {
        setRawValue(key, (data != null && data.length > 0) ? valueEncoder.encode(data) : null);
    }

    // String accessors

    @Nullable
    @Override
    public synchronized String getString(@NonNull String key) {
        final byte[] encoded = getRawValue(key);
        if (encoded == null) {
            return null;
        }
        return valueEncoder.decodeString(encoded);
    }

    @NonNull
    @Override
    public synchronized String getString(@NonNull String key, @NonNull String defaultValue) {
        final byte[] encoded = getRawValue(key);
        if (encoded == null) {
            return defaultValue;
        }
        return valueEncoder.decodeString(encoded);
    }

    @Override
    public synchronized void putString(@Nullable String string, @NonNull String key) {
        setRawValue(key, string != null ? valueEncoder.encode(string) : null);
    }

    // String Set accessors

    @Nullable
    @Override
    public synchronized Set<String> getStringSet(@NonNull String key) {
        final byte[] encoded = getRawValue(key);
        if (encoded == null) {
            return null;
        }
        return valueEncoder.decodeStringSet(encoded);
    }

    @Override
    public synchronized void putStringSet(@Nullable Set<String> stringSet, @NonNull String key) {
        setRawValue(key, stringSet != null ? valueEncoder.encode(stringSet) : null);
    }

    // Boolean accessors

    @Override
    public synchronized boolean getBoolean(@NonNull String key, boolean defaultValue) {
        final byte[] bytes = getRawValue(key);
        if (bytes == null) {
            return defaultValue;
        }
        return valueEncoder.decodeBoolean(bytes);
    }

    @Override
    public synchronized void putBoolean(boolean value, @NonNull String key) {
        setRawValue(key, valueEncoder.encode(value));
    }

    // Long accessors

    @Override
    public synchronized long getLong(@NonNull String key, long defaultValue) {
        final byte[] bytes = getRawValue(key);
        if (bytes == null) {
            return defaultValue;
        }
        return valueEncoder.decodeLong(bytes);
    }

    @Override
    public synchronized void putLong(long value, @NonNull String key) {
        setRawValue(key, valueEncoder.encode(value));
    }

    // Float accessors

    @Override
    public float getFloat(@NonNull String key, float defaultValue) {
        final byte[] bytes = getRawValue(key);
        if (bytes == null) {
            return defaultValue;
        }
        return valueEncoder.decodeFloat(bytes);
    }

    @Override
    public void putFloat(float value, @NonNull String key) {
        setRawValue(key, valueEncoder.encode(value));
    }

    // Import legacy keychain

    /**
     * Constant defines key to {@code SharedPreferences} for value that contains version of {#code EncryptedKeychain}.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final String ENCRYPTED_KEYCHAIN_VERSION_KEY = "com.wultra.PowerAuthKeychain.IsEncrypted";
    /**
     * Constant defines current version of {@code EncryptedKeychain}.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final int ENCRYPTED_KEYCHAIN_VERSION = 1;

    /**
     * Evaluate whether {@link SharedPreferences} contains encrypted content. The method is available also
     * for Android devices older than "M".
     *
     * @param preferences {@link SharedPreferences} content to evaluate.
     * @return {@code true} if provided object contains values for encrypted keychain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static boolean isEncryptedContentInSharedPreferences(@NonNull SharedPreferences preferences) {
        return ENCRYPTED_KEYCHAIN_VERSION == preferences.getInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, 0);
    }

    /**
     * Function does a self-test to verify whether Android Keystore is reliable on this device.
     * @param context Android context.
     * @param keyProvider A symmetric key provider
     * @return {@code true} if encryption and decryption with Keystore key works on this device.
     */
    public static boolean verifyKeystoreEncryption(@NonNull Context context, @NonNull SymmetricKeyProvider keyProvider) {
        final SecretKey secretKey = keyProvider.getOrCreateSecretKey(context,false);
        if (secretKey == null) {
            PA2Log.e("verifyKeystoreEncryption: Failed to acquire secret key.");
            return false;
        }
        final String identifier = "TestIdentifier";
        byte[] testData = new byte[0];
        byte[] encrypted = AesGcmImpl.encrypt(testData, secretKey, identifier);
        if (encrypted == null) {
            PA2Log.e("verifyKeystoreEncryption: Empty data encryption failed.");
            return false;
        }
        byte[] decrypted = AesGcmImpl.decrypt(encrypted, secretKey, identifier);
        if (decrypted == null || !Arrays.equals(testData, decrypted)) {
            PA2Log.e("verifyKeystoreEncryption: Empty data decryption failed.");
            return false;
        }
        testData = ENCRYPTED_KEYCHAIN_VERSION_KEY.getBytes(Charset.defaultCharset());
        encrypted = AesGcmImpl.encrypt(testData, secretKey, identifier);
        if (encrypted == null) {
            PA2Log.e("verifyKeystoreEncryption: Non-empty data encryption failed.");
            return false;
        }
        decrypted = AesGcmImpl.decrypt(encrypted, secretKey, identifier);
        if (decrypted == null || !Arrays.equals(testData, decrypted)) {
            PA2Log.e("verifyKeystoreEncryption: Non-empty data decryption failed.");
            return false;
        }
        return true;
    }

    /**
     * Import content from the legacy keychain. The method encrypts content stored in provided
     * {@code SharedPreferences} object. In case of import failure, the legacy content is
     * kept intact.
     *
     * @param preferences {@link SharedPreferences} object that contains the legacy keychain content.
     * @return {@code true} if import was successful, otherwise {@code false}.
     */
    public boolean importFromLegacyKeychain(@NonNull SharedPreferences preferences) {
        // Acquire an encryption key. Return failure immediately, if the key is not available.
        // The key can be re-created in case of failure, only if this is the first content import attempt.
        final SecretKey encryptionKey = getMasterKey();
        if (encryptionKey == null) {
            return false;
        }
        // Prepare hash map for encrypted content and set of keys with unsupported value types.
        final Map<String, String> encryptedContent = new HashMap<>();
        final Set<String> keysToRemove = new HashSet<>();
        // Iterate over all entries stored in the shared preferences.
        for (final Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
            final Object value = entry.getValue();
            final @NonNull byte[] encodedValue;
            if (value instanceof String) {
                final String string = (String)value;
                if (string.isEmpty()) {
                    // It's impossible to determine whether the stored value was string or Base64
                    // encoded data. The most safe way to handle this situation is to remove such
                    // value from the keychain.
                    keysToRemove.add(entry.getKey());
                    continue;
                }
                // Test whether the string is Base64 encoded sequence of bytes
                final byte[] decodedBytes = Base64.decode(string, Base64.DEFAULT);
                if (Base64.encodeToString(decodedBytes, Base64.DEFAULT).trim().equals(string.trim())) {
                    // String contains Base64 encoded sequence of bytes.
                    encodedValue = valueEncoder.encode(decodedBytes);
                } else {
                    // Non-Base64 encoded string. Just encode string as it is.
                    encodedValue = valueEncoder.encode(string);
                }
            } else if (value instanceof Boolean) {
                // Boolean value
                encodedValue = valueEncoder.encode((Boolean)value);
            } else if (value instanceof Long) {
                // Long value
                encodedValue = valueEncoder.encode((Long)value);
            } else if (value instanceof Float) {
                // Float value
                encodedValue = valueEncoder.encode((Float)value);
            } else if (value instanceof Set<?>) {
                // Set<String> value.
                // We can suppress "unchecked" warning, because SharedPreferences doesn't use other
                // type of set than Set<String>.
                @SuppressWarnings("unchecked")
                final Set<String> stringSet = (Set<String>)value;
                encodedValue = valueEncoder.encode(stringSet);
            } else {
                // This type of object is not supported by the keychain, so remove it from shared preferences.
                PA2Log.e("EncryptedKeychain: " + identifier + ": Removing unsupported value from key: " + entry.getKey());
                keysToRemove.add(entry.getKey());
                continue;
            }

            // Now encrypt the encoded value
            final byte[] encryptedValue = AesGcmImpl.encrypt(encodedValue, encryptionKey, identifier);
            if (encryptedValue == null) {
                PA2Log.e("EncryptedKeychain: " + identifier + ": Failed to import value from key: " + entry.getKey());
                return false;
            }
            // Keep encrypted value, encoded to Base64, for later save.
            encryptedContent.put(entry.getKey(), Base64.encodeToString(encryptedValue, Base64.NO_WRAP));
        }

        // Commit all changes to the underlying shared preferences
        final SharedPreferences.Editor editor = getSharedPreferences().edit();
        // Save all encrypted entries
        for (Map.Entry<String, String> entry : encryptedContent.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        // Remove all unsupported values
        for (String key : keysToRemove) {
            editor.remove(key);
        }
        editor.putInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, ENCRYPTED_KEYCHAIN_VERSION);
        editor.apply();
        return true;
    }

    // Private methods

    /**
     * @return Underlying {@code SharedPreferences} that contains content of keychain.
     */
    private @NonNull SharedPreferences getSharedPreferences() {
        return context.getSharedPreferences(identifier, Context.MODE_PRIVATE);
    }

    /**
     * Return encoded raw value bytes stored in the shared preferences.
     *
     * @param key Key to be used for value retrieval.
     * @return Encoded raw value in case there are some data under given key, {@code null} otherwise.
     */
    @Nullable
    private byte[] getRawValue(@NonNull String key) {
        ReservedKeyImpl.failOnReservedKey(key);
        final String encodedValue = getSharedPreferences().getString(key, null);
        if (encodedValue == null) {
            return null;
        }
        final byte[] encryptedBytes = Base64.decode(encodedValue, Base64.NO_WRAP);
        if (encryptedBytes.length == 0) {
            return null;
        }
        final SecretKey secretKey = getMasterKey();
        if (secretKey == null) {
            return null;
        }
        return AesGcmImpl.decrypt(encryptedBytes, secretKey, identifier);
    }

    /**
     * Put encoded raw value to the shared preferences.
     *
     * @param key Key to be used for storing the encoded raw value.
     * @param value Encoded raw value to be stored. If value is {@code null} then it's equal to {@link #remove(String)}.
     */
    private void setRawValue(@NonNull String key, @Nullable byte[] value) {
        ReservedKeyImpl.failOnReservedKey(key);
        final SecretKey secretKey = getMasterKey();
        if (secretKey == null) {
            // Do not modify entry in case that the secret key is not available.
            return;
        }
        final String encryptedString;
        if (value == null) {
            // null value is equal to remove data.
            encryptedString = null;
        } else {
            final byte[] encryptedValue = AesGcmImpl.encrypt(value, secretKey, identifier);
            if (encryptedValue == null) {
                // Do not delete entry if encryption failed.
                return;
            }
            encryptedString = Base64.encodeToString(encryptedValue, Base64.NO_WRAP);
        }
        getSharedPreferences()
                .edit()
                .putString(key, encryptedString)
                .apply();
    }

    /**
     * Acquire {@link SecretKey} for encryption and decryption purposes, from the symmetric key provider.
     * @return Instance of {@link SecretKey} or {@code null} in case of failure.
     */
    @Nullable
    private SecretKey getMasterKey() {
        final SecretKey masterSecretKey = keyProvider.getOrCreateSecretKey(context, false);
        if (masterSecretKey == null) {
            PA2Log.e("EncryptedKeychain: " + identifier + ": Unable to acquire master key.");
        }
        return masterSecretKey;
    }
}
