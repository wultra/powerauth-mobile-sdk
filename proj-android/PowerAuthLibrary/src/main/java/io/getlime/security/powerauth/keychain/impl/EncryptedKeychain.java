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
import io.getlime.security.powerauth.keychain.StrongBoxSupport;
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
    private final @NonNull SymmetricKeyProvider regularKeyProvider;
    /**
     * Backup secret key provider that always generate non-StrongBox backed keys.
     */
    private final @Nullable SymmetricKeyProvider backupKeyProvider;
    /**
     * Encoder that helps with the keychain value serialization and deserialization.
     */
    private final @NonNull KeychainValueEncoder valueEncoder;
    /**
     * Defines effective key provider used for this keychain.
     */
    private final @NonNull SymmetricKeyProvider effectiveKeyProvider;
    /**
     * Current StrongBox mode (see STRONGBOX_* constants)
     */
    private final int strongBoxMode;

    /**
     * * Default constructor, initialize keychain with given identifier and symmetric key provider.
     *
     * @param context Android application context.
     * @param identifier String with the keychain identifier.
     * @param secretKeyProvider Object that provides secret key for data encryption and decryption.
     * @param backupSecretKeyProvider Object that provides alternate secret key for data encryption
     *                                and decryption. The parameter is required only for StrongBox
     *                                devices.
     */
    public EncryptedKeychain(
            @NonNull Context context,
            @NonNull String identifier,
            @NonNull SymmetricKeyProvider secretKeyProvider,
            @Nullable SymmetricKeyProvider backupSecretKeyProvider) {
        this.identifier = identifier;
        this.context = context;
        this.regularKeyProvider = secretKeyProvider;
        this.backupKeyProvider = backupSecretKeyProvider;
        this.valueEncoder = new KeychainValueEncoder();
        this.strongBoxMode = determineStrongBoxMode(regularKeyProvider.getStrongBoxSupport());
        this.effectiveKeyProvider = determineEffectiveKeyProvider(strongBoxMode, secretKeyProvider, backupSecretKeyProvider);
    }


    @Nullable
    public static SymmetricKeyProvider determineEffectiveSymmetricKeyProvider(@Nullable SymmetricKeyProvider regular, @Nullable SymmetricKeyProvider backup) {
        if (regular == null) {
            return null;
        }
        final StrongBoxSupport support = regular.getStrongBoxSupport();
        final int strongBoxMode = determineStrongBoxMode(support);
        return determineEffectiveKeyProvider(strongBoxMode, regular, backup);
    }

    /**
     * Determine the current level of StrongBox support on the device.
     *
     * @return Current level of StrongBox support. One of STRONGBOX_* constant is returned.
     */
    private static int determineStrongBoxMode(@NonNull StrongBoxSupport strongBoxSupport) {
        if (strongBoxSupport.isStrongBoxSupported()) {
            return strongBoxSupport.isStrongBoxEnabled() ? STRONGBOX_ENABLED : STRONGBOX_DISABLED;
        }
        return STRONGBOX_NOT_SUPPORTED;
    }

    /**
     * Determine effective key provider depending on StrongBox mode and available key providers.
     *
     * @param strongBoxMode The current StrongBox mode determined by {@link #determineStrongBoxMode(StrongBoxSupport)} function.
     * @param regular Regular symmetric key provider.
     * @param backup Backup symmetric key provider
     * @return Backup symmetric key provider in case that strongBox mode is {@link #STRONGBOX_DISABLED}. For all other cases
     *         the regular symmetric key provider is returned.
     */
    @NonNull
    private static SymmetricKeyProvider determineEffectiveKeyProvider(int strongBoxMode, @NonNull SymmetricKeyProvider regular, @Nullable SymmetricKeyProvider backup) {
        if (strongBoxMode != STRONGBOX_DISABLED) {
            // If mode is not DISABLED, then always use regular key provider. The regular key provider
            // is configured to support StrongBox if device has such support.
            return regular;
        }
        // StrongBox is supported by device, but disabled. The backup key provider must be used
        // because it's always configured as NOT-StrongBox backed.
        if (backup == null) {
            PA2Log.e("EncryptedKeychain: Backup key provider is required but not provided.");
            return regular;
        }
        return backup;
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
    public boolean isStrongBoxBacked() {
        return strongBoxMode == STRONGBOX_ENABLED;
    }

    @Override
    public boolean isReservedKey(@NonNull String key) {
        return ReservedKeyImpl.isReservedKey(key);
    }

    /**
     * @return Integer constant representing the current support of StrongBox.
     */
    public int getStrongBoxMode() {
        return strongBoxMode;
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
        final SharedPreferences.Editor editor = getSharedPreferences().edit();
        editor.clear();
        putVersion(editor);
        editor.apply();
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
     * Constant defines key to {@code SharedPreferences} for integer value that contains version of {#code EncryptedKeychain}.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final String ENCRYPTED_KEYCHAIN_VERSION_KEY = "com.wultra.PowerAuthKeychain.IsEncrypted";

    /**
     * Constant defines legacy version of keychain (e.g. no-encryption at all)
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final int KEYCHAIN_V0 = 0;
    /**
     * Constant defines version 1 of {@code EncryptedKeychain}.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final int KEYCHAIN_V1 = 1;
    /**
     * Constant defines version 2 of {@code EncryptedKeychain}. The difference between V1 and V2 is
     * that V2 contains additional information whether the keychain content is encrypted with StrongBox
     * backed key.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final int KEYCHAIN_V2 = 2;

    /**
     * Evaluate whether {@link SharedPreferences} contains encrypted content. The method is available also
     * for Android devices older than "M".
     *
     * @param preferences {@link SharedPreferences} content to evaluate.
     * @return {@code true} if provided object contains values for encrypted keychain.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static boolean isEncryptedContentInSharedPreferences(@NonNull SharedPreferences preferences) {
        return preferences.getInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, KEYCHAIN_V0) >= KEYCHAIN_V1;
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
                final byte[] decodedBytes = tryDecodeBase64Data(string);
                if (decodedBytes != null) {
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
        putVersion(editor);
        editor.apply();
        return true;
    }

    /**
     * Try to decode provided string as Base64 data. If string is real Base64 data, then return
     * array with decoded bytes, otherwise return null.
     *
     * @param string Possible Base64 data to decode.
     * @return Decoded array of bytes in case that string is real Base64 data, otherwise null.
     */
    private @Nullable byte[] tryDecodeBase64Data(@NonNull String string) {
        try {
            final byte[] decodedBytes = Base64.decode(string, Base64.DEFAULT);
            if (Base64.encodeToString(decodedBytes, Base64.DEFAULT).trim().equals(string.trim())) {
                return decodedBytes;
            }
            return null;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    /**
     * Put the current keychain version and other additional data to {@link SharedPreferences.Editor}.
     * @param editor {@link SharedPreferences.Editor} instance.
     */
    private void putVersion(@NonNull SharedPreferences.Editor editor) {
        editor.putInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, KEYCHAIN_V2);
        editor.putInt(ENCRYPTED_KEYCHAIN_STRONGBOX_KEY, strongBoxMode);
    }

    // StrongBox workaround

    /**
     * Constant defines key to {@code SharedPreferences} for integer value that contains information
     * whether AES encryption key is StrongBox backed. This is required due to unreliability of StrongBox
     * on some devices, so keychain has to track whether encryption key is StrongBox backed or not.
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static final String ENCRYPTED_KEYCHAIN_STRONGBOX_KEY = "com.wultra.PowerAuthKeychain.StrongBoxMode";

    /**
     * StrongBox support is not yet determined.
     */
    public static final int STRONGBOX_NA = 0;
    /**
     * StrongBox is supported and enabled on this device.
     */
    public static final int STRONGBOX_ENABLED = 1;
    /**
     * StrongBox is not supported this device.
     */
    public static final int STRONGBOX_NOT_SUPPORTED = 2;
    /**
     * StrongBox is supported but disabled on this device.
     */
    public static final int STRONGBOX_DISABLED = 3;


    public boolean updateStrongBoxSupport(@NonNull SharedPreferences preferences) {
        // Determine keychain version
        final int keychainVersion = preferences.getInt(ENCRYPTED_KEYCHAIN_VERSION_KEY, KEYCHAIN_V0);
        if (keychainVersion == KEYCHAIN_V0) {
            // This keychain is not encrypted. Return false, because content is already stored
            // in the legacy implementation.
            return false;
        }
        // Get stored StrongBox support.
        final int previousDeviceSupport = preferences.getInt(ENCRYPTED_KEYCHAIN_STRONGBOX_KEY, STRONGBOX_NA);
        if (keychainVersion == KEYCHAIN_V2 && strongBoxMode == previousDeviceSupport) {
            // There's no change in StrongBox support from previous initialization.
            return true;
        }
        // Investigate what was changed since the last keychain initialization.
        final boolean strongBoxSupported = strongBoxMode != STRONGBOX_NOT_SUPPORTED;
        final boolean strongBoxEnabled = strongBoxMode == STRONGBOX_ENABLED;
        boolean reEncryptContent = false;
        boolean result = true;
        if (keychainVersion == KEYCHAIN_V1) {
            // We're still on V1 version of keychain. We need re-encrypt content only if StrongBox
            // is supported but it's not enabled. Basically, this is required only when app did
            // upgrade SDK and now StrongBox is considered as unreliable.
            reEncryptContent = strongBoxSupported && !strongBoxEnabled;
        } else if (keychainVersion == KEYCHAIN_V2) {
            // We're on V2 keychain and it seems that StrongBox support was changed. This typically
            // means that this version of SDK has a different support of StrongBox than previous one.
            // For example, Google did fix its implementation and we decided to re-enable it on
            // this device, or vice versa.
            reEncryptContent = true;
        }
        if (reEncryptContent) {
            if (backupKeyProvider != null) {
                // Now we have to decide the right direction of data re-encryption.
                final SecretKey sourceKey, destinationKey;
                if (strongBoxEnabled) {
                    // If StrongBox is enabled, then we have to re-encrypt data from the backup key
                    // to the regular one.
                    sourceKey = backupKeyProvider.getOrCreateSecretKey(context, false);
                    destinationKey = regularKeyProvider.getOrCreateSecretKey(context, false);
                } else {
                    // StrongBox is disabled, so we have to re-encrypt data from the regular key to the backup one.
                    sourceKey = regularKeyProvider.getOrCreateSecretKey(context, false);
                    destinationKey = backupKeyProvider.getOrCreateSecretKey(context, false);
                }
                if (sourceKey != null && destinationKey != null) {
                    result = reEncryptKeychain(preferences, sourceKey, destinationKey);
                } else {
                    PA2Log.e("EncryptedKeychain: " + identifier + ": Unable to get source or destination encryption key.");
                    result = false;
                }
            } else {
                PA2Log.e("EncryptedKeychain: " + identifier + ": Internal error: Backup provider is not set.");
                result = false;
            }
            if (!result) {
                // This is a special cleanup, that leaves data in V0 (e.g. not encrypted) format. It basically remove all
                // the content from the preferences file.
                PA2Log.e("EncryptedKeychain: " + identifier + ": Data migration failed. Removing all remaining content.");
                preferences.edit()
                        .clear()
                        .apply();
            }
        } else {
            // It looks like that re-encryption is not required.
            final SharedPreferences.Editor editor = preferences.edit();
            putVersion(editor);
            editor.apply();
        }
        return result;
    }

    private boolean reEncryptKeychain(@NonNull SharedPreferences preferences, @NonNull SecretKey source, @NonNull SecretKey destination) {
        boolean result = true;
        // Prepare hash map for decrypted content.
        final Map<String, byte[]> decryptedContent = new HashMap<>();
        // Iterate over all entries stored in the shared preferences.
        for (final Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
            final String key = entry.getKey();
            if (ReservedKeyImpl.isReservedKey(key)) {
                continue;
            }
            final Object value = entry.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            final byte[] encodedValue = decryptRawValue(source, (String)value);
            if (encodedValue == null) {
                PA2Log.e("EncryptedKeychain: " + identifier + ": Failed to decrypt data for key '" + key + "'. Data migration will fail.");
                result = false;
                break;
            }
            decryptedContent.put(key, encodedValue);
        }
        // Now encrypt data with a destination secret key.
        SharedPreferences.Editor editor = preferences.edit();
        if (result) {
            // Now try to encrypt all decrypted data.
            for (final Map.Entry<String, byte[]> entry : decryptedContent.entrySet()) {
                final String key = entry.getKey();
                final byte[] value = entry.getValue();
                final String encryptedValue = encryptRawValue(destination, value);
                if (encryptedValue == null) {
                    PA2Log.e("EncryptedKeychain: " + identifier + ": Failed to encrypt data for key '" + key + "'. Data migration will fail.");
                    result = false;
                    break;
                }
                editor.putString(key, encryptedValue);
            }
            if (result) {
                // If the result is still OK then store version and the current mode to the preferences.
                putVersion(editor);
            }
        }
        editor.apply();
        return result;
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
        final SecretKey secretKey = getMasterKey();
        if (secretKey == null) {
            return null;
        }
        return decryptRawValue(secretKey, encodedValue);
    }

    /**
     * Decrypt Base64 encoded data with secret key.
     * @param secretKey Decryption key.
     * @param encodedValue Base64 string with encrypted value.
     * @return Decrypted raw value or {@code null} in case of failure.
     */
    @Nullable
    private byte[] decryptRawValue(@NonNull SecretKey secretKey, @NonNull String encodedValue) {
        final byte[] encryptedBytes = Base64.decode(encodedValue, Base64.NO_WRAP);
        if (encryptedBytes.length == 0) {
            return null;
        }
        return AesGcmImpl.decrypt(encryptedBytes, secretKey, identifier);
    }

    /**
     * Put encoded raw value to the shared preferences.
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
        if (value != null) {
            encryptedString = encryptRawValue(secretKey, value);
            if (encryptedString == null) {
                // Do not delete entry if encryption failed.
                return;
            }
        } else {
            // null value is equal to remove data.
            encryptedString = null;
        }
        getSharedPreferences()
                .edit()
                .putString(key, encryptedString)
                .apply();
    }

    /**
     * Encrypt encoded raw value with a secret key and return encrypted data encoded in Base64.
     * @param secretKey Encryption key.
     * @param rawValue Bytes to encrypt.
     * @return Base64 string with encrypted value or {@code null} in case of failure.
     */
    @Nullable
    private String encryptRawValue(@NonNull SecretKey secretKey, @NonNull byte[] rawValue) {
        final byte[] encryptedValue = AesGcmImpl.encrypt(rawValue, secretKey, identifier);
        if (encryptedValue != null) {
            return Base64.encodeToString(encryptedValue, Base64.NO_WRAP);
        }
        return null;
    }

    /**
     * Acquire {@link SecretKey} for encryption and decryption purposes, from the symmetric key provider.
     * @return Instance of {@link SecretKey} or {@code null} in case of failure.
     */
    @Nullable
    private SecretKey getMasterKey() {
        final SecretKey masterSecretKey;
        masterSecretKey = effectiveKeyProvider.getOrCreateSecretKey(context, false);
        if (masterSecretKey == null) {
            PA2Log.e("EncryptedKeychain: " + identifier + ": Unable to acquire master key.");
        }
        return masterSecretKey;
    }
}
