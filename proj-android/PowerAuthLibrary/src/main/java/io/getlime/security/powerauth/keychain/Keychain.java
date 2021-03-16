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

package io.getlime.security.powerauth.keychain;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.Set;


/**
 * Simple interface encapsulating secure data storage.
 */
public interface Keychain {

    /**
     * Return keychain identifier.
     *
     * @return String with keychain identifier.
     */
    @NonNull String getIdentifier();

    /**
     * @return {@code true} if content of keychain is encrypted.
     */
    boolean isEncrypted();

    /**
     * @return {@code true} if keychain is encrypted with StrongBox backed key.
     */
    boolean isStrongBoxBacked();

    /**
     * Function tests whether the provided key is reserved by the Keychain implementation. Such key
     * cannot be used to store data to the Keychain. If you try to use such key in Keychain, then
     * {@link IllegalArgumentException} is thrown.
     *
     * @param key Key to be evaluated.
     * @return {@code true} in case that the provided key is reserved.
     */
    boolean isReservedKey(@NonNull String key);

    /**
     * Check if there are some data available for given key.
     *
     * @param key Key to be checked.
     * @return True in case there are some data under given key, false otherwise.
     */
    boolean contains(@NonNull String key);

    /**
     * Remove data for given key.
     *
     * @param key Key to be used for data removal.
     */
    void remove(@NonNull String key);

    /**
     * Remove all data stored in this keychain.
     */
    void removeAll();


    // Byte array accessors

    /**
     * Return array of bytes for given key.
     *
     * @param key Key to be used for data retrieval.
     * @return Stored bytes in case there are some data under given key, {@code null} otherwise.
     */
    @Nullable byte[] getData(@NonNull String key);

    /**
     * Store array of bytes for given key. If data is {@code null} then it's equal to {@link #remove(String)}.
     *
     * @param data Data to be stored. If value is {@code null} then it's equal to {@link #remove(String)}.
     * @param key Key to be used for storing data.
     */
    void putData(@Nullable byte[] data, @NonNull String key);


    // String accessors

    /**
     * Return string for given key.
     *
     * @param key Key to be used for string retrieval.
     * @return Stored string in case there are some string under given key, {@code null} otherwise.
     */
    @Nullable String getString(@NonNull String key);

    /**
     * Return string for given key. If there's no such string stored, then return default value.
     *
     * @param key Key to be used for string retrieval.
     * @param defaultValue Default value to return in case that keychain doesn't contain such key.
     * @return Stored string or default value if there's no such string stored in the keychain under given key.
     */
    @NonNull String getString(@NonNull String key, @NonNull String defaultValue);

    /**
     * Store string for given key. If string is {@code null} then it's equal to {@link #remove(String)}.
     *
     * @param string String to be stored. If value is {@code null} then it's equal to {@link #remove(String)}.
     * @param key Key to be used for storing string.
     */
    void putString(@Nullable String string, @NonNull String key);


    // String Set accessors

    /**
     * Return set of strings for given key. If there's no such set stored, then return {@code null}.
     *
     * @param key Key to be used for set of strings retrieval.
     * @return Stored set of strings in case there are some set under given key, {@code null} otherwise.
     */
    @Nullable Set<String> getStringSet(@NonNull String key);

    /**
     * Store set of strings for given key. If provided set is {@code null} then it's equal to {@link #remove(String)}.
     *
     * @param stringSet Set of strings to be stored. If value is {@code null} then it's equal to {@link #remove(String)}.
     * @param key Key to be used for storing set of strings.
     */
    void putStringSet(@Nullable Set<String> stringSet, @NonNull String key);


    // Boolean accessors

    /**
     * Return boolean value for given key. If there's no such value stored, then return default value.
     *
     * @param key Key to be used for boolean retrieval.
     * @param defaultValue Default value to return in case that keychain doesn't contain such key.
     * @return Stored boolean or default value if there's no such string stored in the keychain under given key.
     */
    boolean getBoolean(@NonNull String key, boolean defaultValue);

    /**
     * Store boolean value for given key.
     *
     * @param value Boolean value to be stored.
     * @param key Key to be used for storing boolean value.
     */
    void putBoolean(boolean value, @NonNull String key);


    // Integer accessors

    /**
     * Return long value for given key. If there's no such value stored, then return default value.
     *
     * @param key Key to be used for long retrieval.
     * @param defaultValue Default value to return in case that keychain doesn't contain such key.
     * @return Stored long or default value if there's no such string stored in the keychain under given key.
     */
    long getLong(@NonNull String key, long defaultValue);

    /**
     * Store long value for given key.
     *
     * @param value long value to be stored.
     * @param key Key to be used for storing long value.
     */
    void putLong(long value, @NonNull String key);


    // Float accessors

    /**
     * Return float value for given key. If there's no such value stored, then return default value.
     *
     * @param key Key to be used for float retrieval.
     * @param defaultValue Default value to return in case that keychain doesn't contain such key.
     * @return Stored float or default value if there's no such string stored in the keychain under given key.
     */
    float getFloat(@NonNull String key, float defaultValue);

    /**
     * Store long value for given key.
     *
     * @param value float value to be stored.
     * @param key Key to be used for storing float value.
     */
    void putFloat(float value, @NonNull String key);
}
