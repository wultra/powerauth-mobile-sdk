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
     * Function tests whether the provided key is reserved by the Keychain implementation. Such key
     * cannot be used to store data to the keychain.
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
    boolean containsDataForKey(@NonNull String key);

    /**
     * Remove data for given key.
     *
     * @param key Key to be used for data removal.
     */
    void removeDataForKey(@NonNull String key);

    /**
     * Remove all data stored in this keychain.
     */
    void removeAll();

    // Byte array accessors

    /**
     * Return data for given key.
     *
     * @param key Key to be used for data retrieval.
     * @return Stored bytes in case there are some data under given key, 'null' otherwise.
     */
    @Nullable byte[] dataForKey(@NonNull String key);

    /**
     * Store data for given key. If data is null then it's equal to {@link #removeDataForKey(String)}
     *
     * @param data Data to be stored.
     * @param key Key to be used for storing data.
     */
    void putDataForKey(@Nullable byte[] data, @NonNull String key);

    // String accessors

    /**
     * Return string for given key.
     *
     * @param key Key to be used for string retrieval.
     * @return Stored string in case there are some data under given key, null otherwise.
     */
    @Nullable String stringForKey(@NonNull String key);

    /**
     * Store string for given key.
     *
     * @param string String to be stored. If value is null then it's equal to {@code removeDataForKey()}
     * @param key Key to be used for storing string.
     */
    void putStringForKey(@Nullable String string, @NonNull String key);
}
