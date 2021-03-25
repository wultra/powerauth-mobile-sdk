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

import androidx.annotation.NonNull;

/**
 * The {@code ReservedKeyImpl} is a helper class that determines whether the Keychain key
 * is reserved or not.
 */
class ReservedKeyImpl {

    /**
     * Evaluate whether the provided key is reserved.
     *
     * @param key Key to evaluate.
     * @return {@code true} is key is reserved, otherwise {@code false}.
     */
    static boolean isReservedKey(@NonNull String key) {
        return key.equals(EncryptedKeychain.ENCRYPTED_KEYCHAIN_VERSION_KEY) ||
                key.equals(EncryptedKeychain.ENCRYPTED_KEYCHAIN_MODE_KEY);
    }

    /**
     * Test whether the provided key is reserved and if yes, then throw {@link IllegalArgumentException}.
     * @param key Key to evaluate.
     */
    static void failOnReservedKey(@NonNull String key) {
        if (isReservedKey(key)) {
            throw new IllegalArgumentException("Key '" + key + "' is reserved for Keychain implementation.");
        }
    }
}
