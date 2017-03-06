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

package io.getlime.security.powerauth.keychain;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

/**
 * Simple class encapsulating data storage.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PA2Keychain {

    private String identifier;

    /**
     * Default constructor, intialize keychain with given identifier.
     * @param identifier Identifier.
     */
    public PA2Keychain(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Check if there are some data available for given key.
     * @param context Context.
     * @param key Key to be checked.
     * @return True in case there are some data under given key, false otherwise.
     */
    public synchronized boolean containsDataForKey(@NonNull Context context, @NonNull String key) {
        String serializedStateString = context.getSharedPreferences(identifier, Context.MODE_PRIVATE).getString(key, null);
        if (serializedStateString == null) {
            return false;
        }
        return true;
    }

    /**
     * Return data for given key.
     * @param context Context.
     * @param key Key to be used for data retrieval.
     * @return Stored bytes in case there are some data under given key, 'null' otherwise.
     */
    public synchronized byte[] dataForKey(@NonNull Context context, @NonNull String key) {
        String serializedStateString = context.getSharedPreferences(identifier, Context.MODE_PRIVATE).getString(key, null);
        if (serializedStateString == null) {
            return null;
        }
        return Base64.decode(serializedStateString, Base64.DEFAULT);
    }

    /**
     * Store data for given key.
     * @param context Context.
     * @param data Data to be stored.
     * @param key Key to be used for storing data.
     */
    public synchronized void putDataForKey(@NonNull Context context, @Nullable byte[] data, @NonNull String key) {
        String serializedStateString = Base64.encodeToString(data, Base64.DEFAULT);
        context.getSharedPreferences(identifier, Context.MODE_PRIVATE)
                .edit()
                .putString(key, serializedStateString)
                .apply();
    }

    /**
     * Return data for given key.
     * @param context Context.
     * @param key Key to be used for data removal.
     * @return True in case there was some data under given key and it was removed, 'null' otherwise.
     */
    public synchronized boolean removeDataForKey(@NonNull Context context, @NonNull String key) {
        String serializedStateString = context.getSharedPreferences(identifier, Context.MODE_PRIVATE).getString(key, null);
        if (serializedStateString == null) {
            return false;
        }
        context.getSharedPreferences(identifier, Context.MODE_PRIVATE)
                .edit()
                .remove(key)
                .apply();
        return true;
    }

}
