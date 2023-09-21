/*
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk.impl;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The `KVHelper` class provides a type-safe access to values stored in the {@code Map<K, Object>}.
 * The object is typically useful while processing data deserialized from JSON.
 *
 * @param <K> Type of key in the map.
 */
public class KVHelper<K> {

    /**
     * Map to use in the helper.
     */
    public final @NonNull Map<K, Object> map;

    /**
     * Construct helper with given map.
     * @param map Map to use in the helper.
     */
    public KVHelper(Map<K, Object> map) {
        this.map = map != null ? map : Collections.emptyMap();
    }

    /**
     * Get a string value for given key.
     * @param key Key to retrieve the string value.
     * @return String for given key or null if no such item is stored in the map.
     */
    @Nullable
    public String valueAsString(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof String ? (String) v : null;
    }

    /**
     * Get a multiline string value for given key. The returned string doesn't contain CR-LF endings.
     * @param key Key to retrieve the string value.
     * @return Multiline string for given key or null if no such item is stored in the map.
     */
    @Nullable
    public String valueAsMultilineString(@NonNull K key) {
        final String s = valueAsString(key);
        if (s != null) {
            return s.replace("\r\n", "\n");
        }
        return s;
    }

    /**
     * Get a boolean value for given key.
     * @param key Key to retrieve the boolean value.
     * @return Boolean for given key or false if no such item is stored in the map.
     */
    public boolean valueAsBool(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof Boolean ? (Boolean) v : false;
    }

    /**
     * Get a map for given key.
     * @param key Key to retrieve the map.
     * @return Map for given key or false if no such item is stored.
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public Map<K, Object> valueAsMap(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof Map ? (Map<K, Object>) v : null;
    }

    /**
     * Get a Date created from timestamp in seconds, stored for the given key.
     * @param key Key to retrieve the timestamp.
     * @return Date created from value for given key or null if no such item is stored in the map.
     */
    @Nullable
    public Date valueAsTimestamp(@NonNull K key) {
        final Object v = map.get(key);
        if (v instanceof Number) {
            return new Date(1000 * ((Number) v).longValue());
        }
        return null;
    }

    /**
     * Get a Date created from string value stored for the given key.
     * @param key Key to retrieve the date.
     * @param format Format of date.
     * @return Date created from value for given key, or null if no such item is stored in the map.
     */
    @Nullable
    public Date valueAsDate(@NonNull K key, @NonNull String format) {
        final String v = valueAsString(key);
        if (v != null) {
            try {
                return new SimpleDateFormat(format, Locale.US).parse(v);
            } catch (ParseException e) {
                return null;
            }
        }
        return null;
    }
}
