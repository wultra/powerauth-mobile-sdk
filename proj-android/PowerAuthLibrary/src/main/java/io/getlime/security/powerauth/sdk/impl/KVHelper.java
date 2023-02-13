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

    public @NonNull Map<K, Object> map;

    public KVHelper(Map<K, Object> map) {
        this.map = map != null ? map : Collections.emptyMap();
    }

    @Nullable
    public String valueAsString(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof String ? (String) v : null;
    }

    @Nullable
    public String valueAsMultilineString(@NonNull K key) {
        final String s = valueAsString(key);
        if (s != null) {
            return s.replace("\r\n", "\n");
        }
        return s;
    }

    public boolean valueAsBool(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof Boolean ? (Boolean) v : false;
    }

    @SuppressWarnings("unchecked")
    @Nullable
    public Map<K, Object> valueAsMap(@NonNull K key) {
        final Object v = map.get(key);
        return v instanceof Map ? (Map<K, Object>) v : null;
    }

    @Nullable
    public Date valueAsTimestamp(@NonNull K key) {
        final Object v = map.get(key);
        if (v instanceof Number) {
            return new Date(1000 * ((Number) v).longValue());
        }
        return null;
    }

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
