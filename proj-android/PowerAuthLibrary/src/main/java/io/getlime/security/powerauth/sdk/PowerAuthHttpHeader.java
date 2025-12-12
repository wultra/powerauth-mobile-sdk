/*
 * Copyright 2025 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.CoreHttpHeader;

/**
 * Class representing HTTP header generated in PowerAuth mobile SDK.
 */
public class PowerAuthHttpHeader {
    @NonNull
    private final String key;
    @NonNull
    private final String value;

    /**
     * Construct HTTP header object with header's name and value.
     * @param key Header's name.
     * @param value Header's value.
     */
    public PowerAuthHttpHeader(@NonNull String key, @NonNull String value) {
        this.key = key;
        this.value = value;
    }

    /**
     * @return HTTP header's key.
     */
    @NonNull
    public String getKey() {
        return key;
    }

    /**
     * @return HTTP header's value.
     */
    @NonNull
    public String getValue() {
        return value;
    }

    /**
     * Convert instance of {@link CoreHttpHeader} into {@link PowerAuthHttpHeader}.
     * @param header Core header object.
     * @return {@link PowerAuthHttpHeader}
     */
    public static PowerAuthHttpHeader fromCoreObject(CoreHttpHeader header) {
        return new PowerAuthHttpHeader(header.getKey(), header.getValue());
    }
}
