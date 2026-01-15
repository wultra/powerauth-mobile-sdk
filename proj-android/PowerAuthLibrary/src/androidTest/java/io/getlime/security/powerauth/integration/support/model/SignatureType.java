/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.model;

import androidx.annotation.NonNull;

public enum SignatureType {
    ECDSA("ECDSA"),
    MLDSA("MLDSA")
    ;

    @NonNull
    public final String typeValue;

    SignatureType(@NonNull String typeValue) {
        this.typeValue = typeValue;
    }

    public static @NonNull SignatureType signatureTypeFromString(String typeValue) {
        for (SignatureType v : values()) {
            if (v.typeValue.equals(typeValue)) {
                return v;
            }
        }
        throw new IllegalArgumentException("Invalid signature type " + typeValue);
    }
}
