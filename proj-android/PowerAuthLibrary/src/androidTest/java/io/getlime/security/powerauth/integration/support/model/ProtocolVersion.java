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

package io.getlime.security.powerauth.integration.support.model;

import android.support.annotation.NonNull;

public enum ProtocolVersion {
    V2(20),
    V3(30),
    V3_1(31);

    public int version;

    ProtocolVersion(int version) {
        this.version = version;
    }

    public static @NonNull ProtocolVersion versionFromInt(int version) {
        for (ProtocolVersion v : values()) {
            if (v.version == version) {
                return v;
            }
        }
        throw new IllegalArgumentException("Invalid protocol version " + version);
    }
}
