/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The <code>ProtocolUpgradeData</code> class contains data required for
 * protocol upgrade. The object is accessed from JNI code.
 */
public class ProtocolUpgradeData {

    public final int toVersion;

    // V3 Fields

    public final String v3CtrData;

    /**
     * Constructs data for upgrade to V3 protocol.
     *
     * @param ctrData initial value for hash-based counter. Base64 string is expected.
     * @return data constructed for upgrade to V3 protocol version
     */
    public static @NonNull ProtocolUpgradeData version3(@NonNull String ctrData) {
        return new ProtocolUpgradeData(ProtocolVersion.V3, ctrData);
    }

    /**
     * Private constructor
     *
     * @param toVersion specifies version of data for upgrade
     * @param v3CtrData initial value for hash-based counter
     */
    private ProtocolUpgradeData(ProtocolVersion toVersion, @Nullable String v3CtrData) {
        this.toVersion = toVersion.numericValue;
        this.v3CtrData = v3CtrData;
    }
}
