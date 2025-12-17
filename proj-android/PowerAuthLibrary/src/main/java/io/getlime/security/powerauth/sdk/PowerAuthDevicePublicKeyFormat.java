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

import static java.lang.annotation.RetentionPolicy.SOURCE;
import static io.getlime.security.powerauth.sdk.PowerAuthDevicePublicKeyFormat.*;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;

import io.getlime.security.powerauth.core.CoreDevicePublicKeyFormat;

/**
 * The {@code PowerAuthDevicePublicKeyFormat} enumeration defines the output format used when exporting
 * the device public key.
 */
@Retention(SOURCE)
@IntDef({DER, RAW})
public @interface PowerAuthDevicePublicKeyFormat {
    /**
     * DER key format, which corresponds to the SPKI or X.509 structure.
     */
    int DER = CoreDevicePublicKeyFormat.DER;
    /**
     * RAW key format. The actual output depends on the key type:
     * <ul>
     *  <li>For EC-based keys, the output data is ASN.1 encoded, as specified in ANSI X9.63.</li>
     *  <li>For ML-DSA-based keys, the output data is obtained using the OpenSSL
     *   {@code EVP_PKEY_get_raw_public_key()} function.</li>
     * </ul>
     */
    int RAW = CoreDevicePublicKeyFormat.RAW;
}
