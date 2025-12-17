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

package io.getlime.security.powerauth.core;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.Algorithm.*;

import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

/**
 * The {@code Algorithm} enumeration defines algorithms available for PowerAuth
 * initialization. The algorithm specifies also the protocol version used for communication
 * with the server.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({LEGACY_P256, EC_P384, EC_P384_ML_L3, EC_P384_ML_L5, DEFAULT})
public @interface Algorithm {
    /**
     * Algorithm identifier for legacy protocol V3.3.
     * <p>
     * If used in {@link PowerAuthConfiguration}, then the protocol upgrade is automatically disabled
     * and instance of {@link PowerAuthSDK} will use legacy protocol only for communicating with the server.
     */
    int LEGACY_P256 = 0;

    /**
     * Algorithm identifier for V4 protocol, using only cryptography based on elliptic curves.
     * The following algorithms are used:
     * <ul>
     * <li>Key agreement: ECDHE with P-384</li>
     * <li>Signatures: ECDSA with P-384</li>
     * </ul>
     */
    int EC_P384 = 1;

    /**
     * Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
     * elliptic curves. The following algorithms are used:
     * <ul>
     * <li>Key agreement: ECDHE with P-384 combined with ML-KEM-768</li>
     * <li>Signatures: ECDSA with P-384 combined with ML-DSA-65</li>
     * </ul>
     */
    int EC_P384_ML_L3 = 2;

    /**
     * Algorithm identifier for V4 protocol, using quantum resistant algorithms combined with
     * elliptic curves. The following algorithms are used:
     * <ul>
     * <li>Key agreement: ECDHE with P-384 combined with ML-KEM-1024</li>
     * <li>Signatures: ECDSA with P-384 combined with ML-DSA-87</li>
     * </ul>
     */
    int EC_P384_ML_L5 = 3;

    /**
     * Default algorithm. Value is identical to {@link #EC_P384_ML_L3}.
     */
    int DEFAULT = EC_P384_ML_L3;
}
