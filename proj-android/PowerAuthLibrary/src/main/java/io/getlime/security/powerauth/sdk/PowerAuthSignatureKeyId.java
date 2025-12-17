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
import static io.getlime.security.powerauth.sdk.PowerAuthSignatureKeyId.*;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;

import io.getlime.security.powerauth.core.CoreSignatureKeyId;

/**
 * The {@code PowerAuthCoreSignatureKeyId} enumeration defines keys available for
 * signature calculation or verification.
 * <p>
 * The following key categories are available:
 * <ul>
 *  <li><b>"master"</b> keys are used to verify data signed on the server.
 *      These keys can be used with or without an activation present in {@link PowerAuthSDK}.</li>
 *
 *  <li><b>"server"</b> keys are personalized keys uniquely associated with an activation.
 *      You can use these keys to verify data signed on the server.</li>
 *
 *  </li><b>"device"</b> keys are unique keys stored locally on the device and associated with an activation.
 *       You can use these keys to sign data and to verify previously signed data.</li>
 *  </ul>
 * If the {@link PowerAuthAlgorithm} specified in {@link PowerAuthConfiguration} includes more than one algorithm,
 * you can choose a specific key type or use all keys for the operation.
 * Note that currently, only the API for JWS signatures supports hybrid signatures.
 */
@Retention(SOURCE)
@IntDef({MASTER, MASTER_EC, MASTER_ML_DSA, SERVER, SERVER_EC, SERVER_ML_DSA,
        DEVICE, DEVICE_EC, DEVICE_ML_DSA, MAC_PERSONALIZED})
public @interface PowerAuthSignatureKeyId {
    /**
     * Use all available "master" keys for signature verification.
     */
    int MASTER = CoreSignatureKeyId.MASTER;
    /**
     * Use only the EC-based "master" key for ECDSA signature verification.
     */
    int MASTER_EC = CoreSignatureKeyId.MASTER_EC;
    /**
     * Use only the ML-DSA-based "master" key for ML-DSA signature verification.
     */
    int MASTER_ML_DSA = CoreSignatureKeyId.MASTER_ML_DSA;
    /**
     * Use all available "server" keys for signature verification.
     */
    int SERVER = CoreSignatureKeyId.SERVER;
    /**
     * Use only the EC-based "server" key for ECDSA signature verification.
     */
    int SERVER_EC = CoreSignatureKeyId.SERVER_EC;
    /**
     * Use only the ML-DSA-based "server" key for ML-DSA signature verification.
     */
    int SERVER_ML_DSA = CoreSignatureKeyId.SERVER_ML_DSA;
    /**
     * Use all available "device" keys for signature computation or verification.
     */
    int DEVICE = CoreSignatureKeyId.DEVICE;
    /**
     * Use only the EC-based "device" key for ECDSA signature computation or verification.
     */
    int DEVICE_EC = CoreSignatureKeyId.DEVICE_EC;
    /**
     * Use only the ML-DSA-based "device" key for ML-DSA signature computation or verification.
     */
    int DEVICE_ML_DSA = CoreSignatureKeyId.DEVICE_ML_DSA;
    /**
     * Use the KMAC-based symmetric key for MAC verification.
     * <p>
     * This key is available only when an activation is present.
     * <p>
     * Note that the key is not supported in JWS routines.
     */
    int MAC_PERSONALIZED = CoreSignatureKeyId.MAC_PERSONALIZED;
}
