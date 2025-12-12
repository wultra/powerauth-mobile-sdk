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

import androidx.annotation.NonNull;

/**
 * The {@code CoreDevicePublicKeyData} class represents exported device public key data.
 */
public class CoreDevicePublicKeyData {
    @CoreSignatureKeyType
    private final int keyType;
    @NonNull
    private final String keyAlgorithm;
    @NonNull
    private final byte[] keyData;

    /**
     * Construct object with public key type, algorithm and data.
     * @param keyType Type of the public key.
     * @param keyAlgorithm Information about the key algorithm (e.g., "P-256", "P-384", "ML-DSA-65", etc.).
     * @param keyData Public key data.
     */
    public CoreDevicePublicKeyData(@CoreSignatureKeyType int keyType, @NonNull String keyAlgorithm, @NonNull byte[] keyData) {
        this.keyType = keyType;
        this.keyAlgorithm = keyAlgorithm;
        this.keyData = keyData;
    }

    /**
     * @return Type of the public key.
     */
    @CoreSignatureKeyType
    public int getKeyType() {
        return keyType;
    }

    /**
     * @return Information about the key algorithm (e.g., "P-256", "P-384", "ML-DSA-65", etc.).
     */
    @NonNull
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * @return Public key data.
     */
    @NonNull
    public byte[] getKeyData() {
        return keyData;
    }
}
