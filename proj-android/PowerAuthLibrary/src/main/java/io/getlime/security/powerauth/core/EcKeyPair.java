/*
 * Copyright 2022 Wultra s.r.o.
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
 * The `EcKeyPair` represents pair of public and private keys for elliptic curve based cryptography
 * routines. The PowerAuth is using NIST P-256 curve under the hood.
 */
public class EcKeyPair {

    private final EcPrivateKey privateKey;
    private final EcPublicKey publicKey;

    /**
     * Create object with private and public key part.
     * @param privateKey Private key.
     * @param publicKey Public key.
     */
    public EcKeyPair(@NonNull EcPrivateKey privateKey, @NonNull EcPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Get public key.
     * @return {@link EcPublicKey} object.
     */
    @NonNull
    public EcPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get private key.
     * @return {@link EcPrivateKey} object.
     */
    @NonNull
    public EcPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Destroy both public and private key part.
     */
    public void destroy() {
        publicKey.destroy();
        privateKey.destroy();
    }
}
