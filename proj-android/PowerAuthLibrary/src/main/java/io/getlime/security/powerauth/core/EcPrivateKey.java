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
import androidx.annotation.Nullable;

/**
 * The `EcPrivateKey` represents private key for elliptic curve based cryptography routines.
 * The PowerAuth is using NIST P-256 curve under the hood.
 */
public class EcPrivateKey extends NativeObject {

    /**
     * Constructs a new private key with private key data.
     * @param privateKeyData Private key data bytes.
     */
    public EcPrivateKey(@NonNull byte[] privateKeyData) {
        super(initKey(privateKeyData));
    }

    /**
     * Private constructor used from JNI.
     * @param handle Pointer to native underlying object.
     */
    private EcPrivateKey(long handle) {
        super(handle);
    }

    /**
     * Internal JNI initialization.
     *
     * @param privateKeyData EC private key.
     * @return A handle representing underlying native C++ object.
     */
    private static native long initKey(@NonNull byte[] privateKeyData);

    /**
     * Return byte array representing a private key.
     * @return Array with private key data bytes or null if object is no longer valid.
     */
    @Nullable
    public byte[] getPrivateKeyData() {
        return getKeyData(handle);
    }

    private native static byte[] getKeyData(long handle);
}
