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
 * The `EcPublicKey` represents public key for elliptic curve based cryptography routines.
 * The PowerAuth is using NIST P-256 curve under the hood.
 */
public class EcPublicKey {

    static {
        System.loadLibrary("PowerAuth2Module");
    }

    /**
     * Constructs a new public key with public key data.
     * @param publicKeyData Public key data bytes.
     */
    public EcPublicKey(@NonNull byte[] publicKeyData) {
        this.handle = init(publicKeyData);
    }

    /**
     * Private constructor used from JNI.
     * @param handle Pointer to native underlying object.
     */
    private EcPublicKey(long handle) {
        this.handle = handle;
    }

    /**
     * Pointer to native underlying object.
     */
    private long handle;

    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public synchronized void destroy() {
        if (this.handle != 0) {
            destroy(this.handle);
            this.handle = 0;
        }
    }

    /**
     Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }

    /**
     * Internal JNI destroy.
     *
     * @param handle A handle representing underlying native C++ object
     */
    private native void destroy(long handle);

    /**
     * Internal JNI initialization.
     *
     * @param publicKeyData EC public key bytes.
     * @return A handle representing underlying native C++ object.
     */
    private native long init(@NonNull byte[] publicKeyData);

    /**
     * Return byte array representing a public key.
     * @return Array with public key data bytes or null if object is no longer valid.
     */
    @Nullable
    public native byte[] getPublicKeyData();
}
