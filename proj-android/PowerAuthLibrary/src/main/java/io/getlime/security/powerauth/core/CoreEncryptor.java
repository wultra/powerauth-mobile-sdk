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
import androidx.annotation.Nullable;

/**
 * The {@code CoreEncryptor} implement End-To-End Encryption in PowerAuth protocol.
 * The object can be used only once for request encryption and response decryption.
 * If you want to encrypt another request, then you have to construct a new encryptor.
 */
public class CoreEncryptor extends NativeObject {

    @CoreEncryptorScope
    private final int scope;

    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     * @param scope Encryptor's scope.
     */
    protected CoreEncryptor(long nativeObjectHandle, @CoreEncryptorScope int scope) {
        super(nativeObjectHandle);
        this.scope = scope;
    }

    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public void destroy() {
        safeNativeDestroy(nativeObjectHandle);
    }

    /**
     * @return Get scope of the encryptor.
     */
    @CoreEncryptorScope
    public int getScope() {
        return scope;
    }

    /**
     * @return {@code true} if encryptor is ready for request encryption.
     */
    public native boolean canEncryptRequest();

    /**
     * @return {@code true} if encryptor is ready for response decryption.
     */
    public native boolean canDecryptResponse();

    /**
     * Encrypt request body.
     * @param requestBody Data with request body to encrypt.
     * @return Encrypted request.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreEncryptedRequest encryptRequest(@Nullable byte[] requestBody) throws CoreException;

    /**
     * Decrypt response received from the server.
     * @param response Object with received response.
     * @return Decrypted response.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native byte[] decryptResponse(@NonNull CoreEncryptedResponse response) throws CoreException;
}
