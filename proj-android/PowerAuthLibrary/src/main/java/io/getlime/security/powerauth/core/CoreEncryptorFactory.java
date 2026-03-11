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

/**
 * The {@code CoreEncryptorFactory} is object that construct End-To-End encryptors for
 * general application purpose.
 */
public class CoreEncryptorFactory extends NativeObject {
    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     */
    private CoreEncryptorFactory(long nativeObjectHandle) {
        super(nativeObjectHandle);
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
     * Create encryptor with given scope. If the temporary key for requested scope is not valid,
     * then exception is raised.
     * @param scope Encryptor's scope.
     * @return Instance of {@link CoreEncryptor}.
     * @throws CoreException In case of failure.
     */
    public native CoreEncryptor createEncryptorWithScope(@CoreEncryptorScope int scope) throws CoreException;

    /**
     * Fetch temporary key for given scope from the server.
     *
     * @param scope Temporary key's scope.
     * @return Request object.
     * @throws CoreException In case of failure.
     */
    public native CoreRequest<Object> fetchTemporaryKeyForScope(@CoreEncryptorScope int scope) throws CoreException;

    /**
     * Get information whether there's already pending request for fetching temporary key from the server.
     * @param scope Temporary key's scope.
     * @return {@code true} if there's pending request.
     */
    public native boolean hasPendingRequestForTemporaryKeyWithScope(@CoreEncryptorScope int scope);

    /**
     * Get information whether there's temporary key with requested scope.
     *
     * @param scope Temporary key's scope.
     * @return {@code true} if temporary key is present and is still valid.
     */
    public native boolean hasTemporaryKeyForScope(@CoreEncryptorScope int scope);
}
