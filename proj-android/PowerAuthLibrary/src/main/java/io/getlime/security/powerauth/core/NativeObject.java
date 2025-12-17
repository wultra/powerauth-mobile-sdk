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
 * The {@code NativeObject} is a base class for all objects wrapping a native C++ object.
 */
public class NativeObject {

    static {
        NativeModule.loadNativeModule();
    }

    /**
     * Constant representing a NULL handle.
     */
    public static final long NATIVE_NULL = 0L;

    /**
     * Contains handle to underlying native object.
     */
    protected final long nativeObjectHandle;

    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     * @param nativeObjectHandle Handle to native object.
     */
    protected NativeObject(long nativeObjectHandle) {
        this.nativeObjectHandle = nativeObjectHandle;
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
     * Get information whether the underlying native object is already destroyed.
     * @return {@code true} if underlying native object is already destroyed, {@code false} otherwise.
     */
    public boolean isNativeObjectDestroyed() {
        return isNativeDestroyed(nativeObjectHandle);
    }

    protected void finalize() {
        // Destroy from GC
        safeNativeDestroy(nativeObjectHandle);
    }

    /**
     * Safe destroy underlying native object.
     * @param handle Handle to native object.
     */
    private native static void safeNativeDestroy(long handle);

    /**
     * Get information whether the underlying native object is already destroyed.
     * @param handle Handle to native object.
     * @return {@code true} if underlying native object is already destroyed, {@code false} otherwise.
     */
    private native static boolean isNativeDestroyed(long handle);
}
