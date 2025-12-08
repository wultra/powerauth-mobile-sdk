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

public class NativeObject {

    static {
        NativeModule.loadNativeModule();
    }

    protected static final long NATIVE_NULL = 0L;

    protected final long handle;

    protected NativeObject(long handle) {
        this.handle = handle;
    }

    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public void destroy() {
        safeNativeDestroy(handle);
    }

    public boolean isNativeObjectDestroyed() {
        return isNativeDestroyed(handle);
    }

    protected void finalize() {
        // Destroy from GC
        safeNativeDestroy(handle);
    }

    private native static void safeNativeDestroy(long handle);

    private native static boolean isNativeDestroyed(long handle);
}
