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
 * The {@code CoreConfig} object contains configuration for {@link CoreSession} object.
 */
public class CoreConfig extends NativeObject {

    /**
     * Construct object with handle to native object. This is a designated constructor used from JNI,
     * when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to native object.
     */
    protected CoreConfig(long nativeObjectHandle) {
        super(nativeObjectHandle);
    }

    /**
     * Validate SDK configuration string.
     * @param configuration SDK configuration string to validate.
     * @param algorithm Algorithm to use in the PowerAuth instance.
     */
    public static native void validateConfiguration(@NonNull String configuration, @CoreAlgorithm int algorithm) throws CoreException;

    /**
     * Create instance of {@code CoreConfig} object from the provided parameters.
     * @param configuration SDK configuration string.
     * @param deviceSpecificData Device specific data.
     * @param instanceId Instance identifier.
     * @param algorithm Algorithm to use in the PowerAuth instance.
     * @return New {@link CoreConfig} instance.
     * @throws CoreException with {@link CoreErrorCode#WRONG_PARAMETER} if required parameter is null or empty.
     * @throws CoreException with {@link CoreErrorCode#INVALID_DATA} if SDK configuration string is not valid.
     */
    @NonNull
    public static native CoreConfig build(@NonNull String configuration,
                                          @NonNull byte[] deviceSpecificData,
                                          @NonNull String instanceId,
                                          @CoreAlgorithm int algorithm) throws CoreException;

    /**
     * @return Instance identifier provided in the configuration construction.
     */
    @NonNull
    public native String getInstanceId();

    /**
     * @return Device specific data provided in the configuration construction.
     */
    @NonNull
    public native byte[] getDeviceSpecificData();

    /**
     * @return Algorithm provided in the configuration construction.
     */
    @CoreAlgorithm
    public native int getAlgorithm();
}
