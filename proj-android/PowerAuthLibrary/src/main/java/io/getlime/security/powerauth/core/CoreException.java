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

import androidx.annotation.Nullable;

/**
 * The {@code CoreException} class contains failure information produced in "core" part of SDK.
 */
public class CoreException extends Exception {
    /**
     * Construct exception with
     * @param errorCode Error code with reason of failure.
     * @param message Error message.
     * @param additionalFailureInfo Additional error info reported from C++ code.
     */
    public CoreException(@CoreErrorCode int errorCode, @Nullable String message, @Nullable String[] additionalFailureInfo) {
        super(message);
        this.errorCode = errorCode;
        this.additionalFailureInfo = additionalFailureInfo;
    }

    @CoreErrorCode
    private final int errorCode;

    @Nullable
    private final String[] additionalFailureInfo;

    /**
     * Get error code wth reason of failure.
     * @return Error code wth reason of failure
     */
    @CoreErrorCode
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Get additional error info reported from C++ code.
     * @return Additional error info reported from C++ code.
     */
    @Nullable
    public String[] getAdditionalFailureInfo() {
        return additionalFailureInfo;
    }
}
