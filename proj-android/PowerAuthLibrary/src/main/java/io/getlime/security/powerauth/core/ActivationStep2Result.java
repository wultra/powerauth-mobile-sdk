/*
 * Copyright 2017 Wultra s.r.o.
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
 * Result from 2nd step of activation.
 */
public class ActivationStep2Result {

    /**
     * Error code returned from the C++ code. The value can be compared
     * to constants from {@link ErrorCode} class.
     */
    @ErrorCode
    public final int errorCode;

    /**
     * Short, human readable string, calculated from device's public key.
     * You can display this code to the UI and user can confirm visually
     * if the code is the same on both, server &amp; client sides. This feature
     * must be supported on the server's side of the activation flow.
     */
    public final String activationFingerprint;

    public ActivationStep2Result() {
        this.errorCode = ErrorCode.OK;
        this.activationFingerprint = null;
    }
}
