/*
 * Copyright 2021 Wultra s.r.o.
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
 * The {@code ActivationCode} class contains parsed components from user-provided activation, or recovery
 * code. You can use methods from {@link ActivationCodeUtil} class to fill this object with a valid data.
 */
public class ActivationCode {
    /**
     * If object is constructed from an activation code, then property contains just a code, without a signature part.
     * If object is constructed from a recovery code, then property contains just a code, without an optional "R:" prefix.
     */
    public final String activationCode;
    /**
     * Signature calculated from {@link #activationCode}. The value is typically optional for cases,
     * when the user re-typed activation code manually.
     *
     * If object is constructed from a recovery code, then the activation signature part is always empty.
     */
    public final String activationSignature;

    /**
     * Dummy constructor. The object is initialized in the JNI code.
     */
    public ActivationCode() {
        this.activationCode = null;
        this.activationSignature = null;
    }

    //
    // Getters for compatibility with older codes
    //
    public String getActivationCode() {
        return activationCode;
    }

    public String getActivationSignature() {
        return activationSignature;
    }
}
