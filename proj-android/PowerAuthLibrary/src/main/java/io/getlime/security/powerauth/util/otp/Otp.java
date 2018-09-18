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

package io.getlime.security.powerauth.util.otp;

/**
 * Class representing the activation code.
 */
public class Otp {

    /**
     * Short activation ID
     */
    @Deprecated
    public final String activationIdShort;
    /**
     * Activation OTP (one time password)
     */
    @Deprecated
    public final String activationOtp;

    /**
     * Activation code, without signature part.
     */
    public final String activationCode;
    /**
     * Signature calculated from activationIdShort and activationOtp.
     * The value is typically optional for cases, when the user re-typed activation code
     * manually.
     */
    public final String activationSignature;

    /**
     * Dummy constructor. The object is initialized in the JNI code.
     */
    public Otp() {
        this.activationIdShort = null;
        this.activationOtp = null;
        this.activationCode = null;
        this.activationSignature = null;
    }

    //
    // Getters for compatibility with older codes
    //
    @Deprecated
    public String getActivationIdShort() {
        return activationIdShort;
    }

    @Deprecated
    public String getActivationOtp() {
        return activationOtp;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public String getActivationSignature() {
        return activationSignature;
    }

}
