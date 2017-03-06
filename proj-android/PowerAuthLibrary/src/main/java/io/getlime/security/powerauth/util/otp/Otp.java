/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class Otp {

    private String activationIdShort;
    private String activationOtp;
    private String activationSignature;

    public Otp(String activationIdShort, String activationOtp, String activationSignature) {
        this.activationIdShort = activationIdShort;
        this.activationOtp = activationOtp;
        this.activationSignature = activationSignature;
    }

    public String getActivationIdShort() {
        return activationIdShort;
    }

    public void setActivationIdShort(String activationIdShort) {
        this.activationIdShort = activationIdShort;
    }

    public String getActivationOtp() {
        return activationOtp;
    }

    public void setActivationOtp(String activationOtp) {
        this.activationOtp = activationOtp;
    }

    public String getActivationSignature() {
        return activationSignature;
    }

    public void setActivationSignature(String activationSignature) {
        this.activationSignature = activationSignature;
    }

}
