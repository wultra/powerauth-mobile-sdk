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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.getlime.security.powerauth.core.ActivationStep1Param;

/**
 * Class for parsing the OTP code.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class OtpUtil {

    private static final String ACT_CODE_PATTERN = "^([A-Z2-7]{5}-[A-Z2-7]{5})-([A-Z2-7]{5}-[A-Z2-7]{5})(#([A-Za-z0-9+=]*))?$";

    public static Otp parseFromActivationCode(String activationCode) {
        final Pattern pattern = Pattern.compile(ACT_CODE_PATTERN);
        final Matcher matcher = pattern.matcher(activationCode.trim());

        if (matcher.find()) {
            try {
                String activationIdShort = matcher.group(1);
                String activationOtp = matcher.group(2);
                String activationSignature = matcher.group(3);

                return new Otp(activationIdShort, activationOtp, activationSignature);
            } catch (IllegalStateException | IndexOutOfBoundsException e) { // invalid pattern match
                return null;
            }
        } else {
            return null;
        }
    }

}
