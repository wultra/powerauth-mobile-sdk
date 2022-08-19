/*
 * Copyright 2022 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import java.nio.charset.Charset;

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.core.Password;

/**
 * The {@code PowerAuthAuthenticationHelper} class reveal some methods visible internally only in
 * ".sdk" package for testing purposes. The method also contains password helpers.
 */
public class PowerAuthAuthenticationHelper {
    /**
     * Enable or disable strict mode for PowerAuthAuthentication usage validation. See
     * {@link PowerAuthAuthentication#setStrictValidateAuthenticationUsage(boolean)} for more details.
     * @param strictMode Enable or disable strict mode.
     */
    public static void setStrictModeForUsageValidation(boolean strictMode) {
        PowerAuthAuthentication.setStrictValidateAuthenticationUsage(strictMode);
    }

    /**
     * Extract plaintext password from PowerAuthAuthentication's password.
     * @param authentication Authentication that should contain password.
     * @return Extracted password.
     */
    @NonNull
    public static String extractPlaintextPassword(@NonNull PowerAuthAuthentication authentication) {
        if (authentication.getPassword() == null) {
            throw new IllegalArgumentException("Authentication object has no password set");
        }
        return extractPlaintextPassword(authentication.getPassword());
    }

    /**
     * Extract plaintext password from Password object.
     * @param password Password object.
     * @return Extracted password.
     */
    @NonNull
    public static String extractPlaintextPassword(@NonNull Password password) {
        final String[] result = new String[1];
        password.validatePasswordComplexity(passwordBytes -> {
            result[0] = new String(passwordBytes, Charset.defaultCharset());
            return 0;
        });
        return result[0];
    }
}
