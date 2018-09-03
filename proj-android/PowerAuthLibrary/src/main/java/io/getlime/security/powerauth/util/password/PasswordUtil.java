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

package io.getlime.security.powerauth.util.password;

import java.util.Arrays;

/**
 * Class for validating the password strength.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PasswordUtil {

    private static final int PIN_LENGTH_WEAK = 4;
    private static final int PIN_LENGTH_STRONG = 6;

    private static boolean isValid(String password, PasswordType type) {
        return password.matches("^[0-9]{4,}$");
    }

    private static boolean isWeak(String password, PasswordType type) {
        if (password.length() < PIN_LENGTH_WEAK) {
            return true;
        }

        // "PIN Number Analysis" - http://www.datagenetics.com/blog/september32012/
        String[] weakList = new String[] {
                "1234", "1111", "0000", "1212", "7777",
                "1004", "2000", "4444", "2222", "6969",
                "9999", "3333", "5555", "6666", "1122",
                "1313", "8888", "4321", "2001", "1010"
        };
        if (Arrays.asList(weakList).contains(password)) {
            return true;
        }
        return false;
    }

    /**
     * Evaluate provided password strength using logic that depends on a password type.
     * @param password Password to be evaluated.
     * @param type Type of the password (for example, numeric PIN code).
     * @return Estimated password strength.
     */
    public static PasswordStrength evaluateStrength(String password, PasswordType type) {
        if (!PasswordUtil.isValid(password, type)) {
            return PasswordStrength.INVALID;
        }
        if (PasswordUtil.isWeak(password, type)) {
            return PasswordStrength.WEAK;
        }
        boolean strongPin = password.length() >= PIN_LENGTH_STRONG;
        return strongPin ? PasswordStrength.STRONG : PasswordStrength.NORMAL;
    }
}
