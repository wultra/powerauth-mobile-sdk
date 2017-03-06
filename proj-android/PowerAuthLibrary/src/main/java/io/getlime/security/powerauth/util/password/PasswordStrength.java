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

package io.getlime.security.powerauth.util.password;

/**
 * Enum representing the password strength.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public enum PasswordStrength {
    INVALID,        // Password cannot be evaluated (i.e., invalid PIN).
    WEAK,           // Weak password - indicate password weakness
    NORMAL,         // Normal password - this should be shown as OK
    STRONG          // String password - this should be rewarded
}
