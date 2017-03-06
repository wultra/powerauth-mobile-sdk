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

package io.getlime.security.powerauth.core;

public class ActivationStatus {
    /**
     The activation is just created.
     */
    public static final int State_Created  = 1;
    /**
     The OTP was already used.
     */
    public static final int State_OTP_Used = 2;
    /**
     The shared secure context is valid and active.
     */
    public static final int State_Active   = 3;
    /**
     The activation is blocked.
     */
    public static final int State_Blocked  = 4;
    /**
     The activation doesn't exist anymore.
     */
    public static final int State_Removed  = 5;
    
    
    /**
     Error code returned from the C++ code. The value can be compared
     to constants from ErrorCode class.
     */
    public final int errorCode;
    /**
     State of the activation. You can compare this value to State_XXX constants.
     */
    public final int state;
    /**
     Number of failed authentication attempts in a row.
     */
    public final int failCount;
    /**
     Maximum number of allowed failed authentication attempts in a row.
     */
    public final int maxFailCount;
    
    /**
     Signing counter on the server's side. This value is usable only
     for the debugging purposes. You should avoid dumping this value
     to the debug console.
     */
    public final long counter;
    

    public ActivationStatus() {
        this.errorCode = 0;
        this.state = 0;
        this.failCount = 0;
        this.maxFailCount = 0;
        this.counter = 0;
    }
}