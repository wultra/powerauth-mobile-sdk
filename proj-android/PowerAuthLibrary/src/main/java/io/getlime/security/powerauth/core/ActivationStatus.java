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

import java.util.Map;

public class ActivationStatus {
    /**
     * The activation is just created.
     */
    public static final int State_Created  = 1;
    /**
     * The OTP was already used.
     */
    public static final int State_OTP_Used = 2;
    /**
     * The shared secure context is valid and active.
     */
    public static final int State_Active   = 3;
    /**
     * The activation is blocked.
     */
    public static final int State_Blocked  = 4;
    /**
     * The activation doesn't exist anymore.
     */
    public static final int State_Removed  = 5;
    
    
    /**
     * Error code returned from the C++ code. The value can be compared
     * to constants from ErrorCode class.
     */
    public final int errorCode;
    /**
     * State of the activation. You can compare this value to State_XXX constants.
     */
    public final int state;
    /**
     * Number of failed authentication attempts in a row.
     */
    public final int failCount;
    /**
     * Maximum number of allowed failed authentication attempts in a row.
     */
    public final int maxFailCount;

    /**
     * @return (maxFailCount - failCount) if state is State_Active, otherwise 0.
     */
    public final int getRemainingAttempts() {
        if (state == State_Active) {
            if (maxFailCount >= failCount) {
                return maxFailCount - failCount;
            }
        }
        return 0;
    }

    // Activation version

    /**
     * The activation version currently stored on the server.
     */
    public final ProtocolVersion currentVersion;

    /**
     * Defines version of data supported on the server. If the value is higher than {@link #currentVersion},
     * then the activation upgrade is available.
     */
    public final ProtocolVersion upgradeVersion;

    /**
     * Contains true, if protocol upgrade to newer activation data is available.
     */
    public final boolean isUpgradeAvailable;

    /**
     * Contains custom object received from the server together with the status. The value is optional
     * and the server's implementation must support it.
     */
    private Map<String, Object> customObject;

    // Constructor

    public ActivationStatus() {
        this.errorCode = 0;
        this.state = 0;
        this.failCount = 0;
        this.maxFailCount = 0;
        this.currentVersion = ProtocolVersion.NA;
        this.upgradeVersion = ProtocolVersion.NA;
        this.isUpgradeAvailable = false;
        this.customObject = null;
    }


    /**
     * @param customObject custom object to set
     */
    public void setCustomObject(Map<String, Object> customObject) {
        this.customObject = customObject;
    }

    /**
     * @return custom dictionary received from the server together with the status.
     */
    public Map<String, Object> getCustomObject() {
        return customObject;
    }
}
