/*
 * Copyright 2026 Wultra s.r.o.
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

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.response.CoreActivationStatus;

/**
 * The {@code PowerAuthActivationStatus} object represents a complete status of the activation.
 */
public class PowerAuthActivationStatus {

    private final CoreActivationStatus coreStatus;

    /**
     * Construct status object with instance of {@link CoreActivationStatus} object.
     * @param coreStatus Core status object.
     */
    public PowerAuthActivationStatus(@NonNull CoreActivationStatus coreStatus) {
        this.coreStatus = coreStatus;
    }

    /**
     * @return State of the activation.
     */
    @PowerAuthActivationState
    public int getState() {
        return coreStatus.getState();
    }

    /**
     * @return Number of failed authentication attempts in a row.
     */
    public int getFailCount() {
        return coreStatus.getFailCount();
    }

    /**
     * @return Maximum number of allowed failed authentication attempts in a row.
     */
    public int getMaxFailCount() {
        return coreStatus.getMaxFailCount();
    }

    /**
     * @return Remaining attempts calculated as {@code (maxFailCount - failCount)} if state is
     * {@link PowerAuthActivationState#ACTIVE}, otherwise {@code 0}.
     */
    public int getRemainingAttempts() {
        return coreStatus.getRemainingAttempts();
    }

    /**
     * @return true if upgrade to a newer protocol version is available.
     */
    public boolean isProtocolUpgradeAvailable() {
        return coreStatus.isProtocolUpgradeAvailable();
    }

    /**
     * @return Instance of {@link CoreActivationStatus} for internal purposes.
     */
    @NonNull
    CoreActivationStatus getCoreStatus() {
        return coreStatus;
    }
}
