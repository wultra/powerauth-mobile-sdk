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

package io.getlime.security.powerauth.core.response;

import androidx.annotation.Nullable;

import java.util.Map;

import io.getlime.security.powerauth.core.CoreActivationState;
import jakarta.validation.constraints.Null;

/**
 * The {@code CoreActivationStatus} object represents complete status of the activation.
 */
public class CoreActivationStatus {
    @CoreActivationState
    private final int state;
    private final int failCount;
    private final int maxFailCount;
    private final int remainingAttempts;
    private final boolean isProtocolUpgradeAvailable;
    private final boolean isCounterSynchronizationRecommended;
    private final boolean isSessionSerializationNeeded;
    private final boolean isRemoveBiometricKekRecommended;
    @Nullable
    private final Long blockExpirationTime;
    @Nullable
    private final Map<String, Object> customObject;

    /**
     * Construct status with given parameters
     * @param state State of the activation.
     * @param failCount Number of failed authentication attempts in a row.
     * @param maxFailCount Maximum number of allowed failed authentication attempts in a row.
     * @param remainingAttempts Remaining attempts.
     * @param isProtocolUpgradeAvailable Contains true if upgrade to a newer protocol version is available.
     * @param isCounterSynchronizationRecommended Contains true if dummy authentication code calculation is recommended to prevent the counter's de-synchronization.
     * @param isSessionSerializationNeeded Contains true if session's state should be serialized after the successful activation status decryption.
     * @param isRemoveBiometricKekRecommended Contains true if biometric KEK should be removed from Android Keystore.
     * @param blockExpirationTime If the activation is temporarily blocked, contains the time when it will be unblocked.
     * @param customObject Contains custom object returned from the server.
     */
    public CoreActivationStatus(int state,
                                int failCount,
                                int maxFailCount,
                                int remainingAttempts,
                                boolean isProtocolUpgradeAvailable,
                                boolean isCounterSynchronizationRecommended,
                                boolean isSessionSerializationNeeded,
                                boolean isRemoveBiometricKekRecommended,
                                @Nullable Long blockExpirationTime,
                                @Nullable Map<String, Object> customObject) {
        this.state = state;
        this.failCount = failCount;
        this.maxFailCount = maxFailCount;
        this.remainingAttempts = remainingAttempts;
        this.isProtocolUpgradeAvailable = isProtocolUpgradeAvailable;
        this.isCounterSynchronizationRecommended = isCounterSynchronizationRecommended;
        this.isSessionSerializationNeeded = isSessionSerializationNeeded;
        this.isRemoveBiometricKekRecommended = isRemoveBiometricKekRecommended;
        this.blockExpirationTime = blockExpirationTime;
        this.customObject = customObject;
    }

    /**
     * @return State of the activation.
     */
    @CoreActivationState
    public int getState() {
        return state;
    }

    /**
     * @return Number of failed authentication attempts in a row.
     */
    public int getFailCount() {
        return failCount;
    }

    /**
     * @return Maximum number of allowed failed authentication attempts in a row.
     */
    public int getMaxFailCount() {
        return maxFailCount;
    }

    /**
     * @return Remaining attempts calculated as  (maxFailCount - failCount) if state is {@link CoreActivationState#ACTIVE},
     * otherwise {@code 0}.
     */
    public int getRemainingAttempts() {
        return remainingAttempts;
    }

    /**
     * @return true if upgrade to a newer protocol version is available.
     */
    public boolean isProtocolUpgradeAvailable() {
        return isProtocolUpgradeAvailable;
    }

    /**
     * @return true if dummy authentication code calculation is recommended to prevent the counter's de-synchronization.
     */
    public boolean isCounterSynchronizationRecommended() {
        return isCounterSynchronizationRecommended;
    }

    /**
     * @return true if session's state should be serialized after the successful activation status decryption.
     */
    public boolean isSessionSerializationNeeded() {
        return isSessionSerializationNeeded;
    }

    /**
     * @return true if biometric KEK should be removed from Android Keystore.
     */
    public boolean isRemoveBiometricKekRecommended() {
        return isRemoveBiometricKekRecommended;
    }

    /**
     * @return  If the activation is temporarily blocked, returns the time when it will be unblocked.
     */
    @Nullable
    public Long getBlockExpirationTime() {
        return blockExpirationTime;
    }

    /**
     * @return Custom object returned from the server. The value is optional and PowerAuth Application Server
     * must support this custom object.
     */
    @Nullable
    public Map<String, Object> getCustomObject() {
        return customObject;
    }
}
