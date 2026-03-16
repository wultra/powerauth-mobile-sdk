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

import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.biometry.BiometryType;

/**
 * {@code PowerAuthBiometricStatus} represents the overall availability of biometric authentication
 * in a {@link PowerAuthSDK} instance.
 */
public class PowerAuthBiometricStatus {

    private final boolean authenticationWithBiometricsAvailable;
    private final boolean biometricFactorConfigured;
    private final @BiometricStatus int systemStatus;
    private final @BiometryType int biometryType;

    /**
     * Construct object with given parameters. The constructor is internal on purpose.
     * @param biometricFactorConfigured {@code true} if biometric factor is configured in PowerAuthSDK.
     * @param biometryType The type of biometric sensor.
     * @param systemStatus The current system status of biometrics.
     */
    PowerAuthBiometricStatus(boolean biometricFactorConfigured,
                             @BiometryType int biometryType,
                             @BiometricStatus int systemStatus) {
        this.authenticationWithBiometricsAvailable = biometricFactorConfigured && systemStatus == BiometricStatus.OK;
        this.biometricFactorConfigured = biometricFactorConfigured;
        this.systemStatus = systemStatus;
        this.biometryType = biometryType;
    }

    /**
     * Get information whether biometric authentication is fully available and you can call methods
     * that accept a {@link PowerAuthAuthentication} object configured for biometrics. Note that
     * this doesn't reflect state when the sensor is temporarily or permanently locked out. Such
     * information is available only after you attempt to authenticate with biometrics.
     * <p>
     * The value is calculated as:
     * <pre>
     * isBiometricFactorConfigured && systemStatus == BiometricStatus.OK
     * </pre>
     * @return {@code true} if biometric authentication is fully available, {@code false} otherwise.
     */
    public boolean isAuthenticationWithBiometricsAvailable() {
        return authenticationWithBiometricsAvailable;
    }

    /**
     * Indicates whether the {@link PowerAuthSDK} instance has a biometric factor configured.
     * If {@code false}, the user must first set up biometrics via the appropriate registration
     * method.
     * @return {@code true} if biometric factor is configured, {@code false} otherwise.
     */
    public boolean isBiometricFactorConfigured() {
        return biometricFactorConfigured;
    }

    /**
     * Get the current biometric authentication status reported by the system.
     * @return The current biometric authentication status reported by the system.
     */
    @BiometricStatus
    public int getSystemStatus() {
        return systemStatus;
    }

    /**
     * Get the type of biometric authentication available on the device (e.g. face, fingerprint, or
     * iris).
     * @return The type of biometric authentication available on the device.
     */
    @BiometryType
    public int getBiometryType() {
        return biometryType;
    }
}
