/*
 * Copyright 2019 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;

import io.getlime.security.powerauth.core.RecoveryData;

/**
 * The {@code CreateActivationResult} class represents result of activation creation process.
 * You can typically obtain this object in {@link ICreateActivationListener#onActivationCreateSucceed(CreateActivationResult)}
 * callback.
 */
public class CreateActivationResult {

    /**
     * Decimalized fingerprint calculated from data constructed from device's public key,
     * server's public key and activation identifier.
     */
    private final @NonNull String activationFingerprint;

    /**
     * Custom attributes received from the server. The value may be null in case that there are
     * no custom attributes available.
     */
    private final @Nullable Map<String, Object> customActivationAttributes;

    /**
     * Optional information about activation recovery. The value may be null in case that feature
     * is not supported, or not enabled on the server.
     */
    private final @Nullable RecoveryData recoveryData;

    /**
     * @param activationFingerprint       Decimalized fingerprint calculated from data constructed
     *                                    from device's public key, server's public key and activation
     *                                    identifier.
     * @param customActivationAttributes  Custom attributes received from the server. The value may
     *                                    be null in case that there are no custom attributes available.
     * @param recoveryData                {@link RecoveryData} object with information about activation
     *                                    recovery. The value may be null if feature is not supported,
     *                                    or configured on the server.
     */
    public CreateActivationResult(@NonNull String activationFingerprint, @Nullable Map<String, Object> customActivationAttributes, @Nullable RecoveryData recoveryData) {
        this.activationFingerprint = activationFingerprint;
        this.customActivationAttributes = customActivationAttributes;
        this.recoveryData = recoveryData;
    }

    /**
     * @return String with decimalized fingerprint calculated from data constructed from device's
     *         public key, server's public key and activation identifier.
     */
    public @NonNull String getActivationFingerprint() {
        return activationFingerprint;
    }

    /**
     * @return Map with custom attributes received from the server. The value may be null in case
     *         that there are no custom attributes available.
     */
    public @Nullable Map<String, Object> getCustomActivationAttributes() {
        return customActivationAttributes;
    }

    /**
     * Returns object containing information about activation recovery.
     *
     * If supported and enabled on the server, then the object contains "Recovery Code" and PUK,
     * created for this particular activation. Your application should display that values to the user
     * and forget the values immediately. You should NEVER store values from the object persistently
     * on the device.
     *
     * @return {@link RecoveryData} object with information about activation recovery. The value
     *          may be null if feature is not supported, or configured on the server.
     */
    public @Nullable RecoveryData getRecoveryData() {
        return recoveryData;
    }
}
