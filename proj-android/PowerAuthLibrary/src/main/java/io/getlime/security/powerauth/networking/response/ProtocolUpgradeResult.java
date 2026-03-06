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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.Nullable;

/**
 * Object representing result of the protocol upgrade process.
 */
public class ProtocolUpgradeResult {

    private final boolean activationStatusFetchRequired;

    @Nullable
    private final String activationFingerprint;

    private final boolean biometryFactorRemoved;

    public ProtocolUpgradeResult(boolean activationStatusFetchRequired, @Nullable String activationFingerprint, boolean biometryRemoved) {
        this.activationStatusFetchRequired = activationStatusFetchRequired;
        this.activationFingerprint = activationFingerprint;
        this.biometryFactorRemoved = biometryRemoved;
    }

    /**
     * Indicates whether activation status fetch is required to complete the protocol upgrade.
     *
     * @return If {@code true}, activation status must be fetched to finish the protocol upgrade
     *         process. If {@code false}, no further action is required.
     */
    public boolean isActivationStatusFetchRequired() {
        return activationStatusFetchRequired;
    }

    /**
     * Decimalized fingerprint calculated from device and server public keys.
     * The value is not present, if the protocol upgrade is not yet finished.
     *
     * @return Decimalized activation fingerprint, might be {@code null}.
     */
    @Nullable
    public String getActivationFingerprint() {
        return activationFingerprint;
    }

    /**
     * Indicates whether biometry factor was removed during the protocol upgrade process.
     * If {@code true}, consider adding the biometry factor again.
     *
     * @return {@code true} if the biometry was removed during the protocol upgrade process,
     *         {@code false} otherwise.
     */
    public boolean isBiometryFactorRemoved() {
        return biometryFactorRemoved;
    }
}
