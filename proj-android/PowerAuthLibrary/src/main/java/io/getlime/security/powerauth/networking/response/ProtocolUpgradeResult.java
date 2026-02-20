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

    public ProtocolUpgradeResult(boolean activationStatusFetchRequired, @Nullable String activationFingerprint) {
        this.activationStatusFetchRequired = activationStatusFetchRequired;
        this.activationFingerprint = activationFingerprint;
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
     * The value is not present, if the protocol upgrade is not yet finished,
     * i.e. the {@link #isActivationStatusFetchRequired()} is {@code true}.
     *
     * @return Decimalized activation fingerprint, might be {@code null}.
     */
    @Nullable
    public String getActivationFingerprint() {
        return activationFingerprint;
    }

}
