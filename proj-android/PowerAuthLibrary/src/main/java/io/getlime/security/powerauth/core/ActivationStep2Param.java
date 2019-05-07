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

/**
 * Parameters for second step of device activation.
 */
public class ActivationStep2Param {
    
    /**
     * Real Activation ID received from server.
     */
    public final String activationId;
    /**
     * Server's public key, in Base64 format.
     */
    public final String serverPublicKey;
    /**
     * Initial value for hash-based counter.
     */
    public final String ctrData;
    /**
     * Data for activation recovery. May contain null, in case
     * that there's no recovery available.
     */
    public final RecoveryData activationRecovery;

    public ActivationStep2Param(String activationId, String serverPublicKey, String ctrData, RecoveryData activationRecovery) {
        this.activationId = activationId;
        this.serverPublicKey = serverPublicKey;
        this.ctrData = ctrData;
        this.activationRecovery = activationRecovery;
    }
}