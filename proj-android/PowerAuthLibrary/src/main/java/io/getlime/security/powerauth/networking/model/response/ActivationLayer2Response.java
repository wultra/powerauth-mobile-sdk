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
package io.getlime.security.powerauth.networking.model.response;

import io.getlime.security.powerauth.networking.model.entity.ActivationRecovery;

/**
 * Response object for activation layer 2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer2Response {

    private String activationId;
    private String serverPublicKey;
    private String ctrData;
    private ActivationRecovery activationRecovery;

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get Base64 encoded server public key.
     * @return Server public key.
     */
    public String getServerPublicKey() {
        return serverPublicKey;
    }

    /**
     * Set Base64 encoded server public key.
     * @param serverPublicKey Server public key.
     */
    public void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    /**
     * Get Base64 encoded counter data.
     * @return Counter data.
     */
    public String getCtrData() {
        return ctrData;
    }

    /**
     * Set Base64 encoded counter data.
     * @param ctrData Counter data.
     */
    public void setCtrData(String ctrData) {
        this.ctrData = ctrData;
    }

    /**
     * Get activation recovery information.
     * @return Activation recovery information.
     */
    public ActivationRecovery getActivationRecovery() {
        return activationRecovery;
    }

    /**
     * Set activation recovery information.
     * @param activationRecovery Activation recovery information.
     */
    public void setActivationRecovery(ActivationRecovery activationRecovery) {
        this.activationRecovery = activationRecovery;
    }

}
