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

package io.getlime.security.powerauth.integration.support.shared;

import java.util.Map;

import io.getlime.security.powerauth.integration.support.model.Activation;

public class ActivationResponseV20 {
    private String activationId;
    private String activationCode;

    private Map<String, String> activationSignatures;
    private String userId;
    private String applicationId;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    public Map<String, String> getActivationSignatures() {
        return activationSignatures;
    }

    public void setActivationSignatures(Map<String, String> activationSignatures) {
        this.activationSignatures = activationSignatures;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public Activation copyToActivation() {
        Activation activation = new Activation();
        activation.setActivationCode(activationCode);
        activation.setActivationId(activationId);;
        activation.setActivationSignatures(activationSignatures);
        activation.setApplicationId(applicationId);
        activation.setUserId(userId);
        return activation;
    }
}
