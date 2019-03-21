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
package io.getlime.security.powerauth.networking.model.request;

import io.getlime.security.powerauth.networking.model.entity.ActivationType;

import java.util.Map;

/**
 * Request object for activation layer 1.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer1Request {

    private ActivationType type;
    private Map<String, String> identityAttributes;
    private Map<String, Object> customAttributes;
    private EciesEncryptedRequest activationData;

    /**
     * Get activation type.
     * @return Activation type.
     */
    public ActivationType getType() {
        return type;
    }

    /**
     * Set activation type.
     * @param type Activation type.
     */
    public void setType(ActivationType type) {
        this.type = type;
    }

    /**
     * Get identity attributes.
     * @return Identity attributes.
     */
    public Map<String, String> getIdentityAttributes() {
        return identityAttributes;
    }

    /**
     * Set identity attributes.
     * @param identityAttributes Identity attributes.
     */
    public void setIdentityAttributes(Map<String, String> identityAttributes) {
        this.identityAttributes = identityAttributes;
    }

    /**
     * Get custom attributes.
     * @return Custom attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Set custom attributes.
     * @param customAttributes Custom attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    /**
     * Get encrypted activation data.
     * @return Encrypted activation data.
     */
    public EciesEncryptedRequest getActivationData() {
        return activationData;
    }

    /**
     * Set encrypted activation data.
     * @param activationData Encrypted activation data.
     */
    public void setActivationData(EciesEncryptedRequest activationData) {
        this.activationData = activationData;
    }
}
