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

import java.util.Map;

/**
 * Response object for activation layer 2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer1Response {

    private EciesEncryptedResponse activationData;
    private Map<String, Object> customAttributes;

    /**
     * Get encrypted activation data.
     * @return Encrypted activation data.
     */
    public EciesEncryptedResponse getActivationData() {
        return activationData;
    }

    /**
     * Set encrypted activation data.
     * @param activationData Encrypted activation data.
     */
    public void setActivationData(EciesEncryptedResponse activationData) {
        this.activationData = activationData;
    }

    /**
     * Get custom attributes for activation.
     * @return Custom attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Set custom attributes for activation.
     * @param customAttributes Custom attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }
}
