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

/**
 * Request object for /pa/v3/activation/status end-point.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationStatusRequest {

    private String activationId;
    private String challenge;

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get challenge.
     * @return Challeng
     */
    public String getChallenge() {
        return challenge;
    }

    /**
     * Set challenge.
     * @param challenge challenge in Base64 encoded string.
     */
    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }
}
