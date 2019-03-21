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
 * Request object for activation layer 2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer2Request {

    private String devicePublicKey;
    private String activationName;
    private String extras;

    /**
     * Get Base64 encoded device public key.
     * @return Device public key.
     */
    public String getDevicePublicKey() {
        return devicePublicKey;
    }

    /**
     * Set Base64 encoded device public key.
     * @param devicePublicKey Device public key.
     */
    public void setDevicePublicKey(String devicePublicKey) {
        this.devicePublicKey = devicePublicKey;
    }

    /**
     * Get activation name.
     * @return Activation name.
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get activation extras.
     * @return Activation extras.
     */
    public String getExtras() {
        return extras;
    }

    /**
     * Set activation extras.
     * @param extras Activation extras.
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }
}