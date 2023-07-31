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

/**
 * Response object for endpoints returning data encrypted by ECIES.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptedResponse {

    private String encryptedData;
    private String mac;
    private long timestamp;

    /**
     * Default constructor.
     */
    public EciesEncryptedResponse() {
    }

    /**
     * Constructor with Base64 encoded encrypted data and MAC of key and data.
     * @param encryptedData Encrypted data.
     * @param mac MAC of key and data.
     */
    public EciesEncryptedResponse(String encryptedData, String mac) {
        this.encryptedData = encryptedData;
        this.mac = mac;
    }

    /**
     * Get Base64 encoded encrypted data payload.
     * @return Encrypted data.
     */
    public String getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set Base64 encoded encrypted data payload.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * Get Base64 encoded MAC signature of the response.
     * @return MAC of the response.
     */
    public String getMac() {
        return mac;
    }

    /**
     * Set Base64 encoded MAC signature of the response.
     * @param mac MAC of the response.
     */
    public void setMac(String mac) {
        this.mac = mac;
    }

    /**
     * Set timestamp with the milliseconds' precision.
     * @param timestamp Timestamp in milliseconds.
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * @return Get timestamp in milliseconds.
     */
    public long getTimestamp() {
        return timestamp;
    }
}
