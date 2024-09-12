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
 * Request object with data encrypted by ECIES encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptedRequest {

    private String temporaryKeyId;
    private String ephemeralPublicKey;
    private String encryptedData;
    private String mac;
    private String nonce;
    private long timestamp;

    /**
     * Get Base64 encoded ephemeral public key.
     * @return Ephemeral public key.
     */
    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Set Base64 encoded ephemeral public key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    /**
     * Get Base64 encoded encrypted data.
     * @return Encrypted data.
     */
    public String getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set Base64 encoded encrypted data.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * Get Base64 encoded MAC of key and data.
     * @return MAC of key and data.
     */
    public String getMac() {
        return mac;
    }

    /**
     * Set Base64 encoded MAC of key and data.
     * @param mac MAC of key and data.
     */
    public void setMac(String mac) {
        this.mac = mac;
    }

    /**
     * Get Base64 encoded nonce.
     * @return Nonce in Base64 format.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Set Base64 encoded nonce.
     * @param nonce Nonce in Base64 format.
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * @return Timestamp with milliseconds precision.
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Set timestamp with milliseconds' precision.
     * @param timestamp Timestamp in milliseconds.
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Get identifier of temporary key.
     * @return Identifier of temporary key
     */
    public String getTemporaryKeyId() {
        return temporaryKeyId;
    }

    /**
     * Set identifier of temporary key.
     * @param temporaryKeyId identifier of temporary key.
     */
    public void setTemporaryKeyId(String temporaryKeyId) {
        this.temporaryKeyId = temporaryKeyId;
    }
}
