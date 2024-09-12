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

import android.util.Base64;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.networking.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.networking.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The <code>EciesCryptogram</code> object represents cryptogram transmitted over the network.
 */
public class EciesCryptogram {
    /**
     * An identifier of temporary key.
     */
    public final String temporaryKeyId;
    /**
     * An encrypted data
     */
    public final byte[] body;

    /**
     * A MAC computed for encrypted data
     */
    public final byte[] mac;

    /**
     * An ephemeral EC public key. The value is optional for response data.
     */
    public final byte[] key;

    /**
     * Nonce for IV derivation. The value is optional for response data.
     */
    public final byte[] nonce;

    /**
     * Timestamp with milliseconds precision.
     */
    public final long timestamp;

    /**
     * @return content of body in Base64 formatted string
     */
    public String getBodyBase64() {
        if (body != null) {
            return Base64.encodeToString(body, Base64.NO_WRAP);
        }
        return null;
    }

    /**
     * @return content of mac in Base64 formatted string
     */
    public String getMacBase64() {
        if (mac != null) {
            return Base64.encodeToString(mac, Base64.NO_WRAP);
        }
        return null;
    }

    /**
     * @return content of key in Base64 formatted string
     */
    public String getKeyBase64() {
        if (key != null) {
            return Base64.encodeToString(key, Base64.NO_WRAP);
        }
        return null;
    }

    /**
     * @return content of nonce in Base64 formatted string
     */
    public String getNonceBase64() {
        if (nonce != null) {
            return Base64.encodeToString(nonce, Base64.NO_WRAP);
        }
        return null;
    }

    /**
     * Constructs an empty cryptogram. This constructor is used in the JNI code for internal
     * object initialization.
     */
    public EciesCryptogram() {
        this.temporaryKeyId = null;
        this.body = null;
        this.mac = null;
        this.key = null;
        this.nonce = null;
        this.timestamp = 0;
    }

    /**
     * Constructs a cryptogram with body, mac and key. The key can and nonce be null for responses received
     * from the server.
     * @param temporaryKeyId Identifier of temporary encryption key.
     * @param body encrypted data
     * @param mac MAC computed for encrypted data
     * @param key An optional ephemeral key
     * @param nonce An optional nonce.
     * @param timestamp Timestamp with milliseconds precision.
     */
    public EciesCryptogram(String temporaryKeyId, byte[] body, byte[] mac, byte[] key, byte[] nonce, long timestamp) {
        this.temporaryKeyId = temporaryKeyId;
        this.body = body;
        this.mac = mac;
        this.key = key;
        this.nonce = nonce;
        this.timestamp = timestamp;
    }

    /**
     * Constructs a cryptogram with body, mac and key in Base64 format. The key and nonce can be nil
     * for responses received from the server.
     * @param bodyBase64 encrypted data in Base64 format
     * @param macBase64 MAC computed for encrypted data in Base64 format
     * @param keyBase64 An optional ephemeral key in Base64 format
     * @param nonceBase64 An optional nonce in Base64 format.
     * @param timestamp Timestamp with milliseconds precision.
     */
    public EciesCryptogram(String temporaryKeyId, String bodyBase64, String macBase64, String keyBase64, String nonceBase64, long timestamp) {
        this.temporaryKeyId = temporaryKeyId;
        this.body = (bodyBase64 != null) ? Base64.decode(bodyBase64, Base64.NO_WRAP) : null;
        this.mac  = (macBase64  != null) ? Base64.decode(macBase64, Base64.NO_WRAP) : null;
        this.key  = (keyBase64  != null) ? Base64.decode(keyBase64, Base64.NO_WRAP) : null;
        this.nonce = (nonceBase64 != null) ? Base64.decode(nonceBase64, Base64.NO_WRAP) : null;
        this.timestamp = timestamp;
    }

    /**
     * Convert cryptogram into encrypted request object.
     * @return New instance of {@link EciesEncryptedRequest} object with all parameters set from the cryptogram.
     */
    public EciesEncryptedRequest toEncryptedRequest() {
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        request.setTemporaryKeyId(temporaryKeyId);
        request.setEncryptedData(getBodyBase64());
        request.setMac(getMacBase64());
        request.setNonce(getNonceBase64());
        request.setEphemeralPublicKey(getKeyBase64());
        request.setTimestamp(timestamp);
        return request;
    }

    /**
     * Construct cryptogram from {@link EciesEncryptedResponse} received from the server.
     * @param response Encrypted response object received from the server.
     * @return Cryptogram with response received from the server, or {@code null} in case some required parameter is missing.
     */
    @Nullable
    public static EciesCryptogram fromEncryptedResponse(EciesEncryptedResponse response) {
        if (response != null) {
            try {
                return new EciesCryptogram(
                        null,
                        response.getEncryptedData(),
                        response.getMac(),
                        null,
                        response.getNonce(),
                        response.getTimestamp());
            } catch (IllegalArgumentException e) {
                PowerAuthLog.e("Failed to parse encrypted response: " + e.getMessage());
            }
        }
        return null;
    }
}
