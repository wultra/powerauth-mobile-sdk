/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

/**
 * The <code>ECIESCryptogram</code> object represents cryptogram transmitted over the network.
 */
public class ECIESCryptogram {

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
     * @return content of body in Base64 formatted string
     */
    public String getBodyBase64() {
        if (this.body != null) {
            return Base64.encodeToString(this.body, Base64.DEFAULT);
        }
        return null;
    }

    /**
     * @return content of mac in Base64 formatted string
     */
    public String getMacBase64() {
        if (this.mac != null) {
            return Base64.encodeToString(this.mac, Base64.DEFAULT);
        }
        return null;
    }

    /**
     * @return content of key in Base64 formatted string
     */
    public String getKeyBase64() {
        if (this.key != null) {
            return Base64.encodeToString(this.key, Base64.DEFAULT);
        }
        return null;
    }

    /**
     * Constructs an empty cryptogram. This constructor is used in the JNI code for internal
     * object initialization.
     */
    public ECIESCryptogram() {
        this.body = null;
        this.mac = null;
        this.key = null;
    }

    /**
     * Constructs a cryptogram with body, mac and key. The key can be null for responses received
     * from the server.
     * @param body encrypted data
     * @param mac MAC computed for encrypted data
     * @param key An optional ephemeral key
     */
    public ECIESCryptogram(byte[] body, byte[] mac, byte[] key) {
        this.body = body;
        this.mac = mac;
        this.key = key;
    }

    /**
     * Constructs a cryptogram with body, mac and key in Base64 formats. The key can be nil
     * for responses received from the server.
     * @param bodyBase64 encrypted data in Base64 format
     * @param macBase64 MAC computed for encrypted data in Base64 format
     * @param keyBase64 An optional ephemeral key in Base64 format
     */
    public ECIESCryptogram(String bodyBase64, String macBase64, String keyBase64) {
        this.body = (bodyBase64 != null) ? Base64.decode(bodyBase64, Base64.DEFAULT) : null;
        this.mac  = (macBase64  != null) ? Base64.decode(macBase64, Base64.DEFAULT) : null;
        this.key  = (keyBase64  != null) ? Base64.decode(keyBase64, Base64.DEFAULT) : null;
    }

}
