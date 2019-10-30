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

package io.getlime.security.powerauth.core;

/**
 * The PA2EncryptedActivationStatus object contains encrypted status data and parameters
 * required for the data decryption.
 */
public class EncryptedActivationStatus {

    public final String challenge;
    public final String encryptedStatusBlob;
    public final String nonce;

    /**
     * Construct encrypted activation status object.
     *
     * @param challenge Challenge bytes, Base64 encoded string is expected.
     * @param encryptedStatusBlob Encrypted status bytes, Base64 encoded string is expected.
     * @param nonce Nonce bytes, Base64 encoded string is expected.
     */
    public EncryptedActivationStatus(
            String challenge,
            String encryptedStatusBlob,
            String nonce) {
        this.challenge = challenge;
        this.encryptedStatusBlob = encryptedStatusBlob;
        this.nonce = nonce;
    }
}
