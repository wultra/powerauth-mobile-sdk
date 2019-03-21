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
 * Response object for vault unlock payload.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class VaultUnlockResponsePayload {

    private String encryptedVaultEncryptionKey;
    private boolean signatureValid;

    /**
     * Get encrypted vault encryption key.
     * @return Encrypted vault encryption key.
     */
    public String getEncryptedVaultEncryptionKey() {
        return encryptedVaultEncryptionKey;
    }

    /**
     * Set encrypted vault encryption key.
     * @param encryptedVaultEncryptionKey Encrypted vault encryption key.
     */
    public void setEncryptedVaultEncryptionKey(String encryptedVaultEncryptionKey) {
        this.encryptedVaultEncryptionKey = encryptedVaultEncryptionKey;
    }

    /**
     * Get whether signature is valid.
     * @return Whether signature is valid.
     */
    public boolean isSignatureValid() {
        return signatureValid;
    }

    /**
     * Set whether signature is valid.
     * @param signatureValid Whether signature is valid.
     */
    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }
}