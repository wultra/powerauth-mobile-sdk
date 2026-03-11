/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import android.annotation.SuppressLint;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreSecureVaultKeyId;
import io.getlime.security.powerauth.core.CoreSession;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code PowerAuthSecureVaultKey} class represents a vault encryption key
 * available for application use. The key is typically obtained as part of
 * the activation process, allowing the application to encrypt sensitive data
 * during activation. It can later be retrieved from the server after successful
 * authentication.
 */
public class PowerAuthSecureVaultKey {
    private final @PowerAuthSecureVaultKeyId int keyIdentifier;
    private final SecureData baseKey;

    /**
     * Construct object with key identifier and base secure vault key.
     * @param keyIdentifier Key identifier.
     * @param baseKey Base secure vault key.
     */
    PowerAuthSecureVaultKey(@PowerAuthSecureVaultKeyId int keyIdentifier,
                                   @NonNull SecureData baseKey) {
        this.keyIdentifier = keyIdentifier;
        this.baseKey = baseKey;
    }

    /**
     * @return Key identifier.
     */
    @PowerAuthSecureVaultKeyId
    public int getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * Derives another key from this key, allowing creation of a chain of separated keys.
     *
     * @param index Derivation index.
     * @param keySize Size of derived key in bytes. Minimum is 16 bytes.
     * @return Derived key.
     * @throws PowerAuthErrorException In case of failure.
     */
    @NonNull
    public SecureData deriveKey(long index, int keySize) throws PowerAuthErrorException {
        try {
            return CoreSession.deriveVaultEncryptionKey(baseKey, toCoreKeyId(keyIdentifier), index, keySize);
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Internal method converts {@link PowerAuthSecureVaultKeyId} into {@link CoreSecureVaultKeyId}
     * constant.
     * @param keyId Constant to convert.
     * @return Converted constant.
     */
    @SuppressLint("WrongConstant")
    @CoreSecureVaultKeyId
    static int toCoreKeyId(@PowerAuthSecureVaultKeyId int keyId) {
        // PowerAuthSecureVaultKeyId is subset to CoreSecureVaultKeyId
        return keyId;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PowerAuthSecureVaultKey)) {
            return false;
        }
        PowerAuthSecureVaultKey typed = (PowerAuthSecureVaultKey) obj;
        return keyIdentifier == typed.keyIdentifier &&
                baseKey.equals(typed.baseKey);
    }
}
