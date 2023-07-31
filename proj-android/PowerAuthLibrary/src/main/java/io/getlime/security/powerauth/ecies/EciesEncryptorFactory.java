/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.ecies;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.charset.Charset;

import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.core.EciesEncryptorScope;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SignatureUnlockKeys;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The <code>EciesEncryptorFactory</code> class helps with constructing {@link EciesEncryptor}
 * instances designated for various SDK's or application's tasks.
 */
public class EciesEncryptorFactory {

    private final Session mSession;
    private final byte[] mPossessionUnlockKey;

    /**
     * Initializes object with required session &amp; optional device related key.
     * The device related key is required only for activation scoped encryptors.
     *
     * @param session instance of {@link Session} object
     * @param possessionUnlockKey key for decrypting the possession factor, stored in the {@link Session}.
     *                            If not provided, then activation scoped encryptors cannot be constructed.
     */
    public EciesEncryptorFactory(@NonNull Session session, @Nullable byte[] possessionUnlockKey) {
        this.mSession = session;
        this.mPossessionUnlockKey = possessionUnlockKey;
    }


    /**
     * Constructs a new ECIES encryptor object for given identifier. If the encryptor is for
     * an activation scope, then the internal {@link Session} must have a valid activation.
     *
     * @param identifier type of encryptor to be constructed
     * @return new instance of {@link EciesEncryptor} object.
     * @throws PowerAuthErrorException if factory doesn't have {@link #mPossessionUnlockKey} but is required,
     *                                 or if low level encryptor creation fails
     */
    public @NonNull EciesEncryptor getEncryptor(@NonNull EciesEncryptorId identifier) throws PowerAuthErrorException {
        if (identifier == EciesEncryptorId.NONE) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "'NONE' encryptor cannot be created");
        }
        return getEncryptor(identifier.scope, identifier.sharedInfo1);
    }

    /**
     * Private function for constructing {@link EciesEncryptor} objects.
     *
     * @param scope defines scope of encryptor (application or activation)
     * @param sharedInfo1 optional ECIES parameter
     * @return new instance of {@link EciesEncryptor} object.
     * @throws PowerAuthErrorException if factory doesn't have {@link #mPossessionUnlockKey} but is required,
     *                                 or if low level encryptor creation fails
     */
    private @NonNull EciesEncryptor getEncryptor(@EciesEncryptorScope int scope, @Nullable String sharedInfo1) throws PowerAuthErrorException {
        final byte[] sharedInfo1Bytes = sharedInfo1 != null ? sharedInfo1.getBytes(Charset.defaultCharset()) : null;
        final SignatureUnlockKeys unlockKeys;
        final String activationId;
        if (scope == EciesEncryptorScope.ACTIVATION) {
            if (mPossessionUnlockKey == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Device related key is missing for activation scoped encryptor");
            }
            activationId = mSession.getActivationIdentifier();
            if (activationId == null) {
                throw new PowerAuthErrorException(mSession.hasPendingActivation() ? PowerAuthErrorCodes.PENDING_ACTIVATION : PowerAuthErrorCodes.MISSING_ACTIVATION);
            }
            unlockKeys = new SignatureUnlockKeys(mPossessionUnlockKey, null, null);
        } else {
            activationId = null;
            unlockKeys = null;
        }
        EciesEncryptor encryptor = mSession.getEciesEncryptor(scope, unlockKeys, sharedInfo1Bytes);
        if (encryptor == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to create ECIES encryptor");
        }
        encryptor.setMetadata(new EciesMetadata(mSession.getApplicationKey(), activationId));
        return encryptor;
    }
}
