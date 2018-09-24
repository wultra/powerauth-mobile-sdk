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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.charset.Charset;

import io.getlime.security.powerauth.core.ECIESEncryptor;
import io.getlime.security.powerauth.core.ECIESEncryptorScope;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SignatureUnlockKeys;

/**
 * The <code>ECIESEncryptorFactory</code> class helps with constructing {@link ECIESEncryptor}
 * instances designated for various SDK's or application's tasks.
 */
public class ECIESEncryptorFactory {

    private final Session mSession;
    private final byte[] mPossessionUnlockKey;

    /**
     * Initializes object with required session & optional device related key.
     * The device related key is required only for activation scoped encryptors.
     *
     * @param session instance of {@link Session} object
     * @param possessionUnlockKey key for decrypting the possession factor, stored in the {@link Session}
     */
    public ECIESEncryptorFactory(@NonNull Session session, @NonNull byte[] possessionUnlockKey) {
        this.mSession = session;
        this.mPossessionUnlockKey = possessionUnlockKey;
    }

    //
    // Public encryptors
    //

    /**
     * Constructs a new encryptor for an application scope, which can be used for an
     * application's custom purposes. The application server can typically decrypt data,
     * encrypted with this configuration.
     */
    public @Nullable ECIESEncryptor getPublicEncryptorForApplicationScope() {
        return getEncryptor(ECIESEncryptorScope.Application, null, true);
    }

    /**
     * Constructs a new encryptor for an activation scope, which can be used for an
     * application's custom purposes. The application server can typically decrypt data,
     * encrypted with this configuration.
     */
    public @Nullable ECIESEncryptor getPublicEncryptorForActivationScope() {
        return getEncryptor(ECIESEncryptorScope.Activation, null, true);
    }


    //
    // Encryptors internally use by SDK
    //

    /**
     * Constructs a new encryptor for activation purposes.
     * In current SDK implementation, the method uses {@link #getPublicEncryptorForApplicationScope()}
     * internally, so the payload encrypted with the returned object can be decrypted by
     * the application server.
     */
    public @Nullable ECIESEncryptor getEncryptorForActivationRequest() {
        return getPublicEncryptorForApplicationScope();
    }

    /**
     * Constructs a new encryptor for activation private purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     *
     * Note that the returned encryptor has no associated metadata.
     */
    public @Nullable ECIESEncryptor getEncryptorForActivationPayload() {
        return getEncryptor(ECIESEncryptorScope.Application, "/pa/activation", false);
    }

    /**
     * Constructs a new encryptor for the activation migration purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    public @Nullable ECIESEncryptor getEncryptorForMigrationStartRequest() {
        return getEncryptor(ECIESEncryptorScope.Activation, "/pa/migration", true);
    }

    /**
     * Constructs a new encryptor for the vault unlock request purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    public @Nullable ECIESEncryptor getEncryptorForVaultUnlockRequest() {
        return getEncryptor(ECIESEncryptorScope.Activation, "/pa/vault/unlock", true);
    }

    /**
     * Constructs a new encryptor for the create token request purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    public @Nullable ECIESEncryptor getEncryptorForCreateTokenRequest() {
        return getEncryptor(ECIESEncryptorScope.Activation, "/pa/token/create", true);
    }


    /**
     * Private function for constructing {@link ECIESEncryptor} objects.
     *
     * @param scope defines scope of encryptor (application or activation)
     * @param sharedInfo1 optional ECIES parameter
     * @param addMetaData if true, then {@link ECIESMetaData} will be assigned to the returned encryptor
     * @return encryptor object or null in case of error.
     */
    private @Nullable ECIESEncryptor getEncryptor(@NonNull ECIESEncryptorScope scope, @Nullable String sharedInfo1, boolean addMetaData) {
        final byte[] sharedInfo1Bytes = sharedInfo1 != null ? sharedInfo1.getBytes(Charset.defaultCharset()) : null;
        final SignatureUnlockKeys unlockKeys;
        final String activationId;
        if (scope == ECIESEncryptorScope.Activation) {
            activationId = mSession.getActivationIdentifier();
            unlockKeys = new SignatureUnlockKeys(mPossessionUnlockKey, null, null);
        } else {
            activationId = null;
            unlockKeys = null;
        }
        ECIESEncryptor encryptor = mSession.getEciesEncryptor(scope, unlockKeys, sharedInfo1Bytes);
        if (encryptor != null && addMetaData) {
            encryptor.setMetaData(new ECIESMetaData(mSession.getSessionSetup().applicationKey, activationId));
        }
        return encryptor;
    }
}
