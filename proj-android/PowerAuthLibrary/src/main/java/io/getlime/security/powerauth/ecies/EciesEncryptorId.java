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

import io.getlime.security.powerauth.core.EciesEncryptorScope;

/**
 * The <code>EciesEncryptorId</code> enumeration defines various configurations
 * for our ECIES scheme, used in the PowerAuth protocol.
 */
public enum EciesEncryptorId {

    /**
     * Constant for "no-encryption".
     */
    NONE(EciesEncryptorScope.APPLICATION, null),

    //
    // Available for application
    //

    /**
     * Defines the encryptor for an application scope, which can be used for an application's custom
     * purposes. The application server can typically decrypt data, encrypted with this configuration.
     */
    GENERIC_APPLICATION_SCOPE(EciesEncryptorScope.APPLICATION, "/pa/generic/application"),

    /**
     * Defines the encryptor for an activation scope, which can be used for an application's custom
     * purposes. The application server can typically decrypt data, encrypted with this configuration.
     * This type of encryptor can be used only when the {@code PowerAuthSDK} has a valid activation.
     */
    GENERIC_ACTIVATION_SCOPE(EciesEncryptorScope.ACTIVATION, "/pa/generic/activation"),

    //
    // Available for SDK tasks
    //

    /**
     * Defines a new encryptor for an activation purposes. The configuration is identical to
     * {@link #GENERIC_APPLICATION_SCOPE}.
     */
    ACTIVATION_REQUEST(EciesEncryptorScope.APPLICATION, "/pa/generic/application"),

    /**
     * Defines a new encryptor for activation private purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    ACTIVATION_PAYLOAD(EciesEncryptorScope.APPLICATION, "/pa/activation"),

    /**
     * Constructs a new encryptor for the activation upgrade purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    UPGRADE_START(EciesEncryptorScope.ACTIVATION, "/pa/upgrade"),

    /**
     * Constructs a new encryptor for the vault unlock request purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    VAULT_UNLOCK(EciesEncryptorScope.ACTIVATION, "/pa/vault/unlock"),

    /**
     * Constructs a new encryptor for the create token request purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    TOKEN_CREATE(EciesEncryptorScope.ACTIVATION, "/pa/token/create"),

    /**
     * Constructs a new encryptor for the confirm recovery code request purposes. The content encrypted
     * with this object can be decrypted only by the PowerAuth server.
     */
    CONFIRM_RECOVERY_CODE(EciesEncryptorScope.ACTIVATION, "/pa/recovery/confirm")

    ;

    /**
     * Defines scope in which encryptor encrypts the data.
     */
    @EciesEncryptorScope
    public final int scope;

    /**
     * The "sharedInfo1" constant for our ECIES implementation
     */
    public final String sharedInfo1;

    EciesEncryptorId(@EciesEncryptorScope int scope, String sharedInfo1) {
        this.scope = scope;
        this.sharedInfo1 = sharedInfo1;
    }
}
