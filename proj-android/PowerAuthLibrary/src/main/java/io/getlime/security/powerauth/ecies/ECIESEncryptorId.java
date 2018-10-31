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

import io.getlime.security.powerauth.core.ECIESEncryptorScope;

/**
 The <code>ECIESEncryptorId</code> enumeration defines various configurations
 for our ECIES scheme, used in the PowerAuth protocol.
 */
public enum ECIESEncryptorId {

    /**
     Constant for "no-encryption".
     */
    None(ECIESEncryptorScope.Application, null, false),

    //
    // Available for application
    //

    /**
     Defines the encryptor for an application scope, which can be used for an application's custom
     purposes. The application server can typically decrypt data, encrypted with this configuration.
     */
    GenericApplicationScope(ECIESEncryptorScope.Application, "/pa/generic/application", true),

    /**
     Defines the encryptor for an activation scope, which can be used for an application's custom
     purposes. The application server can typically decrypt data, encrypted with this configuration.
     */
    GenericActivationScope(ECIESEncryptorScope.Activation, "/pa/generic/activation", true),

    //
    // Available for SDK tasks
    //

    /**
     Defines a new encryptor for an activation purposes. The configuration is identical to
     {@link #GenericApplicationScope}.
     */
    ActivationRequest(ECIESEncryptorScope.Application, "/pa/generic/application", true),

    /**
     Defines a new encryptor for activation private purposes. The content encrypted
     with this object can be decrypted only by the PowerAuth server.
     */
    ActivationPayload(ECIESEncryptorScope.Application, "/pa/activation", false),

    /**
     Constructs a new encryptor for the activation migration purposes. The content encrypted
     with this object can be decrypted only by the PowerAuth server.
     */
    MigrationStart(ECIESEncryptorScope.Activation, "/pa/migration", true),

    /**
     Constructs a new encryptor for the vault unlock request purposes. The content encrypted
     with this object can be decrypted only by the PowerAuth server.
     */
    VaultUnlock(ECIESEncryptorScope.Activation, "/pa/vault/unlock", true),

    /**
     Constructs a new encryptor for the create token request purposes. The content encrypted
     with this object can be decrypted only by the PowerAuth server.
     */
    TokenCreate(ECIESEncryptorScope.Activation, "/pa/token/create", true)

    ;

    /**
     Defines scope in which encryptor encrypts the data.
     */
    public  final ECIESEncryptorScope scope;

    /**
     The "sharedInfo1" constant for our ECIES implementation
     */
    public final String sharedInfo1;

    /**
     If true, then {@link ECIESEncryptorFactory} will add {@link ECIESMetaData} object to
     the constructed encryptor.
     */
    public final boolean hasMetadata;


    ECIESEncryptorId(ECIESEncryptorScope scope, String sharedInfo1, boolean hasMetadata) {
        this.scope = scope;
        this.sharedInfo1 = sharedInfo1;
        this.hasMetadata = hasMetadata;
    }
}
