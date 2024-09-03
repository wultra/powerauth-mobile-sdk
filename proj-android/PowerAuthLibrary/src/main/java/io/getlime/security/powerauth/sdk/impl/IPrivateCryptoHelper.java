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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthAuthorizationHttpHeader;

/**
 * The {@code IPrivateCryptoHelper} provides a minimal interface for a several cryptographic tasks
 * required internally in the SDK, but provided by the PowerAuthSDK instance. The main purpose of
 * this separation is that we don't want to have direct dependency on {@code PowerAuthSDK}.
 */
public interface IPrivateCryptoHelper {

    /**
     * Constructs a new {@link EciesEncryptor} object created for given identifier.
     *
     * @param identifier encryptor's identifier
     * @return new instance of {@link EciesEncryptor}
     * @throws PowerAuthErrorException if encryptor cannot be created
     */
    @NonNull EciesEncryptor getEciesEncryptor(@NonNull EciesEncryptorId identifier) throws PowerAuthErrorException;

    /**
     * Calculates PowerAuth signature for given data.
     *
     * @param availableInProtocolUpgrade true, if request is available during the protocol upgrade
     * @param body data to be authorized
     * @param method http method (typically POST)
     * @param uriIdentifier URI identifier, required for PowerAuth signature
     * @param authentication object with credentials
     * @return Authorization header object or null, in case of error.
     * @throws PowerAuthErrorException is signature cannot be calculated
     */
    @NonNull PowerAuthAuthorizationHttpHeader getAuthorizationHeader(
            boolean availableInProtocolUpgrade,
            @NonNull final byte[] body,
            @NonNull final String method,
            @NonNull final String uriIdentifier,
            @NonNull final PowerAuthAuthentication authentication) throws PowerAuthErrorException;


    /**
     * @return Default device related key used for computing the possession factor encryption key.
     *         Function may return null if the key cannot be computed (typically, when Android
     *         {@link android.content.Context} object is not available for the crypto helper.
     */
    @Nullable byte[] getDeviceRelatedKey();

    /**
     * @return Object implementing {@link IKeystoreService} interface.
     */
    @NonNull IKeystoreService getKeystoreService();

    /**
     * @return Core {@link Session} object associated with this helper.
     */
    @NonNull Session getCoreSession();

}
