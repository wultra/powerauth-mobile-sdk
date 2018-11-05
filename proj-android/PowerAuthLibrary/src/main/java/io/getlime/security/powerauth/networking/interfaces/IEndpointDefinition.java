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

package io.getlime.security.powerauth.networking.interfaces;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.ecies.EciesEncryptorId;

/**
 * Interface defines endpoint for communicating with PowerAuth REST API.
 */
public interface IEndpointDefinition<TResponse> {

    /**
     * @return String with relative path to construct full URL
     */
    @NonNull String getRelativePath();

    /**
     * @return String with HTTP method. Currently, only POST is supported.
     */
    @NonNull String getHttpMethod();

    /**
     * @return String with "URI Identifier", required for PowerAuth signature calculation.
     *         If endpoint is not signed, then returns null.
     */
    @Nullable String getAuthorizationUriId();

    /**
     * @return Type of encryptor if request uses ECIES encryption, or {@link EciesEncryptorId#NONE}
     *         for endpoints with no encryption.
     */
    @NonNull
    EciesEncryptorId getEncryptorId();

    /**
     * @return Type of response object.
     */
    @Nullable TypeToken<TResponse> getResponseType();

    /**
     * @return true if request needs to be processed in serialized queue.
     */
    boolean isSynchronized();

    /**
     * @return true if endpoint is available during the protocol upgrade.
     */
    boolean isAvailableInProtocolUpgrade();
}
