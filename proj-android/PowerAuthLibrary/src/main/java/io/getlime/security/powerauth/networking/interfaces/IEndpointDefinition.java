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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

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
    @NonNull
    default String getHttpMethod() {
        return "POST";
    }

    /**
     * @return String with "URI Identifier", required for PowerAuth signature calculation.
     *         If endpoint is not signed, then returns null. By default, returns null.
     */
    @Nullable
    default String getAuthorizationUriId() {
        return null;
    }

    /**
     * @return Type of encryptor if request uses ECIES encryption, or {@link EciesEncryptorId#NONE}
     *         for endpoints with no encryption. By default, returns {@link EciesEncryptorId#NONE}.
     */
    @NonNull
    default EciesEncryptorId getEncryptorId() {
        return EciesEncryptorId.NONE;
    }

    /**
     * @return Type of response object. By default, returns null.
     */
    @Nullable
    default TypeToken<TResponse> getResponseType() {
        return null;
    }

    /**
     * @return true if request needs to be processed in serialized queue. By default, all requests signed with PowerAuth
     * Signature are synchronized.
     */
    default boolean isSynchronized() {
        return getAuthorizationUriId() != null;
    }

    /**
     * @return true if endpoint is available during the protocol upgrade. By default, returns false.
     */
    default boolean isAvailableInProtocolUpgrade() {
        return false;
    }

    /**
     * @return true if request needs synchronized time to complete properly. By default, returns true for requests
     * that use encryption.
     */
    default boolean isRequireSynchronizedTime() {
        return getEncryptorId() != EciesEncryptorId.NONE;
    }

    /**
     * Provide optional custom operation performed on the networking thread, before the request is serialized.
     * @return Optional custom operation that should be executed before the request serialization is performed.
     */
    @Nullable
    default ICustomEndpointOperation getBeforeRequestSerializationOperation() {
        return null;
    }
}
