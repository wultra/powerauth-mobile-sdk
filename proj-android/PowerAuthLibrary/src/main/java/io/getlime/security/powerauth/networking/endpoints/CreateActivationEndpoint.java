/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.networking.interfaces.ICustomEndpointOperation;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.model.response.ActivationLayer1Response;

public class CreateActivationEndpoint implements IEndpointDefinition<ActivationLayer1Response> {

    private final ICustomEndpointOperation beforeRequestSerialization;
    private EciesEncryptor layer2Encryptor;

    /**
     * Construct endpoint with a custom serialization step executed before the request is serialized.
     * @param beforeRequestSerialization Step executed before the request is serialized.
     */
    public CreateActivationEndpoint(ICustomEndpointOperation beforeRequestSerialization) {
        this.beforeRequestSerialization = beforeRequestSerialization;
    }

    @NonNull
    @Override
    public String getRelativePath() {
        return "/pa/v3/activation/create";
    }

    @NonNull
    @Override
    public EciesEncryptorId getEncryptorId() {
        return EciesEncryptorId.ACTIVATION_REQUEST;
    }

    @Nullable
    @Override
    public TypeToken<ActivationLayer1Response> getResponseType() {
        return TypeToken.get(ActivationLayer1Response.class);
    }

    @Override
    public boolean isAvailableInProtocolUpgrade() {
        return true;
    }

    @Nullable
    @Override
    public ICustomEndpointOperation getBeforeRequestSerializationOperation() {
        return beforeRequestSerialization;
    }

    /**
     * Get ECIES encryptor for layer-2 encryption.
     * @return ECIES encryptor for layer-2 encryption.
     */
    public EciesEncryptor getLayer2Encryptor() {
        return layer2Encryptor;
    }

    /**
     * Set ECIES encryptor for layer-2 encryption.
     * @param encryptor ECIES encryptor for layer-2 encryption.
     */
    public void setLayer2Encryptor(EciesEncryptor encryptor) {
        this.layer2Encryptor = encryptor;
    }
}
