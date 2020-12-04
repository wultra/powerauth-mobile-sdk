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

import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.model.response.ActivationLayer1Response;

public class CreateActivationEndpoint implements IEndpointDefinition<ActivationLayer1Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/pa/v3/activation/create";
    }

    @NonNull
    @Override
    public String getHttpMethod() {
        return "POST";
    }

    @Nullable
    @Override
    public String getAuthorizationUriId() {
        return null;
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
    public boolean isSynchronized() {
        return false;
    }

    @Override
    public boolean isAvailableInProtocolUpgrade() {
        return true;
    }
}
