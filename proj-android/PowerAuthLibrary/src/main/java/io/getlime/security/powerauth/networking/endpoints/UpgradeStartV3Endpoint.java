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

package io.getlime.security.powerauth.networking.endpoints;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.model.response.UpgradeResponsePayload;

public class UpgradeStartV3Endpoint implements IEndpointDefinition<UpgradeResponsePayload> {
    @NonNull
    @Override
    public String getRelativePath() {
        return "/pa/v3/upgrade/start";
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
        return EciesEncryptorId.UPGRADE_START;
    }

    @Nullable
    @Override
    public TypeToken<UpgradeResponsePayload> getResponseType() {
        return TypeToken.get(UpgradeResponsePayload.class);
    }

    @Override
    public boolean isSynchronized() {
        return true;
    }

    @Override
    public boolean isAvailableInProtocolUpgrade() {
        return true;
    }
}
