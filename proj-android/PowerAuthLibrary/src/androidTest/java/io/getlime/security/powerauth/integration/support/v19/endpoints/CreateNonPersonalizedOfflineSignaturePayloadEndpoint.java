/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.v19.endpoints;

import com.google.gson.reflect.TypeToken;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;

public class CreateNonPersonalizedOfflineSignaturePayloadEndpoint implements IServerApiEndpoint<CreateNonPersonalizedOfflineSignaturePayloadEndpoint.Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/signature/offline/non-personalized/create";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Request

    public static class Request {

        private String applicationId;
        private String data;

        public String getApplicationId() {
            return applicationId;
        }

        public void setApplicationId(String applicationId) {
            this.applicationId = applicationId;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }

    // Response

    public static class Response extends OfflineSignaturePayload {
    }
}
