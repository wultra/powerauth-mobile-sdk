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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;

public class VerifyOfflineSignatureEndpoint implements IServerApiEndpoint<VerifyOfflineSignatureEndpoint.Response> {
    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v4/auth/offline/verify";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    public static class Request {

        private String activationId;
        private String data;
        private String authenticationCode;
        private boolean allowBiometry;
        private Long componentLength;

        public Request(@NonNull AuthenticationCodeData sd) {
            activationId = sd.getActivationId();
            data = sd.getData();
            authenticationCode = sd.getAuthenticationCode();
            allowBiometry = sd.getAllowBiometry() != null ? sd.getAllowBiometry() : false;
            componentLength = sd.getOfflineAuthenticationCodeComponentLength();
        }

        public String getActivationId() {
            return activationId;
        }

        public void setActivationId(String activationId) {
            this.activationId = activationId;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        public String getAuthenticationCode() {
            return authenticationCode;
        }

        public void setAuthenticationCode(String authenticationCode) {
            this.authenticationCode = authenticationCode;
        }

        public boolean isAllowBiometry() {
            return allowBiometry;
        }

        public void setAllowBiometry(boolean allowBiometry) {
            this.allowBiometry = allowBiometry;
        }

        public Long getComponentLength() {
            return componentLength;
        }

        public void setComponentLength(Long componentLength) {
            this.componentLength = componentLength;
        }
    }

    public static class Response extends AuthenticationResult {
    }
}
