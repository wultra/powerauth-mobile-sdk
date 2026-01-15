/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.v20.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;

public class VerifyOnlineAuthCodeEndpoint implements IServerApiEndpoint<VerifyOnlineAuthCodeEndpoint.Response> {
    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v4/auth/verify";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    public static class Request {

        private String activationId;
        private String applicationKey;
        private String data;
        private String authenticationCode;
        private AuthCodeType authenticationCodeType;
        private String authenticationVersion;
        private Long forcedAuthenticationVersion;

        public Request(@NonNull AuthenticationCodeData sd) {
            activationId = sd.getActivationId();
            applicationKey = sd.getApplicationKey();
            data = sd.getData();
            authenticationCode = sd.getAuthenticationCode();
            authenticationCodeType = sd.getAuthenticationCodeType();
            authenticationVersion = sd.getAuthenticationVersion();
            forcedAuthenticationVersion = sd.getForcedAuthenticationVersion();
        }

        public String getActivationId() {
            return activationId;
        }

        public void setActivationId(String activationId) {
            this.activationId = activationId;
        }

        public String getApplicationKey() {
            return applicationKey;
        }

        public void setApplicationKey(String applicationKey) {
            this.applicationKey = applicationKey;
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

        public AuthCodeType getAuthenticationCodeType() {
            return authenticationCodeType;
        }

        public void setAuthenticationCodeType(AuthCodeType authenticationCodeType) {
            this.authenticationCodeType = authenticationCodeType;
        }

        public String getAuthenticationVersion() {
            return authenticationVersion;
        }

        public void setAuthenticationVersion(String authenticationVersion) {
            this.authenticationVersion = authenticationVersion;
        }

        public Long getForcedAuthenticationVersion() {
            return forcedAuthenticationVersion;
        }

        public void setForcedAuthenticationVersion(Long forcedAuthenticationVersion) {
            this.forcedAuthenticationVersion = forcedAuthenticationVersion;
        }
    }

    public static class Response extends AuthenticationResult {
    }
}
