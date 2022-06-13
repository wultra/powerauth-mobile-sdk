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

package io.getlime.security.powerauth.integration.support.v13.endpoints;

import com.google.gson.reflect.TypeToken;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.model.SignatureData;
import io.getlime.security.powerauth.integration.support.model.SignatureInfo;
import io.getlime.security.powerauth.integration.support.model.SignatureType;

public class VerifyOnlineSignatureEndpoint implements IServerApiEndpoint<VerifyOnlineSignatureEndpoint.Response> {
    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/signature/verify";
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
        private String signature;
        private SignatureType signatureType;
        private String signatureVersion;
        private Long forcedSignatureVersion;

        public Request(@NonNull SignatureData sd) {
            activationId = sd.getActivationId();
            applicationKey = sd.getApplicationKey();
            data = sd.getData();
            signature = sd.getSignature();
            signatureType = sd.getSignatureType();
            signatureVersion = sd.getSignatureVersion();
            forcedSignatureVersion = sd.getForcedSignatureVersion();
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

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public SignatureType getSignatureType() {
            return signatureType;
        }

        public void setSignatureType(SignatureType signatureType) {
            this.signatureType = signatureType;
        }

        public String getSignatureVersion() {
            return signatureVersion;
        }

        public void setSignatureVersion(String signatureVersion) {
            this.signatureVersion = signatureVersion;
        }

        public Long getForcedSignatureVersion() {
            return forcedSignatureVersion;
        }

        public void setForcedSignatureVersion(Long forcedSignatureVersion) {
            this.forcedSignatureVersion = forcedSignatureVersion;
        }
    }

    public static class Response extends SignatureInfo {
    }
}
