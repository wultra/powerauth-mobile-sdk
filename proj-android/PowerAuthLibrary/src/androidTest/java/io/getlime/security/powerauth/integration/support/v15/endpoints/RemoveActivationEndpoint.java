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

package io.getlime.security.powerauth.integration.support.v15.endpoints;

import com.google.gson.reflect.TypeToken;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.integration.support.client.IServerApiEndpoint;

public class RemoveActivationEndpoint implements IServerApiEndpoint<RemoveActivationEndpoint.Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/activation/remove";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Request

    public static class Request {

        private String activationId;
        private String externalUserId;
        private boolean revokeRecoveryCodes;

        public String getActivationId() {
            return activationId;
        }

        public void setActivationId(String activationId) {
            this.activationId = activationId;
        }

        public String getExternalUserId() {
            return externalUserId;
        }

        public void setExternalUserId(String externalUserId) {
            this.externalUserId = externalUserId;
        }

        public boolean isRevokeRecoveryCodes() {
            return revokeRecoveryCodes;
        }

        public void setRevokeRecoveryCodes(boolean revokeRecoveryCodes) {
            this.revokeRecoveryCodes = revokeRecoveryCodes;
        }
    }

    // Response

    public static class Response {

        private String activationId;
        private boolean removed;

        public String getActivationId() {
            return activationId;
        }

        public void setActivationId(String activationId) {
            this.activationId = activationId;
        }

        public boolean isRemoved() {
            return removed;
        }

        public void setRemoved(boolean removed) {
            this.removed = removed;
        }
    }
}
