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

package io.getlime.security.powerauth.integration.support.endpoints;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.integration.support.model.RecoveryConfig;

public class UpdateRecoveryConfigEndpoint implements IServerApiEndpoint<UpdateRecoveryConfigEndpoint.Response> {

    @NonNull
    @Override
    public String getRelativePath() {
        return "/rest/v3/recovery/config/update";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Request

    public static class Request extends RecoveryConfig {

        /**
         * Create request from given recovery config.
         * @param config Recovery config.
         */
        public Request(@NonNull RecoveryConfig config) {
            setApplicationId(config.getApplicationId());
            setActivationRecoveryEnabled(config.isActivationRecoveryEnabled());
            setRecoveryPostcardEnabled(config.isRecoveryPostcardEnabled());
            setAllowMultipleRecoveryCodes(config.getAllowMultipleRecoveryCodes());
            setRemotePostcardPublicKey(config.getRemotePostcardPublicKey());
        }
    }

    // Response

    public static class Response {

        private boolean updated;

        public boolean isUpdated() {
            return updated;
        }

        public void setUpdated(boolean updated) {
            this.updated = updated;
        }
    }
}
