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

public class SetApplicationVersionSupportedEndpoint implements IServerApiEndpoint<SetApplicationVersionSupportedEndpoint.Response> {

    private final boolean supported;

    public SetApplicationVersionSupportedEndpoint(boolean supported) {
        this.supported = supported;
    }

    @NonNull
    @Override
    public String getRelativePath() {
        return supported ? "/rest/v3/application/version/support" : "/rest/v3/application/version/unsupport";
    }

    @Nullable
    @Override
    public TypeToken<Response> getResponseType() {
        return TypeToken.get(Response.class);
    }

    // Request

    public static class Request {

        private Long applicationVersionId;

        public Long getApplicationVersionId() {
            return applicationVersionId;
        }

        public void setApplicationVersionId(Long applicationVersionId) {
            this.applicationVersionId = applicationVersionId;
        }
    }

    // Response

    public static class Response {

        private Long applicationVersionId;
        private boolean supported;

        public Long getApplicationVersionId() {
            return applicationVersionId;
        }

        public void setApplicationVersionId(Long applicationVersionId) {
            this.applicationVersionId = applicationVersionId;
        }

        public boolean isSupported() {
            return supported;
        }

        public void setSupported(boolean supported) {
            this.supported = supported;
        }
    }
}
