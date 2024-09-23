/*
 * Copyright 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.model.request;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Request object for endpoint returning a temporary key for ECIES encryption scheme.
 */
public class GetTemporaryKeyRequest {

    private final String applicationKey;
    private final String activationId;
    private final String challenge;

    public GetTemporaryKeyRequest(@NonNull String applicationKey, @Nullable String activationId, @NonNull String challenge) {
        this.applicationKey = applicationKey;
        this.activationId = activationId;
        this.challenge = challenge;
    }

    @NonNull
    public String getApplicationKey() {
        return applicationKey;
    }

    @Nullable
    public String getActivationId() {
        return activationId;
    }

    @NonNull
    public String getChallenge() {
        return challenge;
    }
}
