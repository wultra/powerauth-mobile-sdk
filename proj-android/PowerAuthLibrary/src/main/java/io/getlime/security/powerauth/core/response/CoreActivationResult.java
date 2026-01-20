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

package io.getlime.security.powerauth.core.response;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;

/**
 * The {@code CoreActivationResult} class represents successful result from the activation process.
 */
public class CoreActivationResult {

    @NonNull
    private final String activationFingerprint;

    @Nullable
    private final Map<String, Object> customAttributes;

    @Nullable
    private final Map<String, Object> userInfo;

    /**
     * Construct result object with given parameters.
     * @param activationFingerprint
     * @param customAttributes
     * @param userInfo
     */
    public CoreActivationResult(@NonNull String activationFingerprint, @Nullable Map<String, Object> customAttributes, @Nullable Map<String, Object> userInfo) {
        this.activationFingerprint = activationFingerprint;
        this.customAttributes = customAttributes;
        this.userInfo = userInfo;
    }

    @NonNull
    public String getActivationFingerprint() {
        return activationFingerprint;
    }

    @Nullable
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    @Nullable
    public Map<String, Object> getUserInfo() {
        return userInfo;
    }
}
