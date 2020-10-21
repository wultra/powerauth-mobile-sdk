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

package io.getlime.security.powerauth.integration.support.model;

import android.support.annotation.NonNull;

public class Activation {

    private String activationCode;
    private @NonNull String activationId = "INVALID_ID";
    private String activationSignature;
    private Long applicationId;
    private String userId;

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    @NonNull
    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(@NonNull String activationId) {
        this.activationId = activationId;
    }

    public String getActivationSignature() {
        return activationSignature;
    }

    public void setActivationSignature(String activationSignature) {
        this.activationSignature = activationSignature;
    }

    public Long getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(Long applicationId) {
        this.applicationId = applicationId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
