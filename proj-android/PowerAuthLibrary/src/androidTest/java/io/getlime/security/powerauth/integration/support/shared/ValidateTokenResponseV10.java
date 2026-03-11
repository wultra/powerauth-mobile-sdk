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

package io.getlime.security.powerauth.integration.support.shared;

import androidx.annotation.NonNull;

import java.util.List;

import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;

public class ValidateTokenResponseV10 {
    private String activationId;
    private String applicationId;
    private String userId;
    private AuthCodeType signatureType;
    private List<String> applicationRoles;
    private boolean tokenValid;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public AuthCodeType getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(AuthCodeType signatureType) {
        this.signatureType = signatureType;
    }

    public List<String> getApplicationRoles() {
        return applicationRoles;
    }

    public void setApplicationRoles(List<String> applicationRoles) {
        this.applicationRoles = applicationRoles;
    }

    public boolean isTokenValid() {
        return tokenValid;
    }

    public void setTokenValid(boolean tokenValid) {
        this.tokenValid = tokenValid;
    }

    @NonNull
    public TokenInfo toTokenInfo() {
        TokenInfo info = new TokenInfo();
        info.setActivationId(activationId);
        info.setApplicationId(applicationId);
        info.setUserId(userId);
        info.setAuthenticationCodeType(signatureType);
        info.setApplicationRoles(applicationRoles);
        info.setTokenValid(tokenValid);
        return info;
    }
}
