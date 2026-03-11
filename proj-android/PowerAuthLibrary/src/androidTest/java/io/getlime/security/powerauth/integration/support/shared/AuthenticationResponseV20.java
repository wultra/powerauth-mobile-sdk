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

import java.util.List;

import io.getlime.security.powerauth.integration.support.model.ActivationStatus;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;

public class AuthenticationResponseV20 {

    private String activationId;
    private ActivationStatus activationStatus;
    private String applicationId;
    private List<String> applicationRoles;
    private String userId;
    private String blockedReason;
    private Long remainingAttempts;
    private AuthCodeType authenticationCodeType;
    private boolean authenticationValid;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public List<String> getApplicationRoles() {
        return applicationRoles;
    }

    public void setApplicationRoles(List<String> applicationRoles) {
        this.applicationRoles = applicationRoles;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getBlockedReason() {
        return blockedReason;
    }

    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    public Long getRemainingAttempts() {
        return remainingAttempts;
    }

    public void setRemainingAttempts(Long remainingAttempts) {
        this.remainingAttempts = remainingAttempts;
    }

    public AuthCodeType getAuthenticationCodeType() {
        return authenticationCodeType;
    }

    public void setAuthenticationCodeType(AuthCodeType authenticationCodeType) {
        this.authenticationCodeType = authenticationCodeType;
    }

    public boolean isAuthenticationValid() {
        return authenticationValid;
    }

    public void setAuthenticationValid(boolean authenticationValid) {
        this.authenticationValid = authenticationValid;
    }

    public AuthenticationResult copyToAuthResult() {
        AuthenticationResult res = new AuthenticationResult();
        res.setActivationId(activationId);
        res.setActivationStatus(activationStatus);
        res.setApplicationRoles(applicationRoles);
        res.setUserId(userId);
        res.setBlockedReason(blockedReason);
        res.setRemainingAttempts(remainingAttempts);
        res.setAuthenticationCodeType(authenticationCodeType);
        res.setAuthenticationValid(authenticationValid);
        return res;
    }
}
