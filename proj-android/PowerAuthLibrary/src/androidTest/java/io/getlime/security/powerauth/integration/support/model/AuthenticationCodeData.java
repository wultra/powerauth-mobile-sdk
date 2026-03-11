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

public class AuthenticationCodeData {

    // Common for online and offline signature
    private String activationId;
    private String data;
    private String authenticationCode;

    // Online specific
    private AuthCodeType authenticationCodeType;
    private String authenticationVersion;
    private Long forcedAuthenticationVersion;
    private String applicationKey;

    // Offline specific
    private Boolean allowBiometry;

    private Long offlineAuthenticationCodeComponentLength;

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
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

    public String getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public Boolean getAllowBiometry() {
        return allowBiometry;
    }

    public void setAllowBiometry(Boolean allowBiometry) {
        this.allowBiometry = allowBiometry;
    }

    public Long getOfflineAuthenticationCodeComponentLength() {
        return offlineAuthenticationCodeComponentLength;
    }

    public void setOfflineAuthenticationCodeComponentLength(Long offlineAuthenticationCodeComponentLength) {
        this.offlineAuthenticationCodeComponentLength = offlineAuthenticationCodeComponentLength;
    }
}
