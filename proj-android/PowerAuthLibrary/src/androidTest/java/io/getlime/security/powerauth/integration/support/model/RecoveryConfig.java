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

public class RecoveryConfig {

    // Always present values
    private long applicationId;
    private boolean activationRecoveryEnabled;
    private boolean recoveryPostcardEnabled;

    // Optional values
    private Boolean allowMultipleRecoveryCodes;
    private String postcardPublicKey; // Should not be set in update
    private String remotePostcardPublicKey;

    public long getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(long applicationId) {
        this.applicationId = applicationId;
    }

    public boolean isActivationRecoveryEnabled() {
        return activationRecoveryEnabled;
    }

    public void setActivationRecoveryEnabled(boolean activationRecoveryEnabled) {
        this.activationRecoveryEnabled = activationRecoveryEnabled;
    }

    public boolean isRecoveryPostcardEnabled() {
        return recoveryPostcardEnabled;
    }

    public void setRecoveryPostcardEnabled(boolean recoveryPostcardEnabled) {
        this.recoveryPostcardEnabled = recoveryPostcardEnabled;
    }

    public Boolean getAllowMultipleRecoveryCodes() {
        return allowMultipleRecoveryCodes;
    }

    public void setAllowMultipleRecoveryCodes(Boolean allowMultipleRecoveryCodes) {
        this.allowMultipleRecoveryCodes = allowMultipleRecoveryCodes;
    }

    public String getPostcardPublicKey() {
        return postcardPublicKey;
    }

    public void setPostcardPublicKey(String postcardPublicKey) {
        this.postcardPublicKey = postcardPublicKey;
    }

    public String getRemotePostcardPublicKey() {
        return remotePostcardPublicKey;
    }

    public void setRemotePostcardPublicKey(String remotePostcardPublicKey) {
        this.remotePostcardPublicKey = remotePostcardPublicKey;
    }
}
