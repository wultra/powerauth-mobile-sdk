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

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class ActivationDetail {

    private String activationId;
    private ActivationStatus activationStatus;
    private ActivationOtpValidation activationOtpValidation;
    private String blockedReason;
    private String activationName;
    private String userId;
    private String extras;
    private String platform;
    private String deviceInfo;
    private List<String> activationFlags;
    private long applicationId;
    private String encryptedStatusBlob;
    private String encryptedStatusBlobNonce;
    private String activationCode;
    private String activationSignature;
    private String devicePublicKeyFingerprint;
    @SerializedName("version")
    private int protocolVersion;

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

    public ActivationOtpValidation getActivationOtpValidation() {
        return activationOtpValidation;
    }

    public void setActivationOtpValidation(ActivationOtpValidation activationOtpValidation) {
        this.activationOtpValidation = activationOtpValidation;
    }

    public String getBlockedReason() {
        return blockedReason;
    }

    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    public String getActivationName() {
        return activationName;
    }

    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getExtras() {
        return extras;
    }

    public void setExtras(String extras) {
        this.extras = extras;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public List<String> getActivationFlags() {
        return activationFlags;
    }

    public void setActivationFlags(List<String> activationFlags) {
        this.activationFlags = activationFlags;
    }

    public long getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(long applicationId) {
        this.applicationId = applicationId;
    }

    public String getEncryptedStatusBlob() {
        return encryptedStatusBlob;
    }

    public void setEncryptedStatusBlob(String encryptedStatusBlob) {
        this.encryptedStatusBlob = encryptedStatusBlob;
    }

    public String getEncryptedStatusBlobNonce() {
        return encryptedStatusBlobNonce;
    }

    public void setEncryptedStatusBlobNonce(String encryptedStatusBlobNonce) {
        this.encryptedStatusBlobNonce = encryptedStatusBlobNonce;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    public String getActivationSignature() {
        return activationSignature;
    }

    public void setActivationSignature(String activationSignature) {
        this.activationSignature = activationSignature;
    }

    public String getDevicePublicKeyFingerprint() {
        return devicePublicKeyFingerprint;
    }

    public void setDevicePublicKeyFingerprint(String devicePublicKeyFingerprint) {
        this.devicePublicKeyFingerprint = devicePublicKeyFingerprint;
    }

    public int getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }
}
