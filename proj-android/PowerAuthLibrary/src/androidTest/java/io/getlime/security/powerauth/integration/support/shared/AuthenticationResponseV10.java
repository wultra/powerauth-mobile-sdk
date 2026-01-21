package io.getlime.security.powerauth.integration.support.shared;

import java.util.List;

import io.getlime.security.powerauth.integration.support.model.ActivationStatus;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;

public class AuthenticationResponseV10 {

    private String activationId;
    private ActivationStatus activationStatus;
    private String applicationId;
    private List<String> applicationRoles;
    private String userId;
    private String blockedReason;
    private Long remainingAttempts;
    private AuthCodeType signatureType;
    private boolean signatureValid;

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

    public AuthCodeType getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(AuthCodeType signatureType) {
        this.signatureType = signatureType;
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public AuthenticationResult copyToAuthResult() {
        AuthenticationResult res = new AuthenticationResult();
        res.setActivationId(activationId);
        res.setActivationStatus(activationStatus);
        res.setApplicationRoles(applicationRoles);
        res.setUserId(userId);
        res.setBlockedReason(blockedReason);
        res.setRemainingAttempts(remainingAttempts);
        res.setAuthenticationCodeType(signatureType);
        res.setAuthenticationValid(signatureValid);
        return res;
    }
}

