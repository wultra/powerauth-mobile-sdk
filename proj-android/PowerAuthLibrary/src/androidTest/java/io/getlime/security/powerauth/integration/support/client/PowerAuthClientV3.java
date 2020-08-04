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

package io.getlime.security.powerauth.integration.support.client;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.Collections;
import java.util.List;

import io.getlime.security.powerauth.integration.support.PowerAuthServerApi;
import io.getlime.security.powerauth.integration.support.endpoints.BlockActivationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.BlockActivationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.BlockActivationResponse;
import io.getlime.security.powerauth.integration.support.endpoints.CommitActivationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.CommitActivationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.CommitActivationResponse;
import io.getlime.security.powerauth.integration.support.endpoints.CreateApplicationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.CreateApplicationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.CreateApplicationVersionEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.CreateApplicationVersionRequest;
import io.getlime.security.powerauth.integration.support.endpoints.GetActivationStatusEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.GetActivationStatusRequest;
import io.getlime.security.powerauth.integration.support.endpoints.GetApplicationDetailEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.GetApplicationDetailRequest;
import io.getlime.security.powerauth.integration.support.endpoints.GetApplicationListEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.GetApplicationListResponse;
import io.getlime.security.powerauth.integration.support.endpoints.GetRecoveryConfigEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.GetRecoveryConfigRequest;
import io.getlime.security.powerauth.integration.support.endpoints.GetSystemStatusEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.GetSystemStatusResponse;
import io.getlime.security.powerauth.integration.support.endpoints.IServerApiEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.InitActivationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.InitActivationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.RemoveActivationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.RemoveActivationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.RemoveActivationResponse;
import io.getlime.security.powerauth.integration.support.endpoints.SetApplicationVersionSupportRequest;
import io.getlime.security.powerauth.integration.support.endpoints.SetApplicationVersionSupportResponse;
import io.getlime.security.powerauth.integration.support.endpoints.SetApplicationVersionSupportedEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.SetApplicationVersionUnsupportedEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.UnblockActivationEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.UnblockActivationRequest;
import io.getlime.security.powerauth.integration.support.endpoints.UnblockActivationResponse;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateActivationOtpEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateActivationOtpRequest;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateActivationOtpResponse;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateRecoveryConfigEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateRecoveryConfigRequest;
import io.getlime.security.powerauth.integration.support.endpoints.UpdateRecoveryConfigResponse;
import io.getlime.security.powerauth.integration.support.endpoints.ValidateTokenEndpoint;
import io.getlime.security.powerauth.integration.support.endpoints.ValidateTokenRequest;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.ActivationOtpValidation;
import io.getlime.security.powerauth.integration.support.model.ActivationStatus;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;
import io.getlime.security.powerauth.integration.support.model.ApplicationVersion;
import io.getlime.security.powerauth.integration.support.model.RecoveryConfig;
import io.getlime.security.powerauth.integration.support.model.ServerConstants;
import io.getlime.security.powerauth.integration.support.model.ServerVersion;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;

public class PowerAuthClientV3 implements PowerAuthServerApi {

    private final @NonNull HttpRestClient restClient;
    private final @NonNull ServerVersion minSupportedVersion;
    private final @NonNull ServerVersion maxSupportedVersion;
    private ServerVersion currentServerVersion;

    /**
     * Create REST client that communicate with PowerAuth Server RESTful API.
     *
     * @param serverApiUrl URL to PowerAuth Server.
     * @param minSupportedVersion Minimum supported server version. If {@code null} is provided, then {@link ServerVersion#LATEST} is used.
     * @param maxSupportedVersion Maximum supported server version. If {@code null} is provided, then {@link ServerVersion#LATEST} is used.
     */
    public PowerAuthClientV3(@NonNull String serverApiUrl, @Nullable ServerVersion minSupportedVersion, @Nullable ServerVersion maxSupportedVersion) throws Exception {
        this.restClient = new HttpRestClient(serverApiUrl);
        this.minSupportedVersion = minSupportedVersion == null ? ServerVersion.LATEST : minSupportedVersion;
        this.maxSupportedVersion = maxSupportedVersion == null ? ServerVersion.LATEST : maxSupportedVersion;
        if (this.minSupportedVersion.numericVersion > this.maxSupportedVersion.numericVersion) {
            throw new Exception("Minimum supported server version is higher that maximum.");
        }
    }

    @Override
    public void validateConnection() throws Exception {
        final GetSystemStatusResponse response = restClient.send(null, new GetSystemStatusEndpoint());
        String version = response.getVersion();
        if (version == null) {
            throw new Exception("Missing version in system status response.");
        }
        currentServerVersion = ServerVersion.versionFromString(version, true);
        if (currentServerVersion.numericVersion < minSupportedVersion.numericVersion || currentServerVersion.numericVersion > maxSupportedVersion.numericVersion) {
            throw new Exception("Unsupported server version " + response.getVersion());
        }
    }

    @NonNull
    @Override
    public ServerVersion getServerVersion() throws Exception {
        if (currentServerVersion == null) {
            validateConnection();
            if (currentServerVersion == null) {
                throw new Exception("Cannot determine server version.");
            }
        }
        return currentServerVersion;
    }

    @NonNull
    @Override
    public List<Application> getApplicationList() throws Exception {
        final GetApplicationListResponse response = restClient.send(null, new GetApplicationListEndpoint());
        return response.getApplications() != null ? response.getApplications() : Collections.<Application>emptyList();
    }

    @NonNull
    @Override
    public Application createApplication(@NonNull String applicationName) throws Exception {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(applicationName);
        return restClient.send(request, new CreateApplicationEndpoint());
    }

    @NonNull
    @Override
    public ApplicationDetail getApplicationDetailByName(@NonNull String applicationName) throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(applicationName);
        return restClient.send(request, new GetApplicationDetailEndpoint());
    }

    @NonNull
    @Override
    public ApplicationDetail getApplicationDetailById(long applicationId) throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return restClient.send(request, new GetApplicationDetailEndpoint());
    }

    @NonNull
    @Override
    public ApplicationVersion createApplicationVersion(long applicationId, @NonNull String versionName) throws Exception {
        final CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return restClient.send(request, new CreateApplicationVersionEndpoint());
    }

    @Override
    public void setApplicationVersionSupported(long applicationVersionId, boolean supported) throws Exception {
        final SetApplicationVersionSupportRequest request = new SetApplicationVersionSupportRequest();
        request.setApplicationVersionId(applicationVersionId);
        final IServerApiEndpoint<SetApplicationVersionSupportResponse> endpoint;
        if (supported) {
            endpoint = new SetApplicationVersionSupportedEndpoint();
        } else {
            endpoint = new SetApplicationVersionUnsupportedEndpoint();
        }
        final SetApplicationVersionSupportResponse response = restClient.send(request, endpoint);
        if (response.isSupported() != supported) {
            throw new Exception("Application version is still " + (supported ? "unsupported" : "supported") + " after successful response.");
        }
    }

    @NonNull
    @Override
    public RecoveryConfig getRecoveryConfig(long applicationId) throws Exception {
        final GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return restClient.send(request, new GetRecoveryConfigEndpoint());
    }

    @Override
    public void updateRecoveryConfig(@NonNull RecoveryConfig recoveryConfig) throws Exception {
        final UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest(recoveryConfig);
        final UpdateRecoveryConfigResponse response = restClient.send(request, new UpdateRecoveryConfigEndpoint());
        if (!response.isUpdated()) {
            throw new Exception("Recovery config for application " + recoveryConfig.getApplicationId() + " is not updated after successful response.");
        }
    }

    @NonNull
    @Override
    public Activation activationInit(@NonNull Application application, @NonNull String userId, @Nullable String otp, @Nullable ActivationOtpValidation otpValidation, @Nullable Long maxFailureCount) throws Exception {
        if ((otp != null && otpValidation == null) || (otp == null) && (otpValidation != null)) {
            throw new Exception("Invalid combination of activation OTP and OTP validation.");
        }
        final InitActivationRequest request = new InitActivationRequest();
        request.setApplicationId(application.getApplicationId());
        request.setUserId(userId);
        request.setActivationOtp(otp);
        request.setActivationOtpValidation(otpValidation);
        request.setMaxFailureCount(maxFailureCount != null ? maxFailureCount : ServerConstants.DEFAULT_MAX_FAILURE_ATTEMPTS);
        return restClient.send(request, new InitActivationEndpoint());
    }

    @NonNull
    @Override
    public Activation activationInit(@NonNull Application application, @NonNull String userId) throws Exception {
        return activationInit(application, userId, null, null, null);
    }

    @Override
    public void updateActivationOtp(@NonNull String activationId, @NonNull String otp, @Nullable String externalUserId) throws Exception {
        final UpdateActivationOtpRequest request = new UpdateActivationOtpRequest();
        request.setActivationId(activationId);
        request.setActivationOtp(otp);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final UpdateActivationOtpResponse response = restClient.send(request, new UpdateActivationOtpEndpoint());
        if (!response.isUpdated()) {
            throw new Exception("Ativation OTP for activation " + activationId + " is not updated after request success.");
        }
    }

    @Override
    public void updateActivationOtp(@NonNull Activation activation, @NonNull String otp) throws Exception {
        updateActivationOtp(activation.getActivationId(), otp, ServerConstants.DEFAULT_EXTERNAL_USER_ID);
    }

    @Override
    public void activationCommit(@NonNull String activationId, @Nullable String otp, @Nullable String externalUserId) throws Exception {
        final CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setActivationOtp(otp);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final CommitActivationResponse response = restClient.send(request, new CommitActivationEndpoint());
        if (!response.isActivated()) {
            throw new Exception("Activation " + activationId + " is not activated after commit after successful response.");
        }
    }

    @Override
    public void activationCommit(@NonNull Activation activation) throws Exception {
        activationCommit(activation.getActivationId(), null, ServerConstants.DEFAULT_EXTERNAL_USER_ID);
    }

    @Override
    public void activationRemove(@NonNull String activationId, @Nullable String externalUserId, boolean revokeRecoveryCodes) throws Exception {
        final RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        final RemoveActivationResponse response = restClient.send(request, new RemoveActivationEndpoint());
        if (!response.isRemoved()) {
            throw new Exception("Activation " + activationId + " is not removed after request success.");
        }
    }

    @Override
    public void activationRemove(@NonNull Activation activation) throws Exception {
        activationRemove(activation.getActivationId(), ServerConstants.DEFAULT_EXTERNAL_USER_ID, true);
    }

    @Override
    public void activationBlock(@NonNull String activationId, @Nullable String reason, @Nullable String externalUserId) throws Exception {
        final BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason != null ? reason : ServerConstants.BLOCKED_REASON_NOT_SPECIFIED);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final BlockActivationResponse response = restClient.send(request, new BlockActivationEndpoint());
        if (response.getActivationStatus() != ActivationStatus.BLOCKED) {
            throw new Exception("Activation " + activationId + " is not blocked after block request success.");
        }
    }

    @Override
    public void activationBlock(@NonNull Activation activation) throws Exception {
        activationBlock(activation.getActivationId(), ServerConstants.BLOCKED_REASON_NOT_SPECIFIED, ServerConstants.DEFAULT_EXTERNAL_USER_ID);
    }

    @Override
    public void activationUnblock(@NonNull String activationId, @Nullable String externalUserId) throws Exception {
        final UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final UnblockActivationResponse response = restClient.send(request, new UnblockActivationEndpoint());
        if (response.getActivationStatus() != ActivationStatus.ACTIVE) {
            throw new Exception("Activation " + activationId + " is not active after unblock request success.");
        }
    }

    @Override
    public void activationUnblock(@NonNull Activation activation) throws Exception {
        activationUnblock(activation.getActivationId(), ServerConstants.DEFAULT_EXTERNAL_USER_ID);
    }

    @NonNull
    @Override
    public ActivationDetail getActivationDetail(@NonNull String activationId, @Nullable String challenge) throws Exception {
        final GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return restClient.send(request, new GetActivationStatusEndpoint());
    }

    @NonNull
    @Override
    public ActivationDetail getActivationDetail(@NonNull Activation activation) throws Exception {
        return getActivationDetail(activation.getActivationId(), null);
    }

    @NonNull
    @Override
    public TokenInfo validateToken(@NonNull String tokenId, @NonNull String tokenDigest, @NonNull String nonce, long timestamp) throws Exception {
        final ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setTokenDigest(tokenDigest);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        return restClient.send(request, new ValidateTokenEndpoint());
    }
}
