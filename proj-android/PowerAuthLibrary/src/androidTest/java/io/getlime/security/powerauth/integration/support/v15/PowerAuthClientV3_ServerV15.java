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

package io.getlime.security.powerauth.integration.support.v15;

import java.util.Collections;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.integration.support.PowerAuthServerApi;
import io.getlime.security.powerauth.integration.support.client.HttpRestClient;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.ActivationOtpValidation;
import io.getlime.security.powerauth.integration.support.model.ActivationStatus;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;
import io.getlime.security.powerauth.integration.support.model.ApplicationVersion;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;
import io.getlime.security.powerauth.integration.support.model.RecoveryConfig;
import io.getlime.security.powerauth.integration.support.model.ServerConstants;
import io.getlime.security.powerauth.integration.support.model.ServerVersion;
import io.getlime.security.powerauth.integration.support.model.SignatureData;
import io.getlime.security.powerauth.integration.support.model.SignatureInfo;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;
import io.getlime.security.powerauth.integration.support.v15.endpoints.BlockActivationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.CommitActivationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.CreateApplicationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.CreateApplicationVersionEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.CreateNonPersonalizedOfflineSignaturePayloadEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.CreatePersonalizedOfflineSignaturePayloadEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.GetActivationStatusEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.GetApplicationDetailEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.GetApplicationListEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.GetRecoveryConfigEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.GetSystemStatusEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.InitActivationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.RemoveActivationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.SetApplicationVersionSupportedEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.UnblockActivationEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.UpdateActivationOtpEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.UpdateRecoveryConfigEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.ValidateTokenEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.VerifyEcdsaSignatureEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.VerifyOfflineSignatureEndpoint;
import io.getlime.security.powerauth.integration.support.v15.endpoints.VerifyOnlineSignatureEndpoint;

public class PowerAuthClientV3_ServerV15 implements PowerAuthServerApi {

    private final @NonNull HttpRestClient restClient;
    private final @NonNull ServerVersion minSupportedVersion;
    private final @NonNull ServerVersion maxSupportedVersion;
    private ServerVersion currentServerVersion;

    /**
     * Create REST client that communicate with PowerAuth Server RESTful API.
     *
     * @param serverApiUrl URL to PowerAuth Server.
     * @param authorization Optional authorization header value, if PowerAuth Server require authorization.
     * @param minSupportedVersion Minimum supported server version. If {@code null} is provided, then {@link ServerVersion#LATEST} is used.
     * @param maxSupportedVersion Maximum supported server version. If {@code null} is provided, then {@link ServerVersion#LATEST} is used.
     */
    public PowerAuthClientV3_ServerV15(@NonNull String serverApiUrl, @Nullable String authorization, @Nullable ServerVersion minSupportedVersion, @Nullable ServerVersion maxSupportedVersion) throws Exception {
        this.restClient = new HttpRestClient(serverApiUrl, authorization);
        this.minSupportedVersion = minSupportedVersion == null ? ServerVersion.LATEST : minSupportedVersion;
        this.maxSupportedVersion = maxSupportedVersion == null ? ServerVersion.LATEST : maxSupportedVersion;
        if (this.minSupportedVersion.numericVersion > this.maxSupportedVersion.numericVersion) {
            throw new Exception("Minimum supported server version is higher that maximum.");
        }
    }

    @Override
    public void validateConnection() throws Exception {
        final GetSystemStatusEndpoint.Response response = restClient.send(null, new GetSystemStatusEndpoint());
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

    @Nullable
    @Override
    public Application findApplicationByName(@NonNull String applicationName) throws Exception {
        final GetApplicationListEndpoint.Response response = restClient.send(null, new GetApplicationListEndpoint());
        if (response != null && response.getApplications() != null) {
            for (Application app : response.getApplications()) {
                // If V1.3 server has been migrated from older version, then contains previous application names in form of identifier.
                // There's no such application name in the new model.
                if (applicationName.equals(app.getApplicationId())) {
                    return app;
                }
            }
        }
        return null;
    }

    @Nullable
    @Override
    public ApplicationVersion findApplicationVersionByName(@NonNull ApplicationDetail applicationDetail, @NonNull String applicationVersionName) throws Exception {
        if (applicationDetail.getVersions() != null) {
            for (ApplicationVersion version: applicationDetail.getVersions()) {
                // If V1.3 server has been migrated from older version, then contains previous version names in form of identifier.
                // There's no such application version name in the new model.
                if (applicationVersionName.equals(version.getApplicationVersionId())) {
                    return version;
                }
            }
        }
        return null;
    }

    @NonNull
    @Override
    public List<Application> getApplicationList() throws Exception {
        final GetApplicationListEndpoint.Response response = restClient.send(null, new GetApplicationListEndpoint());
        return response.getApplications() != null ? response.getApplications() : Collections.<Application>emptyList();
    }

    @NonNull
    @Override
    public Application createApplication(@NonNull String applicationName) throws Exception {
        final CreateApplicationEndpoint.Request request = new CreateApplicationEndpoint.Request();
        request.setApplicationId(applicationName);
        return restClient.send(request, new CreateApplicationEndpoint());
    }

    @NonNull
    @Override
    public ApplicationDetail getApplicationDetailByName(@NonNull String applicationName) throws Exception {
        final GetApplicationDetailEndpoint.Request request = new GetApplicationDetailEndpoint.Request();
        request.setApplicationName(applicationName);
        return restClient.send(request, new GetApplicationDetailEndpoint());
    }

    @NonNull
    @Override
    public ApplicationDetail getApplicationDetailById(String applicationId) throws Exception {
        final GetApplicationDetailEndpoint.Request request = new GetApplicationDetailEndpoint.Request();
        request.setApplicationId(applicationId);
        return restClient.send(request, new GetApplicationDetailEndpoint());
    }

    @NonNull
    @Override
    public ApplicationVersion createApplicationVersion(String applicationId, @NonNull String versionName) throws Exception {
        final CreateApplicationVersionEndpoint.Request request = new CreateApplicationVersionEndpoint.Request();
        request.setApplicationId(applicationId);
        request.setApplicationVersionId(versionName);
        return restClient.send(request, new CreateApplicationVersionEndpoint());
    }

    @Override
    public void setApplicationVersionSupported(String applicationVersionId, boolean supported) throws Exception {
        final SetApplicationVersionSupportedEndpoint.Request request = new SetApplicationVersionSupportedEndpoint.Request();
        request.setApplicationVersionId(applicationVersionId);
        final SetApplicationVersionSupportedEndpoint.Response response = restClient.send(request, new SetApplicationVersionSupportedEndpoint(supported));
        if (response.isSupported() != supported) {
            throw new Exception("Application version is still " + (supported ? "unsupported" : "supported") + " after successful response.");
        }
    }

    @NonNull
    @Override
    public RecoveryConfig getRecoveryConfig(String applicationId) throws Exception {
        final GetRecoveryConfigEndpoint.Request request = new GetRecoveryConfigEndpoint.Request();
        request.setApplicationId(applicationId);
        return restClient.send(request, new GetRecoveryConfigEndpoint());
    }

    @Override
    public void updateRecoveryConfig(@NonNull RecoveryConfig recoveryConfig) throws Exception {
        final UpdateRecoveryConfigEndpoint.Request request = new UpdateRecoveryConfigEndpoint.Request(recoveryConfig);
        final UpdateRecoveryConfigEndpoint.Response response = restClient.send(request, new UpdateRecoveryConfigEndpoint());
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
        final InitActivationEndpoint.Request request = new InitActivationEndpoint.Request();
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
        final UpdateActivationOtpEndpoint.Request request = new UpdateActivationOtpEndpoint.Request();
        request.setActivationId(activationId);
        request.setActivationOtp(otp);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final UpdateActivationOtpEndpoint.Response response = restClient.send(request, new UpdateActivationOtpEndpoint());
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
        final CommitActivationEndpoint.Request request = new CommitActivationEndpoint.Request();
        request.setActivationId(activationId);
        request.setActivationOtp(otp);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final CommitActivationEndpoint.Response response = restClient.send(request, new CommitActivationEndpoint());
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
        final RemoveActivationEndpoint.Request request = new RemoveActivationEndpoint.Request();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        final RemoveActivationEndpoint.Response response = restClient.send(request, new RemoveActivationEndpoint());
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
        final BlockActivationEndpoint.Request request = new BlockActivationEndpoint.Request();
        request.setActivationId(activationId);
        request.setReason(reason != null ? reason : ServerConstants.BLOCKED_REASON_NOT_SPECIFIED);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final BlockActivationEndpoint.Response response = restClient.send(request, new BlockActivationEndpoint());
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
        final UnblockActivationEndpoint.Request request = new UnblockActivationEndpoint.Request();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId != null ? externalUserId : ServerConstants.DEFAULT_EXTERNAL_USER_ID);
        final UnblockActivationEndpoint.Response response = restClient.send(request, new UnblockActivationEndpoint());
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
        final GetActivationStatusEndpoint.Request request = new GetActivationStatusEndpoint.Request();
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
    public TokenInfo validateToken(@NonNull String tokenId, @NonNull String tokenDigest, @NonNull String nonce, long timestamp, @NonNull String protocolVersion) throws Exception {
        final ValidateTokenEndpoint.Request request = new ValidateTokenEndpoint.Request();
        request.setTokenId(tokenId);
        request.setTokenDigest(tokenDigest);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setProtocolVersion(protocolVersion);
        return restClient.send(request, new ValidateTokenEndpoint());
    }

    @NonNull
    @Override
    public SignatureInfo verifyOnlineSignature(@NonNull SignatureData signatureData) throws Exception {
        final VerifyOnlineSignatureEndpoint.Request request = new VerifyOnlineSignatureEndpoint.Request(signatureData);
        return restClient.send(request, new VerifyOnlineSignatureEndpoint());
    }

    @NonNull
    @Override
    public SignatureInfo verifyOfflineSignature(@NonNull SignatureData signatureData) throws Exception {
        final VerifyOfflineSignatureEndpoint.Request request = new VerifyOfflineSignatureEndpoint.Request(signatureData);
        return restClient.send(request, new VerifyOfflineSignatureEndpoint());
    }

    @Override
    public boolean verifyEcdsaSignature(@NonNull String activationId, @NonNull String data, @NonNull String signature) throws Exception {
        final VerifyEcdsaSignatureEndpoint.Request request = new VerifyEcdsaSignatureEndpoint.Request();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        final VerifyEcdsaSignatureEndpoint.Response response = restClient.send(request, new VerifyEcdsaSignatureEndpoint());
        return response.isSignatureValid();
    }

    @NonNull
    @Override
    public OfflineSignaturePayload createNonPersonalizedOfflineSignaturePayload(String  applicationId, @NonNull String data) throws Exception {
        final CreateNonPersonalizedOfflineSignaturePayloadEndpoint.Request request = new CreateNonPersonalizedOfflineSignaturePayloadEndpoint.Request();
        request.setApplicationId(applicationId);
        request.setData(data);
        return restClient.send(request, new CreateNonPersonalizedOfflineSignaturePayloadEndpoint());
    }

    @NonNull
    @Override
    public OfflineSignaturePayload createPersonalizedOfflineSignaturePayload(@NonNull String activationId, @NonNull String data) throws Exception {
        final CreatePersonalizedOfflineSignaturePayloadEndpoint.Request request = new CreatePersonalizedOfflineSignaturePayloadEndpoint.Request();
        request.setActivationId(activationId);
        request.setData(data);
        return restClient.send(request, new CreatePersonalizedOfflineSignaturePayloadEndpoint());
    }
}
