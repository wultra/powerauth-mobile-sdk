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

package io.getlime.security.powerauth.integration.support;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.List;

import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.ActivationOtpValidation;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;
import io.getlime.security.powerauth.integration.support.model.ApplicationVersion;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;
import io.getlime.security.powerauth.integration.support.model.RecoveryConfig;
import io.getlime.security.powerauth.integration.support.model.ServerVersion;
import io.getlime.security.powerauth.integration.support.model.SignatureData;
import io.getlime.security.powerauth.integration.support.model.SignatureInfo;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;

public interface PowerAuthServerApi {

    /**
     * Validates connection to the PowerAuth Server RESTFul API.
     * @throws Exception In case that there's no connection or you're connecting to a wrong server.
     */
    void validateConnection() throws Exception;

    /**
     * @return {@link ServerVersion} enumeration.
     */
    @NonNull ServerVersion getServerVersion() throws Exception;

    // Application & Application Version

    /**
     * Return list of available applications.
     * @return List of {@link Application} objects.
     * @throws Exception if operation fails.
     */
    @NonNull List<Application> getApplicationList() throws Exception;

    /**
     * Create a new application with given name.
     * @param applicationName Application name.
     * @return {@link Application} object representing just created application.
     * @throws Exception if operation fails.
     */
    @NonNull Application createApplication(@NonNull String applicationName) throws Exception;

    /**
     * Lookup for application by application name.
     * @param applicationName Application name to look for.
     * @return {@link ApplicationDetail} object with information about application.
     * @throws Exception if operation fails.
     */
    @NonNull ApplicationDetail getApplicationDetailByName(@NonNull String applicationName) throws Exception;

    /**
     * Lookup for application by application id.
     * @param applicationId Application id to look for.
     * @return {@link ApplicationDetail} object with information about application.
     * @throws Exception if operation fails.
     */
    @NonNull ApplicationDetail getApplicationDetailById(long applicationId) throws Exception;

    /**
     * Create a new application version for given application.
     * @param applicationId Application id.
     * @param versionName New version name.
     * @return {@link ApplicationVersion} object with information about just crated application version.
     * @throws Exception if operation fails.
     */
    @NonNull ApplicationVersion createApplicationVersion(long applicationId, @NonNull String versionName) throws Exception;

    /**
     * Set application version supported or unsupported.
     * @param applicationVersionId Identifier of application version to be modified.
     * @param supported If {@code true} then set application supported.
     * @throws Exception if operation fails.
     */
    void setApplicationVersionSupported(long applicationVersionId, boolean supported) throws Exception;

    // Recovery config

    /**
     * Get recovery config for application.
     *
     * @param applicationId Application identifier.
     * @return {@link RecoveryConfig} object.
     * @throws Exception In case of failure.
     */
    @NonNull RecoveryConfig getRecoveryConfig(long applicationId) throws Exception;

    /**
     * Update recovery config for application specified in {@link RecoveryConfig} object.
     * @param recoveryConfig Config that specifies application and fields that should be updated.
     * @throws Exception In case of failure.
     */
    void updateRecoveryConfig(@NonNull RecoveryConfig recoveryConfig) throws Exception;

    // Activation

    /**
     * Initialize activation for give application and user id. You can also specify other optional parameters,
     * like OTP and maximum failure attempts value.
     *
     * @param application {@link Application} with a valid application on the server.
     * @param userId User identifier.
     * @param otp Optional activation OTP.
     * @param otpValidation Optional activation OTP validation mode, that must be provided together with OTP.
     * @param maxFailureCount Optional maximum failure count. If not provided, value 5 will be used.
     * @return {@link Activation} object containing information about just initialized activation.
     * @throws Exception In case of failure.
     */
    @NonNull Activation activationInit(@NonNull Application application, @NonNull String userId, @Nullable String otp, @Nullable ActivationOtpValidation otpValidation, @Nullable Long maxFailureCount) throws Exception;

    /**
     * Initialize activation for give application and user id.
     *
     * @param application {@link Application} with a valid application on the server.
     * @param userId User identifier.
     * @return {@link Activation} object containing information about just initialized activation.
     * @throws Exception In case of failure.
     */
    @NonNull Activation activationInit(@NonNull Application application, @NonNull String userId) throws Exception;

    /**
     * Update activation OTP on the server.
     *
     * @param activationId Activation identifier.
     * @param otp New activation OTP.
     * @param externalUserId External user identifier.
     * @throws Exception In case of failure.
     */
    void updateActivationOtp(@NonNull String activationId, @NonNull String otp, @Nullable String externalUserId) throws Exception;

    /**
     * Update activation OTP on the server.
     * @param activation {@link Activation} object containing information about activation.
     * @param otp New activation OTP.
     * @throws Exception In case of failure.
     */
    void updateActivationOtp(@NonNull Activation activation, @NonNull String otp) throws Exception;

    /**
     * Commit activation on the server.
     * @param activationId Activation identifier.
     * @param otp Optional OTP, in case that OTP is expected in this phase.
     * @param externalUserId External user identifier.
     * @throws Exception In case of failure.
     */
    void activationCommit(@NonNull String activationId, @Nullable String otp, @Nullable String externalUserId) throws Exception;

    /**
     * Commit activation on the server.
     * @param activation {@link Activation} object containing information about activation.
     * @throws Exception In case of failure.
     */
    void activationCommit(@NonNull Activation activation) throws Exception;

    /**
     * Remove activation on the server.
     *
     * @param activationId Activation identifier.
     * @param externalUserId Optional external user identifier.
     * @param revokeRecoveryCodes Also revoke recovery codes associated to this activation.
     * @throws Exception In case of failure.
     */
    void activationRemove(@NonNull String activationId, @Nullable String externalUserId, boolean revokeRecoveryCodes) throws Exception;

    /**
     * Remove activation on the server and also revoke any associated recovery code with it.
     *
     * @param activation {@link Activation} object containing information about activation.
     * @throws Exception In case of failure.
     */
    void activationRemove(@NonNull Activation activation) throws Exception;

    /**
     * Set activation blocked on the server.
     *
     * @param activationId Activation identifier.
     * @param reason Optional block reason.
     * @param externalUserId Optional external user identifier.
     * @throws Exception In case of failure.
     */
    void activationBlock(@NonNull String activationId, @Nullable String reason, @Nullable String externalUserId) throws Exception;

    /**
     * Set activation blocked on the server.
     *
     * @param activation {@link Activation} object containing information about activation.
     * @throws Exception In case of failure.
     */
    void activationBlock(@NonNull Activation activation) throws Exception;

    /**
     * Set activation unblocked on the server.
     * @param activationId Activation identifier.
     * @param externalUserId Optional external user identifier.
     * @throws Exception In case of failure.
     */
    void activationUnblock(@NonNull String activationId, @Nullable String externalUserId) throws Exception;

    /**
     * Set activation unblocked on the server.
     *
     * @param activation {@link Activation} object containing information about activation.
     * @throws Exception In case of failure.
     */
    void activationUnblock(@NonNull Activation activation) throws Exception;

    /**
     * Get information about activation.
     *
     * @param activationId Activation identifier.
     * @param challenge Optional challenge, required for acquiring V3.1 {@code encryptedStatusBlob}.
     * @return {@link ActivationDetail} object.
     * @throws Exception In case of failure.
     */
    @NonNull ActivationDetail getActivationDetail(@NonNull String activationId, @Nullable String challenge) throws Exception;

    /**
     * Get information about activation.
     *
     * @param activation {@link Activation} object containing information about activation.
     * @return {@link ActivationDetail} object.
     * @throws Exception In case of failure.
     */
    @NonNull ActivationDetail getActivationDetail(@NonNull Activation activation) throws Exception;

    // Tokens

    /**
     * Validate token on the server.
     *
     * @param tokenId Token identifier.
     * @param tokenDigest Token digest.
     * @param nonce Nonce in Base64 encoding.
     * @param timestamp Timestamp used for calculate token.
     * @return {@link TokenInfo} object in case of success.
     * @throws Exception In case of failure.
     */
    @NonNull TokenInfo validateToken(@NonNull String tokenId, @NonNull String tokenDigest, @NonNull String nonce, long timestamp) throws Exception;

    // Signatures

    /**
     * Verify online signature on the server.
     * @param signatureData {@link SignatureData} object that contains common and online-specific properties set.
     * @return {@link SignatureInfo} with verification result.
     * @throws Exception In case of failure.
     */
    @NonNull SignatureInfo verifyOnlineSignature(@NonNull SignatureData signatureData) throws Exception;

    /**
     * Verify offline signature on the server.
     * @param signatureData {@link SignatureData} object that contains common and offline-specific properties set.
     * @return {@link SignatureInfo} with verification result.
     * @throws Exception In case of failure.
     */
    @NonNull SignatureInfo verifyOfflineSignature(@NonNull SignatureData signatureData) throws Exception;

    /**
     * Verify ECDSA signature, calculated with device's private key.
     * @param activationId Activation identifier.
     * @param data Signed data.
     * @param signature Signature for data.
     * @return {@code true} if signature is valid.
     * @throws Exception In case of failure.
     */
    boolean verifyEcdsaSignature(@NonNull String activationId, @NonNull String data, @NonNull String signature) throws Exception;

    /**
     * Create a payload for offline QR code, signed with non-personalized private key.
     * @param applicationId Application identifier.
     * @param data Data to sign.
     * @return {@link OfflineSignaturePayload} with payload data.
     * @throws Exception In case of failure.
     */
    @NonNull OfflineSignaturePayload createNonPersonalizedOfflineSignaturePayload(long applicationId, @NonNull String data) throws Exception;

    /**
     * Create a payload for offline QR code, signed with personalized private key associated with user's activation.
     * @param activationId Activation identifier.
     * @param data Data to sign.
     * @return {@link OfflineSignaturePayload} with payload data.
     * @throws Exception In case of failure.
     */
    @NonNull OfflineSignaturePayload createPersonalizedOfflineSignaturePayload(@NonNull String activationId, @NonNull String data) throws Exception;
}
