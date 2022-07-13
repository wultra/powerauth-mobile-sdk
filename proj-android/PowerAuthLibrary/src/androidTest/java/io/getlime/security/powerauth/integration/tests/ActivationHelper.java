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

package io.getlime.security.powerauth.integration.tests;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.List;

import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.Logger;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.ActivationOtpValidation;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ServerConstants;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.response.CreateActivationResult;
import io.getlime.security.powerauth.networking.response.IActivationStatusListener;
import io.getlime.security.powerauth.networking.response.ICreateActivationListener;
import io.getlime.security.powerauth.networking.response.IValidatePasswordListener;
import io.getlime.security.powerauth.sdk.PowerAuthActivation;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * The {@code ActivationHelper} class provides support for activation creation and cleanup.
 */
public class ActivationHelper {

    private final @NonNull PowerAuthTestHelper testHelper;
    private final @NonNull Application application;
    private final @NonNull String userId;
    private final @NonNull PowerAuthSDK powerAuthSDK;
    private Activation activation;
    private PowerAuthAuthentication validAuthentication;
    private PowerAuthAuthentication invalidAuthentication;
    private CreateActivationResult createActivationResult;

    /**
     * Helper's state.
     */
    public static class HelperState {
        Activation activation;
        PowerAuthAuthentication validAuthentication;
        PowerAuthAuthentication invalidAuthentication;
        CreateActivationResult createActivationResult;
        HelperState(Activation activation, PowerAuthAuthentication validAuthentication, PowerAuthAuthentication invalidAuthentication, CreateActivationResult createActivationResult) {
            this.activation = activation;
            this.validAuthentication = validAuthentication;
            this.invalidAuthentication = invalidAuthentication;
            this.createActivationResult = createActivationResult;
        }
    }

    /**
     * Get helper's state that can be used to create another instance of ActivationHelper.
     * @return Helper's state.
     */
    public @NonNull HelperState getHelperState() {
        return new HelperState(activation, validAuthentication, invalidAuthentication, createActivationResult);
    }

    /**
     * Construct activation helper with default values, acquired from test helper and with state saved
     * from another activation helper object.
     * @param testHelper Test helper instance.
     * @param state State acquired from another instance of ActivationHelper.
     */
    public ActivationHelper(@NonNull PowerAuthTestHelper testHelper, @NonNull HelperState state) {
        this.testHelper = testHelper;
        this.application = testHelper.getSharedApplication();
        this.userId = testHelper.getUserId();
        this.powerAuthSDK = testHelper.getSharedSdk();
        this.activation = state.activation;
        this.validAuthentication = state.validAuthentication;
        this.invalidAuthentication = state.invalidAuthentication;
        this.createActivationResult = state.createActivationResult;
    }

    /**
     * Construct activation helper with default values, acquired from test helper.
     * @param testHelper Test helper instance.
     */
    public ActivationHelper(@NonNull PowerAuthTestHelper testHelper) {
        this.testHelper = testHelper;
        this.application = testHelper.getSharedApplication();
        this.userId = testHelper.getUserId();
        this.powerAuthSDK = testHelper.getSharedSdk();
    }

    /**
     * Initialize activation helper with custom values.
     * @param testHelper Test helper instance.
     * @param application Custom application.
     * @param userId Custom user identifier.
     * @param sdk Custom PowerAuthSDK.
     */
    public ActivationHelper(@NonNull PowerAuthTestHelper testHelper, @NonNull Application application, @NonNull String userId, @NonNull PowerAuthSDK sdk) {
        this.testHelper = testHelper;
        this.application = application;
        this.userId = userId;
        this.powerAuthSDK = sdk;
    }

    /**
     * Initialize activation on the server.
     * @return Activation object for just created activation.
     * @throws Exception In case of failure, or when this helper already has an activation.
     */
    public @NonNull Activation initActivation() throws Exception {
        if (activation != null) {
            throw new Exception("ActivationHelper already has an activation. Use removeActivation() before you initialize new activation.");
        }
        activation = testHelper.getServerApi().activationInit(application, userId);
        return activation;
    }

    /**
     * Initialize activation with additional parameters on the server.
     * @param otpValidation OTP validation mode.
     * @param otp OTP value.
     * @param maxFailureAttempts Maximum number of failed attempts.
     * @return Activation object for just created activation.
     * @throws Exception In case of failure, or when this helper already has an activation.
     */
    public @NonNull Activation initActivation(@NonNull ActivationOtpValidation otpValidation, @NonNull String otp, long maxFailureAttempts) throws Exception {
        if (activation != null) {
            throw new Exception("ActivationHelper already has an activation. Use removeActivation() before you initialize new activation.");
        }
        activation = testHelper.getServerApi().activationInit(application, userId, otp, otpValidation,  maxFailureAttempts);
        return activation;
    }

    /**
     * Remove activation on the server and locally, from PowerAuthSDK instance.
     * @param revokeRecoveryCodes Set true to also revoke possible recovery codes associated with the activation.
     * @throws Exception In case of failure.
     */
    public void removeActivation(boolean revokeRecoveryCodes) throws Exception {
        if (activation != null) {
            testHelper.getServerApi().activationRemove(activation.getActivationId(), ServerConstants.DEFAULT_EXTERNAL_USER_ID, revokeRecoveryCodes);
            activation = null;
            validAuthentication = null;
            invalidAuthentication = null;
            createActivationResult = null;
        }
        removeActivationLocal(true);
    }

    /**
     * Remove activation locally.
     *
     * @param removeSharedBiometryKey If true, then also remove a shared biometry key.
     */
    public void removeActivationLocal(boolean removeSharedBiometryKey) {
        if (powerAuthSDK.hasValidActivation()) {
            powerAuthSDK.removeActivationLocal(testHelper.getContext(), removeSharedBiometryKey);
        }
    }

    /**
     * Get information about activation directly from PowerAuth Server.
     * @return {@link ActivationDetail} object.
     * @throws Exception In case of failure.
     */
    public @NonNull ActivationDetail getActivationDetail() throws Exception {
        if (activation == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return testHelper.getServerApi().getActivationDetail(activation);
    }

    /**
     * Fetch activation status with using internal instance of {@link PowerAuthSDK}.
     * @return {@link ActivationStatus} object.
     * @throws Exception In case of failure.
     */
    public @NonNull ActivationStatus fetchActivationStatus() throws Exception {
        return AsyncHelper.await(new AsyncHelper.Execution<ActivationStatus>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<ActivationStatus> resultCatcher) throws Exception {
                powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                    @Override
                    public void onActivationStatusSucceed(ActivationStatus status) {
                        resultCatcher.completeWithResult(status);
                    }

                    @Override
                    public void onActivationStatusFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
    }

    /**
     * Prepare valid and invalid authentication objects.
     * @return Array of passwords used for authentication objects creation. First is valid, second is invalid password.
     * @throws Exception In case that generator failed to generate strings.
     */
    public @NonNull List<String> prepareAuthentications() throws Exception {
        List<String> passwords = testHelper.getRandomGenerator().generateRandomStrings(2, 4, 16);
        validAuthentication = PowerAuthAuthentication.possessionWithPassword(passwords.get(0));
        invalidAuthentication = PowerAuthAuthentication.possessionWithPassword(passwords.get(1));
        return passwords;
    }

    /**
     * Create a standard activation on the server and locally. The result is prepared PowerAuthSDK
     * instance for other tests.
     *
     * @param codeWithSignature If true, then code + signature will be used for the activation.
     * @param extras Extra attributes associated with the activation.
     * @return Information about activation.
     * @throws Exception In case of failure.
     */
    public @NonNull ActivationDetail createStandardActivation(boolean codeWithSignature, @Nullable String extras) throws Exception {

        // Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());

        final List<String> passwords = prepareAuthentications();

        // Initialize activation on the server
        initActivation();

        // Create activation locally
        final String activationCode;
        if (codeWithSignature) {
            activationCode = activation.getActivationCode() + "#" + activation.getActivationSignature();
        } else {
            activationCode = activation.getActivationCode();
        }
        final PowerAuthActivation paActivation = PowerAuthActivation.Builder.activation(activationCode, testHelper.getDeviceInfo())
                .setExtras(extras)
                .build();
        createActivationResult = AsyncHelper.await(new AsyncHelper.Execution<CreateActivationResult>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<CreateActivationResult> resultCatcher) throws Exception {
                powerAuthSDK.createActivation(paActivation, new ICreateActivationListener() {
                    @Override
                    public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                        resultCatcher.completeWithResult(result);
                    }

                    @Override
                    public void onActivationCreateFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
                assertFalse(powerAuthSDK.hasValidActivation());
                assertTrue(powerAuthSDK.hasPendingActivation());
                assertFalse(powerAuthSDK.canStartActivation());
            }
        });

        assertFalse(powerAuthSDK.hasValidActivation());
        assertTrue(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Commit activation locally
        int resultCode = powerAuthSDK.commitActivationWithPassword(testHelper.getContext(), passwords.get(0), null);
        if (resultCode != PowerAuthErrorCodes.SUCCEED) {
            throw new Exception("PowerAuthSDK.commit failed with error code " + resultCode);
        }

        assertTrue(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Fetch status to test whether it's in "pending commit" or "active" state, depending on server's configuration.
        final boolean isAutoCommit = testHelper.getTestConfig().isServerAutoCommit();
        ActivationStatus activationStatus = fetchActivationStatus();
        final @ActivationStatus.ActivationState int expectedState = isAutoCommit ? ActivationStatus.State_Active : ActivationStatus.State_Pending_Commit;
        if (activationStatus.state != expectedState) {
            throw new Exception("Activation is in invalid state after creation. State = " + activationStatus.state + ", Expected = " + expectedState);
        }

        // Compare public key fingerprints
        final ActivationDetail activationDetail = getActivationDetail();
        if (!activationDetail.getDevicePublicKeyFingerprint().equals(createActivationResult.getActivationFingerprint())) {
            throw new Exception("Public key fingerprints doesn't match between server and client.");
        }

        if (!isAutoCommit) {
            // Commit activation on the server.
            testHelper.getServerApi().activationCommit(activation);

            // Fetch status to validate whether activation is now active
            activationStatus = fetchActivationStatus();
            if (activationStatus.state != ActivationStatus.State_Active) {
                throw new Exception("Activation is in invalid state after commit. State = " + activationStatus.state);
            }
        }

        return activationDetail;
    }

    /**
     * Assign a custom created activation and its activation result to this helper object. This method
     * is useful in case that you need to test custom or recovery activations and wants to continue
     * use this helper for other tasks.
     *
     * @param createActivationResult {@link CreateActivationResult} object returned from PowerAuthSDK.
     * @return {@link ActivationDetail) for just assigned activation.
     * @throws Exception In case of failure.
     */
    public @NonNull ActivationDetail assignCustomActivationAndCommitLocally(@NonNull CreateActivationResult createActivationResult) throws Exception {
        if (this.activation != null) {
            throw new Exception("ActivationHelper already has an activation. Use removeActivation() before you initialize new activation.");
        }
        this.createActivationResult = createActivationResult;
        final List<String> passwords = prepareAuthentications();
        // Commit activation locally
        int resultCode = powerAuthSDK.commitActivationWithPassword(testHelper.getContext(), passwords.get(0), null);
        if (resultCode != PowerAuthErrorCodes.SUCCEED) {
            throw new Exception("PowerAuthSDK.commit failed with error code " + resultCode);
        }
        // Now we can get an activation identifier
        String activationId = powerAuthSDK.getActivationIdentifier();
        assertNotNull(activationId);
        // Acquire activation detail and create and keep new Activation object.
        ActivationDetail activationDetail = testHelper.getServerApi().getActivationDetail(activationId, null);
        activation = activationDetail.copyToActivation();
        return activationDetail;
    }

    /**
     * Validate user password on server.
     *
     * @param password Password to validate.
     * @return {@code true} if password is equal to password that was used during PowerAuthSDK activation creation.
     * @throws Exception In case of other failure.
     */
    public boolean validateUserPassword(@NonNull final String password) throws Exception {
        return AsyncHelper.await(new AsyncHelper.Execution<Boolean>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Boolean> resultCatcher) throws Exception {
                powerAuthSDK.validatePasswordCorrect(testHelper.getContext(), password, new IValidatePasswordListener() {
                    @Override
                    public void onPasswordValid() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onPasswordValidationFailed(@NonNull Throwable t) {
                        if (t instanceof ErrorResponseApiException) {
                            final ErrorResponseApiException apiException = (ErrorResponseApiException)t;
                            if (apiException.getResponseCode() == 401) {
                                resultCatcher.completeWithResult(false);
                                return;
                            }
                        }
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
    }

    /**
     * Function removes activation on the server and locally. Unlike {@link #removeActivation(boolean)}, this
     * method catch all possible errors and allows tests to continue.
     */
    public void cleanupAfterTest() {
        try {
            removeActivation(true);
        } catch (Exception ex) {
            Logger.e("ActivationHelper failed to remove activation: " + ex.getMessage());
        }
    }

    /**
     * @return Application associated to this helper.
     */
    @NonNull
    public Application getApplication() {
        return application;
    }

    /**
     * Return last created activation.
     * @return Last created activation.
     * @throws Exception In case that there's no activation created yet.
     */
    @NonNull Activation getActivation() throws Exception {
        if (activation == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return activation;
    }

    /**
     * @return User identifier.
     */
    @NonNull
    public String getUserId() {
        return userId;
    }

    /**
     * @return PowerAuthSDK instance that manages activation.
     */
    @NonNull
    public PowerAuthSDK getPowerAuthSDK() {
        return powerAuthSDK;
    }

    /**
     * Get authentication object with a valid password that was used to create a PowerAuthSDK activation.
     * @return Authentication object with valid credentials.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull PowerAuthAuthentication getValidAuthentication() throws Exception {
        if (validAuthentication == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return validAuthentication;
    }

    /**
     * @return Return new instance of {@link PowerAuthAuthentication} object with possession factor set.
     */
    public @NonNull PowerAuthAuthentication getPossessionAuthentication() {
        return PowerAuthAuthentication.possession();
    }

    /**
     * Get authentication object with invalid password.
     * @return Authentication object with invalid credentials.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull PowerAuthAuthentication getInvalidAuthentication() throws Exception {
        if (invalidAuthentication == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return invalidAuthentication;
    }

    /**
     * Get valid password that was used to create a PowerAuthSDK activation.
     * @return Valid password.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull String getValidPassword() throws Exception {
        if (validAuthentication == null || validAuthentication.getPassword() == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return validAuthentication.getPassword();
    }

    /**
     * Get invalid password (e.g. password different than was used to create a PowerAuthSDK activation).
     * @return Invalid password.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull String getInvalidPassword() throws Exception {
        if (invalidAuthentication == null || invalidAuthentication.getPassword() == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return invalidAuthentication.getPassword();
    }

    /**
     * Get activation result from last crated activation.
     * @return Activation result.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull CreateActivationResult getCreateActivationResult() throws Exception {
        if (createActivationResult == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        return createActivationResult;
    }
}
