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
import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.biometry.IPersistActivationWithBiometricsListener;
import io.getlime.security.powerauth.core.CoreProtocolVersion;
import io.getlime.security.powerauth.core.CoreSession;
import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.Logger;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.ActivationOtpValidation;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ProtocolVersion;
import io.getlime.security.powerauth.integration.support.model.ServerConstants;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.response.*;
import io.getlime.security.powerauth.sdk.*;

import static org.junit.Assert.*;

/**
 * The {@code ActivationHelper} class provides support for activation creation and cleanup.
 */
public class ActivationHelper {

    private final @NonNull PowerAuthTestHelper testHelper;
    private final @NonNull Application application;
    private final @NonNull String userId;
    private @NonNull PowerAuthSDK powerAuthSDK;
    private Activation activation;
    private PowerAuthAuthentication validAuthentication;
    private PowerAuthAuthentication invalidAuthentication;
    private SecureData fakeBiometricKek;
    private CreateActivationResult createActivationResult;

    /**
     * Create activation with activation code and signature. If not used, then just unsigned
     * activation code will be used.
     */
    public static final int TF_CREATE_WITH_SIGNATURE            = 0x0001;
    /**
     * Persist method with String password will be used.
     */
    public static final int TF_PERSIST_WITH_PASSWORD            = 0x0002;
    /**
     * Persist method with core/Password will be used.
     */
    public static final int TF_PERSIST_WITH_CORE_PASSWORD       = 0x0004;
    /**
     * Persist method with additional biometry factor. Combine with other flags.
     * In this case, Fragment is used for biometric prompt.
     */
    public static final int TF_PERSIST_WITH_BIOMETRY_FRAGMENT   = 0x0008;
    /**
     * Persist method with additional biometry factor. Combine with other flags.
     * In this case, FragmentActivity is used for biometric prompt.
     */
    public static final int TF_PERSIST_WITH_BIOMETRY_ACTIVITY   = 0x0010;
    /**
     * Persist method with additional biometry factor represented by a generated biometry related key.
     * No actual biometric authentication is needed. Combine with other flags.
     */
    public static final int TF_PERSIST_WITH_FAKE_BIOMETRY = 0x0020;
    /**
     * Alternate method that persist activation with deprecated functions.
     */
    // @Deprecated // 2.0.0
    public static final int TF_PERSIST_WITH_DEPRECATED          = 0x0100;

    /**
     * Helper's state.
     */
    public static class HelperState {
        Activation activation;
        PowerAuthAuthentication validAuthentication;
        PowerAuthAuthentication invalidAuthentication;
        CreateActivationResult createActivationResult;
        SecureData fakeBiometricKek;
        HelperState(Activation activation,
                    PowerAuthAuthentication validAuthentication,
                    PowerAuthAuthentication invalidAuthentication,
                    SecureData fakeBiometricKek,
                    CreateActivationResult createActivationResult) {
            this.activation = activation;
            this.validAuthentication = validAuthentication;
            this.invalidAuthentication = invalidAuthentication;
            this.fakeBiometricKek = fakeBiometricKek.copy();
            this.createActivationResult = createActivationResult;
        }
    }

    /**
     * Get helper's state that can be used to create another instance of ActivationHelper.
     * @return Helper's state.
     */
    public @NonNull HelperState getHelperState() {
        return new HelperState(activation, validAuthentication, invalidAuthentication, fakeBiometricKek, createActivationResult);
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
        this.fakeBiometricKek = state.fakeBiometricKek;
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
        updateServerApiProtocolAfterAlgorithmChange();
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
     * @throws Exception In case of failure.
     */
    public void removeActivation() throws Exception {
        if (activation != null) {
            testHelper.getServerApi().activationRemove(activation.getActivationId(), ServerConstants.DEFAULT_EXTERNAL_USER_ID);
            activation = null;
            validAuthentication = null;
            invalidAuthentication = null;
            createActivationResult = null;
        }
        removeActivationLocal();
    }

    /**
     * Remove activation locally.
     */
    public void removeActivationLocal() {
        if (powerAuthSDK.hasValidActivation()) {
            powerAuthSDK.removeActivationLocal(testHelper.getContext());
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
     * @return {@link PowerAuthActivationStatus} object.
     * @throws Exception In case of failure.
     */
    public @NonNull PowerAuthActivationStatus fetchActivationStatus() throws Exception {
        return AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    resultCatcher.completeWithResult(status);
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
    }

    /**
     * Prepare valid and invalid authentication objects.
     * @return List of passwords used for authentication objects creation. First is valid, second is invalid password.
     * @throws Exception In case that generator failed to generate strings.
     */
    public @NonNull List<String> prepareAuthentications() throws Exception {
        List<String> passwords = testHelper.getRandomGenerator().generateRandomStrings(2, 4, 16);
        validAuthentication = PowerAuthAuthentication.possessionWithPassword(passwords.get(0));
        invalidAuthentication = PowerAuthAuthentication.possessionWithPassword(passwords.get(1));
        fakeBiometricKek = null;
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
        return createStandardActivation(codeWithSignature ? TF_CREATE_WITH_SIGNATURE : 0, extras);
    }

    /**
     * Create a standard activation on the server and locally. The result is prepared PowerAuthSDK
     * instance for other tests.
     *
     * @param flags Use {@code TF_} constants from this class to specify flags.
     * @param extras Extra attributes associated with the activation.
     * @return Information about activation.
     * @throws Exception In case of failure.
     */
    public @NonNull ActivationDetail createStandardActivation(int flags, @Nullable String extras) throws Exception {

        final boolean codeWithSignature = (flags & TF_CREATE_WITH_SIGNATURE) != 0;
        final boolean persistWithPassword = (flags & TF_PERSIST_WITH_PASSWORD) != 0;
        final boolean persistWithCorePassword = (flags & TF_PERSIST_WITH_CORE_PASSWORD) != 0;
        final boolean persistWithDeprecated = (flags & TF_PERSIST_WITH_DEPRECATED) != 0;
        final boolean persistWithBiometryFrag = (flags & TF_PERSIST_WITH_BIOMETRY_FRAGMENT) != 0;
        final boolean persistWithBiometryAct = (flags & TF_PERSIST_WITH_BIOMETRY_ACTIVITY) != 0;
        final boolean persistWithFakeBiometry = (flags & TF_PERSIST_WITH_FAKE_BIOMETRY) != 0;

        // Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
        assertNull(powerAuthSDK.getActivationIdentifier());
        assertNull(powerAuthSDK.getActivationFingerprint());

        final List<String> passwords = prepareAuthentications();

        // Initialize activation on the server
        initActivation();

        // Update client protocol version in server API
        testHelper.getServerApi().setClientAlgorithm(powerAuthSDK.getCurrentAlgorithm());

        // Create activation locally
        final String activationCode;
        if (codeWithSignature) {
            activationCode = activation.getActivationCode() + "#" + activation.getActivationSignatureLegacy();
        } else {
            activationCode = activation.getActivationCode();
        }
        final PowerAuthActivation paActivation = PowerAuthActivation.Builder.activation(activationCode, testHelper.getDeviceInfo())
                .setExtras(extras)
                .build();
        createActivationResult = AsyncHelper.await(resultCatcher -> {
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
            assertNull(powerAuthSDK.getActivationIdentifier());
            assertNull(powerAuthSDK.getActivationFingerprint());
        });

        assertFalse(powerAuthSDK.hasValidActivation());
        assertTrue(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());
        assertNotNull(powerAuthSDK.getActivationIdentifier());
        assertNotNull(powerAuthSDK.getActivationFingerprint());

        // Persist activation locally
        boolean persistResult = AsyncHelper.await(resultCatcher -> {
            final String password = passwords.get(0);
            final Password corePassword = new Password(password);
            final IPersistActivationListener persistActivationListener = new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable error) {
                    resultCatcher.completeWithError(error);
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    resultCatcher.completeWithResult(false);
                }
            };
            if (!persistWithDeprecated) {
                // New asynchronous persist (2.0.0)
                // If biometry (in any form) is required, then we have to use auth object.
                boolean useAuthObject = persistWithBiometryAct || persistWithBiometryFrag || persistWithFakeBiometry;
                if (!useAuthObject) {
                    if (persistWithPassword) {
                        powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), password, persistActivationListener);
                    } else if (persistWithCorePassword) {
                        powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), corePassword, persistActivationListener);
                    } else {
                        // No explicit request for password or core password means that persist with auth object is requested.
                        useAuthObject = true;
                    }
                }
                if (useAuthObject) {
                    final PowerAuthBiometricPrompt biometricPrompt;
                    final SecureData biometricKey;
                    if (persistWithFakeBiometry) {
                        int protocolVersion = powerAuthSDK.getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256 ? CoreProtocolVersion.V3 : CoreProtocolVersion.V4;
                        biometricPrompt = null;
                        biometricKey = CoreSession.generateFactorKekForProtocolVersion(protocolVersion);
                        this.fakeBiometricKek = biometricKey.copy();
                    } else {
                        if (persistWithBiometryFrag) {
                            biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragment());
                        } else if (persistWithBiometryAct) {
                            biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());
                        } else {
                            biometricPrompt = null;
                        }
                        biometricKey = null;
                    }
                    final PowerAuthAuthentication authentication = buildPersistAuthObject(password, persistWithCorePassword, biometricPrompt, biometricKey);
                    powerAuthSDK.persistActivationWithAuthentication(testHelper.getContext(), authentication, persistActivationListener);
                }
            } else {
                // @Deprecated // 2.0.0 - Remove in 2.1.0
                if (persistWithBiometryAct || persistWithBiometryFrag) {
                    //noinspection deprecation
                    IPersistActivationWithBiometricsListener deprecatedListener = new IPersistActivationWithBiometricsListener() {
                        @Override
                        public void onBiometricDialogCancelled() {
                            resultCatcher.completeWithResult(false);
                        }

                        @Override
                        public void onBiometricDialogSuccess() {
                            resultCatcher.completeWithResult(true);
                        }

                        @Override
                        public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                            resultCatcher.completeWithError(error);
                        }
                    };
                    if (persistWithBiometryAct) {
                        if (persistWithCorePassword) {
                            //noinspection deprecation
                            powerAuthSDK.persistActivation(testHelper.getContext(), testHelper.getFragmentActivity(), "test", "test", corePassword, deprecatedListener);
                        } else {
                            //noinspection deprecation
                            powerAuthSDK.persistActivation(testHelper.getContext(), testHelper.getFragmentActivity(), "test", "test", password, deprecatedListener);
                        }
                    } else {
                        if (persistWithCorePassword) {
                            //noinspection deprecation
                            powerAuthSDK.persistActivation(testHelper.getContext(), testHelper.getFragment(), "test", "test", corePassword, deprecatedListener);
                        } else {
                            //noinspection deprecation
                            powerAuthSDK.persistActivation(testHelper.getContext(), testHelper.getFragment(), "test", "test", password, deprecatedListener);
                        }
                    }
                } else {
                    if (persistWithPassword) {
                        //noinspection deprecation
                        assertEquals(PowerAuthErrorCodes.SUCCEED, powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), password));
                    } else if (persistWithCorePassword) {
                        //noinspection deprecation
                        assertEquals(PowerAuthErrorCodes.SUCCEED, powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), corePassword));
                    } else {
                        //noinspection deprecation
                        assertEquals(PowerAuthErrorCodes.SUCCEED, powerAuthSDK.persistActivationWithAuthentication(testHelper.getContext(), PowerAuthAuthentication.persistWithPassword(password)));
                    }
                    resultCatcher.completeWithResult(true);
                }
            }
        });
        assertTrue(persistResult);

        assertTrue(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());
        assertNotNull(powerAuthSDK.getActivationIdentifier());
        assertNotNull(powerAuthSDK.getActivationFingerprint());

        // Fetch status to test whether it's in "pending commit" or "active" state, depending on server's configuration.
        final boolean isAutoCommit = testHelper.getTestConfig().isServerAutoCommit();
        PowerAuthActivationStatus activationStatus = fetchActivationStatus();
        final @PowerAuthActivationState int expectedState = isAutoCommit ? PowerAuthActivationState.ACTIVE : PowerAuthActivationState.PENDING_COMMIT;
        if (activationStatus.getState() != expectedState) {
            throw new Exception("Activation is in invalid state after creation. State = " + activationStatus.getState() + ", Expected = " + expectedState);
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
            if (activationStatus.getState() != PowerAuthActivationState.ACTIVE) {
                throw new Exception("Activation is in invalid state after commit. State = " + activationStatus.getState());
            }
        }

        return activationDetail;
    }

    private static PowerAuthAuthentication buildPersistAuthObject(String password, boolean useCorePassword, PowerAuthBiometricPrompt prompt, SecureData biometricKey) {
        if (useCorePassword) {
            Password corePassword = new Password(password);
            if (prompt != null) {
                return PowerAuthAuthentication.persistWithPasswordAndBiometry(corePassword, prompt);
            }
            if (biometricKey != null) {
                return PowerAuthAuthentication.persistWithPasswordAndBiometry(corePassword, biometricKey);
            }
            return PowerAuthAuthentication.persistWithPassword(corePassword);
        } else {
            if (prompt != null) {
                return PowerAuthAuthentication.persistWithPasswordAndBiometry(password, prompt);
            }
            if (biometricKey != null) {
                return PowerAuthAuthentication.persistWithPasswordAndBiometry(password, biometricKey);
            }
            return PowerAuthAuthentication.persistWithPassword(password);
        }
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
        boolean persistResult = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), passwords.get(0), new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable error) {
                    resultCatcher.completeWithError(error);
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(persistResult);
        // Now we can get an activation identifier
        String activationId = powerAuthSDK.getActivationIdentifier();
        assertNotNull(activationId);
        // Acquire activation detail and create and keep new Activation object.
        ActivationDetail activationDetail = testHelper.getServerApi().getActivationDetail(activationId, null);
        activation = activationDetail.copyToActivation();
        return activationDetail;
    }

    /**
     * Re-create instance of {@link PowerAuthSDK} with the same configuration to simulate application's restart.
     * @return New instance of {@link PowerAuthSDK}.
     * @throws Exception In case of failure.
     */
    @NonNull
    PowerAuthSDK reCreateSdk() throws Exception {
        powerAuthSDK = testHelper.reCreateSdk(null, null, null, null);
        return powerAuthSDK;
    }

    /**
     * Validate user password on server.
     * This implementation is for integration testing only. Do NOT use `beginPasswordChange`
     * as a general password-validation mechanism.
     *
     * @param password Password to validate.
     * @return {@code true} if password is equal to password that was used during PowerAuthSDK activation creation.
     * @throws Exception In case of other failure.
     */
    public boolean validateUserPassword(@NonNull final Password password) throws Exception {
        return AsyncHelper.await(resultCatcher ->
                powerAuthSDK.beginPasswordChange(testHelper.getContext(), password, new IBeginPasswordChangeListener() {
                    @Override
                    public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onBeginPasswordChangeFailed(@NonNull Throwable t) {
                        if (t instanceof ErrorResponseApiException) {
                            final ErrorResponseApiException apiException = (ErrorResponseApiException) t;
                            if (apiException.getResponseCode() == 401) {
                                resultCatcher.completeWithResult(false);
                                return;
                            }
                        }
                        resultCatcher.completeWithError(t);
                    }
                })
        );
    }

    /**
     * Updates client protocol version in {@link io.getlime.security.powerauth.integration.support.PowerAuthServerApi}
     * after algorithm change in {@link PowerAuthSDK} instance.
     */
    public void updateServerApiProtocolAfterAlgorithmChange() {
        testHelper.getServerApi().setClientAlgorithm(powerAuthSDK.getCurrentAlgorithm());
    }

    /**
     * Validate user password on server.
     * This implementation is for integration testing only. Do NOT use `beginPasswordChange`
     * as a general password-validation mechanism.
     *
     * @param password Password to validate.
     * @return {@code true} if password is equal to password that was used during PowerAuthSDK activation creation.
     * @throws Exception In case of other failure.
     */
    public boolean validateUserPassword(@NonNull final String password) throws Exception {
        return AsyncHelper.await(resultCatcher -> powerAuthSDK.beginPasswordChange(testHelper.getContext(), password, new IBeginPasswordChangeListener() {
            @Override
            public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                resultCatcher.completeWithResult(true);
            }

            @Override
            public void onBeginPasswordChangeFailed(@NonNull Throwable t) {
                if (t instanceof ErrorResponseApiException) {
                    final ErrorResponseApiException apiException = (ErrorResponseApiException)t;
                    if (apiException.getResponseCode() == 401) {
                        resultCatcher.completeWithResult(false);
                        return;
                    }
                }
                resultCatcher.completeWithError(t);
            }
        }));
    }

    /**
     * Function removes activation on the server and locally. Unlike {@link #removeActivation()}, this
     * method catch all possible errors and allows tests to continue.
     */
    public void cleanupAfterTest() {
        try {
            removeActivation();
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
     * Get authentication object with biometric factor.
     * @param prompt If provided, then returned object uses prompt for authentication. If null, then
     *               activation has to be persisted with a fake biometric key.
     * @return Authentication object configured for authentication with biometric factor.
     * @throws Exception When called in wrong state or if prompt is required and is missing.
     */
    public @NonNull PowerAuthAuthentication getBiometricAuthentication(@Nullable PowerAuthBiometricPrompt prompt) throws Exception {
        if (validAuthentication == null) {
            throw new Exception("ActivationHelper has no activation yet.");
        }
        if (prompt != null) {
            return PowerAuthAuthentication.possessionWithBiometry(prompt);
        }
        if (fakeBiometricKek == null) {
            throw new Exception("Biometric prompt must be provided, because no fake biometry key is set");
        }
        return PowerAuthAuthentication.possessionWithBiometry(fakeBiometricKek.copy());
    }

    /**
     * Get valid password that was used to create a PowerAuthSDK activation.
     * @return Valid password.
     * @throws Exception In case that such object is not created yet.
     */
    public @NonNull Password getValidPassword() throws Exception {
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
    public @NonNull Password getInvalidPassword() throws Exception {
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

    /**
     * Extract plaintext password from Password object.
     * @param password Password object.
     * @return Extracted password or null if no password object was provided.
     */
    @NonNull
    public static String extractPlaintextPassword(@NonNull Password password) {
        return PowerAuthAuthenticationHelper.extractPlaintextPassword(password);
    }

    /**
     * Create a new token or get a local token with the specified token name
     * and validate it against server.
     *
     * @param tokenName Name of the token to validate.
     * @param createToken If {@code true}, new token is requested. If {@code false}, local token is used.
     * @throws Exception In case of an error.
     */
    public void createTokenAndValidateTokenHeader(final String tokenName, final boolean createToken) throws Exception {
        if (createToken) {
            final PowerAuthToken token = AsyncHelper.await(resultCatcher ->
                    powerAuthSDK.getTokenStore().requestAccessToken(testHelper.getContext(), tokenName, getPossessionAuthentication(), new IGetTokenListener() {
                        @Override
                        public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                            resultCatcher.completeWithResult(token);
                        }

                        @Override
                        public void onGetTokenFailed(@NonNull Throwable t) {
                            resultCatcher.completeWithError(t);
                        }
                    })
            );
            assertNotNull(token);
        } else {
            final boolean exists = powerAuthSDK.getTokenStore().hasLocalToken(testHelper.getContext(), tokenName);
            assertTrue(exists);
        }

        final PowerAuthHttpHeader header = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.getTokenStore().generateAuthenticationHeader(testHelper.getContext(), tokenName, new IGenerateTokenHeaderListener() {
                    @Override
                    public void onGenerateTokenHeaderSucceeded(@NonNull PowerAuthHttpHeader header) {
                        resultCatcher.completeWithResult(header);
                    }

                    @Override
                    public void onGenerateTokenHeaderFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                })
        );

        assertNotNull(header);
        assertTrue(validateTokenHeader(header));
    }

    /**
     * Validates a PowerAuth token-based authentication HTTP header against the test server.
     *
     * @param header Token authentication HTTP header to validate.
     * @return {@code true} if the server reports the token as valid; {@code false} otherwise.
     * @throws Exception In case of an error.
     */
    boolean validateTokenHeader(final PowerAuthHttpHeader header) throws Exception {
        final Map<String, String> parsedHeader = AuthenticationHelper.parseAuthenticationHeader(header);
        final TokenInfo tokenInfo = testHelper.getServerApi().validateToken(
                Objects.requireNonNull(parsedHeader.get("token_id")),
                Objects.requireNonNull(parsedHeader.get("token_digest")),
                Objects.requireNonNull(parsedHeader.get("nonce")),
                Long.parseLong(Objects.requireNonNull(parsedHeader.get("timestamp"))),
                Objects.requireNonNull(parsedHeader.get("version"))
        );

        assertEquals(getActivation().getActivationId(), tokenInfo.getActivationId());
        assertEquals(getApplication().getApplicationId(), tokenInfo.getApplicationId());
        return tokenInfo.isTokenValid();
    }

    /**
     * Fetches secure vault keys using different authentication factors and optionally
     * verifies them against expected values.
     *
     * @param knowledge Expected {@link PowerAuthSecureVaultKeyId#KNOWLEDGE} vault key.
     * @param knowledgeOrBiometry Expected {@link PowerAuthSecureVaultKeyId#KNOWLEDGE_OR_BIOMETRY} vault key.
     * @return List containing the fetched keys in order {@link PowerAuthSecureVaultKeyId#KNOWLEDGE}, {@link PowerAuthSecureVaultKeyId#KNOWLEDGE_OR_BIOMETRY}.
     * @throws Exception In case of an error.
     */
    List<PowerAuthSecureVaultKey> fetchSecureVaultKeys(@Nullable final PowerAuthSecureVaultKey knowledge, @Nullable final PowerAuthSecureVaultKey knowledgeOrBiometry) throws Exception {
        final PowerAuthSecureVaultKey key1 = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchSecureVaultKey(testHelper.getContext(), getValidAuthentication(), PowerAuthSecureVaultKeyId.KNOWLEDGE, new IFetchSecureVaultKeyListener() {
                    @Override
                    public void onFetchSecureVaultKeySucceed(@NonNull PowerAuthSecureVaultKey vaultKey) {
                        resultCatcher.completeWithResult(vaultKey);
                    }

                    @Override
                    public void onFetchSecureVaultKeyFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithError(throwable);
                    }
                }));
        assertNotNull(key1);
        if (knowledge != null) {
            assertEquals(knowledge, key1);
        }

        final PowerAuthSecureVaultKey key2 = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.fetchSecureVaultKey(testHelper.getContext(), getValidAuthentication(), PowerAuthSecureVaultKeyId.KNOWLEDGE_OR_BIOMETRY, new IFetchSecureVaultKeyListener() {
                    @Override
                    public void onFetchSecureVaultKeySucceed(@NonNull PowerAuthSecureVaultKey vaultKey) {
                        resultCatcher.completeWithResult(vaultKey);
                    }

                    @Override
                    public void onFetchSecureVaultKeyFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithError(throwable);
                    }
                }));

        assertNotNull(key2);
        if (knowledgeOrBiometry != null) {
            assertEquals(knowledgeOrBiometry, key2);
        }

        return List.of(key1, key2);
    }

    /**
     * Prepare an activation that uses {@link PowerAuthAlgorithm#LEGACY_P256} protocol
     * and is configured to support a future upgrade to the specified target algorithm.
     *
     * @param targetAlgorithm The algorithm to which this activation should be upgradable.
     * @param flags Flags that are forwarded to the {@link ActivationHelper#createStandardActivation(int, String)}.
     * @param authenticateOnBiometricKeySetup Flag that modifies requirement of authentication on biometry key setup for this SDK instance.
     * @return A new {@link PowerAuthSDK} instance that can be upgraded.
     * @throws Exception In case of a failure.
     */
    public PowerAuthSDK prepareActivationForUpgradeTest(final @PowerAuthAlgorithm int targetAlgorithm, final int flags, final boolean authenticateOnBiometricKeySetup) throws Exception {
        // Protocol upgrade not available before calling a fetch activation status.
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        final ActivationDetail activationDetail = createStandardActivation(flags, null);

        final PowerAuthBiometricConfiguration currentBiometricConfiguration = powerAuthSDK.getBiometricConfiguration();
        final PowerAuthBiometricConfiguration targetBiometricConfiguration = new PowerAuthBiometricConfiguration.Builder()
                .authenticateOnBiometricKeySetup(authenticateOnBiometricKeySetup)
                .confirmBiometricAuthentication(currentBiometricConfiguration.isConfirmBiometricAuthentication())
                .enableFallbackToSharedBiometryKey(currentBiometricConfiguration.isFallbackToSharedBiometryKeyEnabled())
                .invalidateBiometricFactorAfterChange(currentBiometricConfiguration.isInvalidateBiometricFactorAfterChange())
                .build();

        return prepareActivationForUpgradeTest(targetAlgorithm, activationDetail, targetBiometricConfiguration);
    }

    /**
     * Prepare an activation that uses {@link PowerAuthAlgorithm#LEGACY_P256} protocol
     * and is configured to support a future upgrade to the specified target algorithm.
     *
     * @param targetAlgorithm The algorithm to which this activation should be upgradable.
     * @param flags Flags that are forwarded to the {@link ActivationHelper#createStandardActivation(int, String)}.
     * @return A new {@link PowerAuthSDK} instance that can be upgraded.
     * @throws Exception In case of a failure.
     */
    public PowerAuthSDK prepareActivationForUpgradeTest(final @PowerAuthAlgorithm int targetAlgorithm, final int flags) throws Exception {
        // Protocol upgrade not available before calling a fetch activation status.
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        final ActivationDetail activationDetail = createStandardActivation(flags, null);
        return prepareActivationForUpgradeTest(targetAlgorithm, activationDetail, null);
    }

    /**
     * Prepare an activation that uses {@link PowerAuthAlgorithm#LEGACY_P256} protocol
     * and is configured to support a future upgrade to the specified target algorithm.
     *
     * @param targetAlgorithm The algorithm to which this activation should be upgradable.
     * @param activationDetail Result of the activation creation.
     * @param biometricConfiguration Biometric configuration to be used for the SDK instance.
     * @return A new {@link PowerAuthSDK} instance that can be upgraded.
     * @throws Exception In case of a failure.
     */
    private PowerAuthSDK prepareActivationForUpgradeTest(final @PowerAuthAlgorithm int targetAlgorithm, final ActivationDetail activationDetail, final PowerAuthBiometricConfiguration biometricConfiguration) throws Exception {
        // Protocol upgrade not available before calling a fetch activation status.
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // Extract session data
        final byte[] sessionData = powerAuthSDK.getCoreSession().getSerializedState();

        // Reconfigure SDK to support target algorithm
        final PowerAuthConfiguration currentConfiguration = powerAuthSDK.getConfiguration();
        final PowerAuthConfiguration targetConfiguration = new PowerAuthConfiguration.Builder(currentConfiguration.getInstanceId(), currentConfiguration.getBaseEndpointUrl(), currentConfiguration.getConfiguration())
                .algorithm(targetAlgorithm)
                .build();
        powerAuthSDK = testHelper.reCreateSdk(targetConfiguration, biometricConfiguration, null, null);

        // Load the old V3 session
        powerAuthSDK.getCoreSession().deserializeState(sessionData);
        assertTrue(powerAuthSDK.hasValidActivation());
        assertEquals(activationDetail.getActivationId(), powerAuthSDK.getActivationIdentifier());
        assertTrue(validateUserPassword(getValidPassword()));

        // Activation now uses legacy protocol, but is configured to support tested algorithm
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertEquals(targetAlgorithm, powerAuthSDK.getConfiguration().getAlgorithm());

        final PowerAuthActivationStatus status = fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(status.isProtocolUpgradeAvailable());
        assertEquals(targetAlgorithm > PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.hasProtocolUpgradeAvailable());

        return powerAuthSDK;
    }

    /**
     * Start the protocol upgrade and expect a failure.
     *
     * @param targetAlgorithm Target algorithm for the protocol upgrade.
     * @param authentication Authentication object with biometry key or prompt.
     * @return {@link Throwable} representing an expected error during protocol upgrade.
     * @throws Exception In case of unexpected error.
     */
    Throwable startProtocolUpgradeExpectFailure(final @PowerAuthAlgorithm int targetAlgorithm, final PowerAuthAuthentication authentication) throws Exception {
        return AsyncHelper.await(resultCatcher ->
                powerAuthSDK.startProtocolUpgrade(testHelper.getContext(), getValidPassword(), authentication, new IProtocolUpgradeListener() {
                    @Override
                    public void onProtocolUpgradeSucceed(@NonNull ProtocolUpgradeResult result) {
                        resultCatcher.completeWithResult(null);
                    }

                    @Override
                    public void onProtocolUpgradeFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithResult(throwable);
                    }
                })
        );
    }

    /**
     * Start the protocol upgrade and expect a failure.
     *
     * @param targetAlgorithm Target algorithm for the protocol upgrade.
     * @return {@link Throwable} representing an expected error during protocol upgrade.
     * @throws Exception In case of unexpected error.
     */
    Throwable startProtocolUpgradeExpectFailure(final @PowerAuthAlgorithm int targetAlgorithm) throws Exception {
        return startProtocolUpgradeExpectFailure(targetAlgorithm, null);
    }

    /**
     * Start protocol upgrade and expect valid {@link ProtocolUpgradeResult}.
     * If the {@code targetAlgorithm} is {@link PowerAuthAlgorithm#LEGACY_P256},
     * then the protocol upgrade request is not valid and {@code null} is returned.
     *
     * @param targetAlgorithm Target algorithm for the protocol upgrade.
     * @param authentication Authentication object with biometry key or prompt.
     * @return Valid protocol upgrade result for newer protocols and {@code null} for legacy protocol.
     * @throws Exception in case of upgrade process failure.
     */
    ProtocolUpgradeResult startProtocolUpgradeExpectResult(final @PowerAuthAlgorithm int targetAlgorithm, final PowerAuthAuthentication authentication) throws Exception {
        final ProtocolUpgradeResult result = AsyncHelper.await(resultCatcher ->
                powerAuthSDK.startProtocolUpgrade(testHelper.getContext(), getValidPassword(), authentication, new IProtocolUpgradeListener() {
                    @Override
                    public void onProtocolUpgradeSucceed(@NonNull ProtocolUpgradeResult result) {
                        resultCatcher.completeWithResult(result);
                    }

                    @Override
                    public void onProtocolUpgradeFailed(@NonNull Throwable throwable) {
                        if (targetAlgorithm == PowerAuthAlgorithm.LEGACY_P256) {
                            assertTrue(throwable instanceof PowerAuthErrorException);
                            assertEquals("powerAuth::PowerAuthException: Protocol upgrade is not possible with current configuration", throwable.getMessage());
                            resultCatcher.completeWithResult(null);
                        } else {
                            resultCatcher.completeWithError(throwable);
                        }
                    }
                })
        );

        if (targetAlgorithm > PowerAuthAlgorithm.LEGACY_P256) {
            testHelper.getServerApi().setClientProtocolVersion(ProtocolVersion.V4_0);
            if (!result.isActivationStatusFetchRequired()) {
                // Upgrade finished completely
                // Fetch status from the server, whether the activation version has been upgraded and activation fingerprint match.
                final ActivationDetail activationDetail = testHelper.getServerApi().getActivationDetail(getActivation());
                assertEquals(powerAuthSDK.getActivationFingerprint(), activationDetail.getDevicePublicKeyFingerprint());
                assertEquals(4, activationDetail.getProtocolVersion());
                assertTrue(validateUserPassword(getValidPassword()));
            } else if (result.isActivationStatusFetchRequired() && result.getActivationFingerprint() == null) {
                // Confirm not completed, so password validation should fail
                final Exception asyncException = assertThrows(Exception.class, () -> validateUserPassword(getValidPassword()));
                assertTrue(asyncException.getCause() instanceof PowerAuthErrorException);
                assertEquals("powerAuth::PowerAuthException: Authentication header calculation is not allowed during pending protocol upgrade", asyncException.getCause().getMessage());
                assertEquals(17, ((PowerAuthErrorException) asyncException.getCause()).getPowerAuthErrorCode());
            }
        }
        return result;
    }

    /**
     * Start protocol upgrade and expect valid {@link ProtocolUpgradeResult}.
     * If the {@code targetAlgorithm} is {@link PowerAuthAlgorithm#LEGACY_P256},
     * then the protocol upgrade request is not valid and {@code null} is returned.
     *
     * @param targetAlgorithm Target algorithm for the protocol upgrade.
     * @return Valid protocol upgrade result for newer protocols and {@code null} for legacy protocol.
     * @throws Exception in case of upgrade process failure.
     */
    ProtocolUpgradeResult startProtocolUpgradeExpectResult(final @PowerAuthAlgorithm int targetAlgorithm) throws Exception {
        return startProtocolUpgradeExpectResult(targetAlgorithm, null);
    }

}
