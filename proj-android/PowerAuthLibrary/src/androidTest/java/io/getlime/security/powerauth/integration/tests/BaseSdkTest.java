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

package io.getlime.security.powerauth.integration.tests;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.CoreEncryptor;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.keychain.KeychainFactory;
import io.getlime.security.powerauth.keychain.KeychainProtection;
import io.getlime.security.powerauth.sdk.PowerAuthActivationState;
import io.getlime.security.powerauth.sdk.PowerAuthActivationStatus;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.networking.response.*;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.PowerAuthActivation;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.system.PowerAuthSystem;

import static org.junit.Assert.*;

public class BaseSdkTest extends BaseTest {

    // Using PowerAuthActivation

    @Test
    public void testRestoreSdkState() throws Exception {
        activationHelper.createStandardActivation(false, null);
        assertTrue(powerAuthSDK.hasValidActivation());
        activationHelper.validateUserPassword(activationHelper.getValidPassword());
        byte[] stateBefore = powerAuthSDK.getCoreSession().getSerializedState();
        powerAuthSDK = activationHelper.reCreateSdk();
        assertTrue(powerAuthSDK.hasValidActivation());
        byte[] stateAfter = powerAuthSDK.getCoreSession().getSerializedState();
        assertArrayEquals(stateBefore, stateAfter);
    }

    @Test
    public void testCreateWithActivationCode() throws Exception {
        activationHelper.createStandardActivation(false, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateWithActivationCodeAndSignature() throws Exception {
        activationHelper.createStandardActivation(true, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateWithExtraAttributes() throws Exception {
        final String extras = "extra,attributes";
        final ActivationDetail activationDetail = activationHelper.createStandardActivation(true, extras);
        // Validate extras
        assertEquals(extras, activationDetail.getExtras());
        // Validate platform & device info
        assertEquals("android", activationDetail.getPlatform());
        assertEquals(PowerAuthSystem.getDeviceInfo(), activationDetail.getDeviceInfo());
    }

    @Test
    public void testCreateAndPersistWithPassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithPasswordDeprecated() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithCorePassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithCorePasswordDeprecated() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    // Using legacy method

    @Test
    public void testLegacyCreateWithActivationCode() throws Exception {
        legacyCreateActivation(false);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testLegacyCreateWithActivationCodeAndSignature() throws Exception {
        legacyCreateActivation(true);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    /**
     * Create activation with using legacy methods (e.g. without PowerAuthActivation object).
     * @param codeWithSignature true if activation should use code and signature.
     * @throws Exception In case of failure.
     */
    private void legacyCreateActivation(boolean codeWithSignature) throws Exception {
        // Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());

        final List<String> passwords = activationHelper.prepareAuthentications();

        // Initialize activation on the server
        final Activation activation = activationHelper.initActivation();

        // Create activation locally
        final String activationCode;
        if (codeWithSignature) {
            activationCode = activation.getActivationCode() + "#" + activation.getActivationSignatureLegacy();
        } else {
            activationCode = activation.getActivationCode();
        }
        final CreateActivationResult createActivationResult = AsyncHelper.await(new AsyncHelper.Execution<CreateActivationResult>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<CreateActivationResult> resultCatcher) throws Exception {
                powerAuthSDK.createActivation(testHelper.getDeviceInfo(), activationCode, new ICreateActivationListener() {
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

        // Persist activation locally
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

        assertTrue(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Fetch status to test whether it's in "pending commit" state.
        final boolean isAutoCommit = testHelper.getTestConfig().isServerAutoCommit();
        final @PowerAuthActivationState int expectedState = isAutoCommit ? PowerAuthActivationState.ACTIVE : PowerAuthActivationState.PENDING_COMMIT;
        PowerAuthActivationStatus activationStatus = activationHelper.fetchActivationStatus();
        if (activationStatus.getState() != expectedState) {
            throw new Exception("Activation is in invalid state after creation. State = " + activationStatus.getState() + ", Expected = " + expectedState);
        }

        // Compare public key fingerprints
        final ActivationDetail activationDetail = activationHelper.getActivationDetail();
        if (!activationDetail.getDevicePublicKeyFingerprint().equals(createActivationResult.getActivationFingerprint())) {
            throw new Exception("Public key fingerprints doesn't match between server and client.");
        }

        // Commit activation on the server.
        if (!isAutoCommit) {
            testHelper.getServerApi().activationCommit(activation);

            // Fetch status to validate whether activation is now active
            activationStatus = activationHelper.fetchActivationStatus();
            if (activationStatus.getState() != PowerAuthActivationState.ACTIVE) {
                throw new Exception("Activation is in invalid state after commit. State = " + activationStatus.getState());
            }
        }
    }

    // Recovery from failed confirm

    /**
     * Create activation and expect failure at persist step.
     * @param shouldPass true if process should succeed.
     * @throws Exception In case of failure.
     */
    public void createActivationAndExpectPersistFailure(boolean shouldPass) throws Exception {
        Activation activationData = activationHelper.initActivation();
        PowerAuthActivation activation = PowerAuthActivation.Builder.activation(activationData.getActivationCode()).build();
        CreateActivationResult createResult = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
                @Override
                public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                    resultCatcher.completeWithResult(result);
                }

                @Override
                public void onActivationCreateFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        PowerAuthAuthentication initialAuthentication = PowerAuthAuthentication.persistWithPassword(activationHelper.prepareAuthentications().get(0));
        final AsyncHelper.Execution<Boolean> persistActivation = resultCatcher -> {
            powerAuthSDK.persistActivationWithAuthentication(testHelper.getContext(), initialAuthentication, new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithResult(false);
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    resultCatcher.completeWithResult(false);
                }
            });
        };
        boolean success = AsyncHelper.await(persistActivation);
        assertEquals(shouldPass, success);
        if (!shouldPass) {
            // retry the operation
            clearAllSimulateFailures();
            success = AsyncHelper.await(persistActivation);
            assertTrue(success);
        }
        activationHelper.cleanupAfterTest();
        clearAllSimulateFailures();
    }

    @Test
    public void testPersistActivationFailRecovery() throws Exception {
        if (getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256) {
            System.out.println("Test not available for  LEGACY_P256");
            return;
        }
        final String confirmEndpoint = "/activation/confirm";
        final String statusEndpoint = "/activation/status";
        final String keystoreEndpoint = "/keystore/create";

        // one failure at confirm send, no failure at status
        simulateNetworkErrorOnSend(confirmEndpoint, 1);
        createActivationAndExpectPersistFailure(true);

        // one failure at confirm send, one failure at /keystore/create (prerequisite for status)
        simulateNetworkErrorOnSend(confirmEndpoint, 1);
        simulateNetworkErrorOnSend(keystoreEndpoint, 1);
        createActivationAndExpectPersistFailure(false);

        // 2 failures at confirm send, no failure at status. We should recovery from this.
        simulateNetworkErrorOnSend(confirmEndpoint, 2);
        createActivationAndExpectPersistFailure(true);

        // 3 failures at confirm send, no failure at status. Out of recovery attempts
        simulateNetworkErrorOnSend(confirmEndpoint, 3);
        createActivationAndExpectPersistFailure(false);

        // one failure at confirm, one failure at status. Cannot recovery here
        simulateNetworkErrorOnSend(confirmEndpoint, 1);
        simulateNetworkErrorOnSend(statusEndpoint, 1);
        createActivationAndExpectPersistFailure(false);

        // failure at confirm receive, so the server processed the confirmation
        simulateNetworkErrorOnReceive(confirmEndpoint);
        createActivationAndExpectPersistFailure(true);
    }

    // Remove activation

    @Test
    public void testRemoveActivationLocal() throws Exception {
        activationHelper.createStandardActivation(true, null);
        // Remove activation
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        // Back to Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    @Test
    public void testRemoveActivationWithAuthentication() throws Exception {

        activationHelper.createStandardActivation(true, null);

        boolean removed = AsyncHelper.await(resultCatcher -> {
            // Now remove activation
            powerAuthSDK.removeActivationWithAuthentication(testHelper.getContext(), activationHelper.getValidAuthentication(), new IActivationRemoveListener() {
                @Override
                public void onActivationRemoveSucceed() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onActivationRemoveFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertTrue(removed);

        // Back to initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    @Test
    public void testRemoveActivationWithBiometry() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY, null);
        boolean result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.removeActivationWithAuthentication(testHelper.getContext(), activationHelper.getBiometricAuthentication(null), new IActivationRemoveListener() {
                @Override
                public void onActivationRemoveSucceed() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onActivationRemoveFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(result);
    }

    // Activation status

    @Test
    public void testGetActivationStatus() throws Exception {
        activationHelper.createStandardActivation(true, null);
        PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        testHelper.getServerApi().activationBlock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.BLOCKED, status.getState());

        testHelper.getServerApi().activationUnblock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        testHelper.getServerApi().activationRemove(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.REMOVED, status.getState());

        assertNotNull(powerAuthSDK.getLastFetchedActivationStatus());
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        assertNull(powerAuthSDK.getLastFetchedActivationStatus());
    }

    @Test
    public void testGetActivationStatusConcurrent() throws Exception {
        activationHelper.createStandardActivation(true, null);

        final PowerAuthActivationStatus[] status1 = new PowerAuthActivationStatus[1];
        final PowerAuthActivationStatus[] status2 = new PowerAuthActivationStatus[1];
        final PowerAuthActivationStatus[] status3 = new PowerAuthActivationStatus[1];
        final AtomicInteger counter = new AtomicInteger(0);

        AsyncHelper.await((AsyncHelper.Execution<Boolean>) resultCatcher -> {
            final ICancelable task1, task2, task3, task4;
            task1 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status1[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task1);
            task4 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    fail();
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task4);
            task2 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status2[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task2);
            task3 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status3[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task3);
            task4.cancel();
        });
        assertSame(status1[0], status2[0]);
        assertSame(status1[0], status3[0]);
        assertSame(status2[0], status3[0]);
    }

    @Test
    public void testCallToCreateActivationInWrongState() throws Exception {
        activationHelper.createStandardActivation(true, null);

        AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), "1234", new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    fail("Operation should not succeed");
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable error) {
                    if (error instanceof PowerAuthErrorException) {
                        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, ((PowerAuthErrorException)error).getPowerAuthErrorCode());
                    }
                    resultCatcher.completeWithSuccess();
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    fail("Operation should not be canceled");
                }
            });
        });
        assertTrue(powerAuthSDK.hasValidActivation());

        AsyncHelper.await((AsyncHelper.Execution<Boolean>) resultCatcher -> {
            final PowerAuthActivation activation = PowerAuthActivation.Builder.activation("MMMMM-MMMMM-MMMMM-MUTOA", null).build();
            powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
                @Override
                public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                    fail("Create activation should not pass");
                }

                @Override
                public void onActivationCreateFailed(@NonNull Throwable t) {
                    if (t instanceof PowerAuthErrorException) {
                        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, ((PowerAuthErrorException) t).getPowerAuthErrorCode());
                        resultCatcher.completeWithSuccess();
                    } else {
                        fail("Unexpected error received");
                    }
                }
            });
        });
        assertTrue(powerAuthSDK.hasValidActivation());
    }

    // User Info

    @Test
    public void testUserInfo() throws Exception {

        // Test the `lastFetchedUserInfo` is null before the data are fetched.
        assertNull(powerAuthSDK.getLastFetchedUserInfo());

        activationHelper.createStandardActivation(true, null);

        // Test that the User Info from the Activation response is stored as last fetched.
        final UserInfo infoFromActivation = activationHelper.getCreateActivationResult().getUserInfo();
        final String userId = activationHelper.getUserId();
        assertNotNull(infoFromActivation);
        assertNotNull(powerAuthSDK.getLastFetchedUserInfo());
        assertEquals(userId, powerAuthSDK.getLastFetchedUserInfo().getSubject());
        assertEquals(userId, infoFromActivation.getSubject());
        assertEquals(infoFromActivation.getAllClaims().get("jti"), powerAuthSDK.getLastFetchedUserInfo().getAllClaims().get("jti"));

        // Now fetch user info from the server
        UserInfo info = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.fetchUserInfo(testHelper.getContext(), new IUserInfoListener() {
                @Override
                public void onUserInfoSucceed(@NonNull UserInfo userInfo) {
                    resultCatcher.completeWithResult(userInfo);
                }

                @Override
                public void onUserInfoFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
            assertNotNull(task);
        });
        assertNotNull(info);
        assertEquals(userId, info.getSubject());

        // Check the last fetched User Info was updated (i.e. JWT ID was changed).
        assertNotEquals(info.getAllClaims().get("jti"), infoFromActivation.getAllClaims().get("jti"));
        assertEquals(info.getAllClaims().get("jti"), powerAuthSDK.getLastFetchedUserInfo().getAllClaims().get("jti"));
    }

    @Test
    public void testGetCoreEncryptors() throws Exception {
        CoreEncryptor appEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForApplicationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(appEncryptor);
        assertTrue(appEncryptor.canEncryptRequest());

        boolean success = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForActivationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    assertTrue(encryptor.canEncryptRequest());
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertFalse(success);

        // Now create activation
        activationHelper.createStandardActivation(false, null);

        appEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForApplicationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(appEncryptor);
        assertTrue(appEncryptor.canEncryptRequest());

        CoreEncryptor actEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForActivationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(actEncryptor);
        assertTrue(actEncryptor.canEncryptRequest());
    }

    // TODO: This test is temporarily disabled, the used API doesn't work for protocol V4
    // @Test
    public void testTemporaryKeyExpiration() throws Exception {
        // This test requires PAS configured for a very short temporary key lifespan.
        activationHelper.createStandardActivation(true, null);

        Boolean result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchEncryptionKey(testHelper.getContext(), activationHelper.getValidAuthentication(), 1000, new IFetchEncryptionKeyListener() {
                @Override
                public void onFetchEncryptionKeySucceed(@NonNull SecureData encryptionKey) {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onFetchEncryptionKeyFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(result);

        Thread.sleep(15_000);
        result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchEncryptionKey(testHelper.getContext(), activationHelper.getValidAuthentication(), 1000, new IFetchEncryptionKeyListener() {
                @Override
                public void onFetchEncryptionKeySucceed(@NonNull SecureData encryptionKey) {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onFetchEncryptionKeyFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(result);
    }

    @Test
    public void testServerStatus() throws Exception {
        ServerStatus result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchServerStatus(new IServerStatusListener() {
                @Override
                public void onServerStatusSucceeded(@NonNull ServerStatus status) {
                    resultCatcher.completeWithResult(status);
                }

                @Override
                public void onServerStatusFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(result);
        System.out.println("Server name: " + result.getApplicationName() + ", version: " + result.getApplicationVersion());
    }

    @Test
    public void cleanupActivationData() throws Exception {
        activationHelper.createStandardActivation(false, null);
        assertTrue(powerAuthSDK.hasValidActivation());
        PowerAuthSDK.cleanupInstanceData(testHelper.getContext(), powerAuthSDK.getConfiguration(), powerAuthSDK.getKeychainConfiguration());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertFalse(powerAuthSDK.hasValidActivation());
    }

    Keychain getInstanceKeychain() throws Exception {
        String keychainId = powerAuthSDK.getKeychainConfiguration().getKeychainStatusId();
        return KeychainFactory.getKeychain(testHelper.getContext(), keychainId, KeychainProtection.NONE);
    }

    @Test
    public void testUnsupportedDataHandling() throws Exception {
        byte[] unsupportedData = "HELLO".getBytes(StandardCharsets.UTF_8);
        String instanceId = powerAuthSDK.getConfiguration().getInstanceId();
        PowerAuthConfiguration configuration = powerAuthSDK.getConfiguration();
        PowerAuthKeychainConfiguration keychainConfiguration = powerAuthSDK.getKeychainConfiguration();

        // Insert status data
        Keychain keychain = getInstanceKeychain();
        keychain.putData(unsupportedData, instanceId);

        // re-create SDK
        PowerAuthErrorException exception = assertThrows(PowerAuthErrorException.class, () ->
            new PowerAuthSDK.Builder(configuration)
                    .keychainConfiguration(keychainConfiguration)
                    .build(testHelper.getContext())
        );
        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA, exception.getPowerAuthErrorCode());

        // Erase instance data
        PowerAuthSDK.cleanupInstanceData(testHelper.getContext(), configuration, keychainConfiguration);

        // re-create should work now
        powerAuthSDK = activationHelper.reCreateSdk();
    }

    @Test
    public void testUpgradeSDKDetection() throws Exception {
        // Session's data blob begins with sequence 'P' 'A' (data version) and status flag.
        byte[] unsupportedData = "PX0".getBytes(StandardCharsets.UTF_8);
        String instanceId = powerAuthSDK.getConfiguration().getInstanceId();
        PowerAuthConfiguration configuration = powerAuthSDK.getConfiguration();
        PowerAuthKeychainConfiguration keychainConfiguration = powerAuthSDK.getKeychainConfiguration();

        // Insert status data
        Keychain keychain = getInstanceKeychain();
        keychain.putData(unsupportedData, instanceId);

        // re-create SDK
        PowerAuthErrorException exception = assertThrows(PowerAuthErrorException.class, () ->
                new PowerAuthSDK.Builder(configuration)
                        .keychainConfiguration(keychainConfiguration)
                        .build(testHelper.getContext())
        );
        assertEquals(PowerAuthErrorCodes.UPGRADE_SDK, exception.getPowerAuthErrorCode());

        // Erase instance data
        PowerAuthSDK.cleanupInstanceData(testHelper.getContext(), configuration, keychainConfiguration);

        // re-create should work now
        powerAuthSDK = activationHelper.reCreateSdk();
    }
}
