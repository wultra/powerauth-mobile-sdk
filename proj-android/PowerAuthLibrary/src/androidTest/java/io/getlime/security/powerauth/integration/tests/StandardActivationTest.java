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
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.CreateActivationResult;
import io.getlime.security.powerauth.networking.response.IActivationRemoveListener;
import io.getlime.security.powerauth.networking.response.IActivationStatusListener;
import io.getlime.security.powerauth.networking.response.ICreateActivationListener;
import io.getlime.security.powerauth.networking.response.IUserInfoListener;
import io.getlime.security.powerauth.networking.response.UserInfo;
import io.getlime.security.powerauth.sdk.PowerAuthActivation;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.system.PowerAuthSystem;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class StandardActivationTest {

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;

    @Before
    public void setUp() throws Exception {
        testHelper = new PowerAuthTestHelper.Builder().build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
    }

    // Using PowerAuthActivation

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
    public void testCreateAndCommitWithPassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_COMMIT_WITH_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndCommitWithPasswordAlt() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_COMMIT_WITH_PASSWORD | ActivationHelper.TF_COMMIT_WITH_ALTERNATE_METHOD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndCommitWithCorePassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_COMMIT_WITH_CORE_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndCommitWithCorePasswordAlt() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_COMMIT_WITH_CORE_PASSWORD | ActivationHelper.TF_COMMIT_WITH_ALTERNATE_METHOD, null);
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
            activationCode = activation.getActivationCode() + "#" + activation.getActivationSignature();
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

        // Commit activation locally
        int resultCode = powerAuthSDK.commitActivationWithPassword(testHelper.getContext(), passwords.get(0), null);
        if (resultCode != PowerAuthErrorCodes.SUCCEED) {
            throw new Exception("PowerAuthSDK.commit failed with error code " + resultCode);
        }

        assertTrue(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Fetch status to test whether it's in "pending commit" state.
        final boolean isAutoCommit = testHelper.getTestConfig().isServerAutoCommit();
        final @ActivationStatus.ActivationState int expectedState = isAutoCommit ? ActivationStatus.State_Active : ActivationStatus.State_Pending_Commit;
        ActivationStatus activationStatus = activationHelper.fetchActivationStatus();
        if (activationStatus.state != expectedState) {
            throw new Exception("Activation is in invalid state after creation. State = " + activationStatus.state + ", Expected = " + expectedState);
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
            if (activationStatus.state != ActivationStatus.State_Active) {
                throw new Exception("Activation is in invalid state after commit. State = " + activationStatus.state);
            }
        }
    }

    // Remove activation

    @Test
    public void testRemoveActivationLocal() throws Exception {
        activationHelper.createStandardActivation(true, null);
        // Remove activation
        powerAuthSDK.removeActivationLocal(testHelper.getContext(), true);
        // Back to Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    @Test
    public void testRemoveActivationWithAuthentication() throws Exception {

        activationHelper.createStandardActivation(true, null);

        boolean removed = AsyncHelper.await(new AsyncHelper.Execution<Boolean>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Boolean> resultCatcher) throws Exception {
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
            }
        });
        assertTrue(removed);

        // Back to initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    // Activation status

    @Test
    public void testGetActivationStatus() throws Exception {
        activationHelper.createStandardActivation(true, null);
        ActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Active, status.state);

        testHelper.getServerApi().activationBlock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Blocked, status.state);

        testHelper.getServerApi().activationUnblock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Active, status.state);

        testHelper.getServerApi().activationRemove(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Removed, status.state);

        assertNotNull(powerAuthSDK.getLastFetchedActivationStatus());
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        assertNull(powerAuthSDK.getLastFetchedActivationStatus());
    }

    @Test
    public void testGetActivationStatusConcurrent() throws Exception {
        activationHelper.createStandardActivation(true, null);

        final ActivationStatus[] status1 = new ActivationStatus[1];
        final ActivationStatus[] status2 = new ActivationStatus[1];
        final ActivationStatus[] status3 = new ActivationStatus[1];
        final AtomicInteger counter = new AtomicInteger(0);

        AsyncHelper.await((AsyncHelper.Execution<Boolean>) resultCatcher -> {
            final ICancelable task1, task2, task3, task4;
            task1 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(ActivationStatus status) {
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
                public void onActivationStatusSucceed(ActivationStatus status) {
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
                public void onActivationStatusSucceed(ActivationStatus status) {
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
                public void onActivationStatusSucceed(ActivationStatus status) {
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

        int result = powerAuthSDK.commitActivationWithPassword(testHelper.getContext(), "1234");
        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, result);
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

    // UserInfo

    @Test
    public void testUserInfo() throws Exception {
        activationHelper.createStandardActivation(true, null);

        final String userId = activationHelper.getUserId();
        assertNotNull(activationHelper.getCreateActivationResult().getUserInfo());
        assertNotNull(powerAuthSDK.getLastFetchedUserInfo());
        assertEquals(userId, powerAuthSDK.getLastFetchedUserInfo().getSubject());
        assertEquals(userId, activationHelper.getCreateActivationResult().getUserInfo().getSubject());

        // Now fetch user info from the server
        UserInfo info = AsyncHelper.await((AsyncHelper.Execution<UserInfo>) resultCatcher -> {
            powerAuthSDK.fetchUserInfo(testHelper.getContext(), new IUserInfoListener() {
                @Override
                public void onUserInfoSucceed(@NonNull UserInfo userInfo) {
                    resultCatcher.completeWithResult(userInfo);
                }

                @Override
                public void onUserInfoFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertEquals(userId, info.getSubject());
        assertEquals(info, powerAuthSDK.getLastFetchedUserInfo());
    }
}
