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

import androidx.test.filters.LargeTest;
import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.core.RecoveryData;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.Logger;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.integration.support.model.RecoveryConfig;
import io.getlime.security.powerauth.networking.response.CreateActivationResult;
import io.getlime.security.powerauth.networking.response.ICreateActivationListener;
import io.getlime.security.powerauth.sdk.PowerAuthActivation;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class RecoveryActivationTest {

    private PowerAuthTestHelper testHelper;
    private ActivationHelper regularActivation;
    private ActivationHelper recoveryActivation;

    @Before
    public void setUp() throws Exception {
        testHelper = new PowerAuthTestHelper.Builder().build();
        regularActivation = new ActivationHelper(testHelper);
        final PowerAuthSDK recoverySdk = testHelper.createSdk("test.recoveryInstance", true);
        recoveryActivation = new ActivationHelper(testHelper, testHelper.getSharedApplication(), testHelper.getUserId(), recoverySdk);
    }

    @After
    public void tearDown() {
        if (regularActivation != null) {
            regularActivation.cleanupAfterTest();
        }
        if (recoveryActivation != null) {
            recoveryActivation.cleanupAfterTest();
        }
    }

    @Test
    public void testCreateActivationWithNoRC() throws Exception {
        // Disable recovery activations
        enableRecoveryActivations(false);
        regularActivation.createStandardActivation(true, null);
        CreateActivationResult createActivationResult = regularActivation.getCreateActivationResult();
        assertNotNull(createActivationResult);
        assertNull(createActivationResult.getRecoveryData());
    }

    @Test
    public void testCreateRecoveryActivation() throws Exception {

        final String extras = "recovery,attributes";

        // Enable recovery activations
        enableRecoveryActivations(true);

        // Create activation to just acquire a recovery code
        regularActivation.createStandardActivation(true, null);
        CreateActivationResult createActivationResult = regularActivation.getCreateActivationResult();
        assertNotNull(createActivationResult);
        RecoveryData recoveryData = createActivationResult.getRecoveryData();
        assertNotNull(recoveryData);
        assertNotNull(recoveryData.recoveryCode);
        assertNotNull(recoveryData.puk);

        // Now try to create a recovery activation
        final PowerAuthActivation paActivation = PowerAuthActivation.Builder.recoveryActivation(recoveryData.recoveryCode, recoveryData.puk, testHelper.getDeviceInfo())
                .setExtras(extras)
                .build();
        // Create a recovery activation
        createActivationResult = AsyncHelper.await(new AsyncHelper.Execution<CreateActivationResult>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<CreateActivationResult> resultCatcher) throws Exception {
                recoveryActivation.getPowerAuthSDK().createActivation(paActivation, new ICreateActivationListener() {
                    @Override
                    public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                        resultCatcher.completeWithResult(result);
                    }

                    @Override
                    public void onActivationCreateFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
        // Commit new activation locally
        ActivationDetail recoveryActivationDetail = recoveryActivation.assignCustomActivationAndCommitLocally(createActivationResult);
        assertEquals(extras, recoveryActivationDetail.getExtras());

        // Validate old activation state
        ActivationStatus oldActivationStatus = regularActivation.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Removed, oldActivationStatus.state);

        // Validate new activation state
        ActivationStatus recoveryActivationStatus = recoveryActivation.fetchActivationStatus();
        assertEquals(ActivationStatus.State_Active, recoveryActivationStatus.state);

        // Validate valid and invalid password
        boolean passwordValid = recoveryActivation.validateUserPassword(recoveryActivation.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = recoveryActivation.validateUserPassword(recoveryActivation.getInvalidPassword());
        assertFalse(passwordValid);
    }

    /**
     * Enable or disable recovery codes associated with activations.
     *
     * @param enable Enable or disable recovery activations.
     * @throws Exception In case of failure.
     */
    private void enableRecoveryActivations(boolean enable) throws Exception {
        long applicationId = testHelper.getSharedApplication().getApplicationId();
        RecoveryConfig recoveryConfig = testHelper.getServerApi().getRecoveryConfig(applicationId);
        if (recoveryConfig.isActivationRecoveryEnabled() == enable) {
            String currentState = enable ? "enabled" : "disabled";
            Logger.d("Recovery activations are already " + currentState + " for application " + applicationId);
            return;
        }
        Logger.d("Enabling recovery activations for application " + applicationId);
        recoveryConfig.setActivationRecoveryEnabled(enable);
        testHelper.getServerApi().updateRecoveryConfig(recoveryConfig);
    }

}
