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

import android.support.annotation.NonNull;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.networking.response.IActivationRemoveListener;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void testCreateWithActivationCode() throws Exception {
        activationHelper.createStandardActivation(false);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateWithActivationCodeAndSignature() throws Exception {
        activationHelper.createStandardActivation(true);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testRemoveActivationLocal() throws Exception {
        activationHelper.createStandardActivation(true);
        powerAuthSDK.removeActivationLocal(testHelper.getContext(), true);
        // Back to Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    @Test
    public void testRemoveActivationWithAuthentication() throws Exception {

        activationHelper.createStandardActivation(true);

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
                    public void onActivationRemoveFailed(Throwable t) {
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

}
