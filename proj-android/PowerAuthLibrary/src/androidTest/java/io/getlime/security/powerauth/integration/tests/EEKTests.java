/*
 * Copyright 2022 Wultra s.r.o.
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.RandomGenerator;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class EEKTests {

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
    }

    @Test
    public void testModifyEEK() throws Exception {
        // Setup
        testHelper = new PowerAuthTestHelper.Builder().build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);

        // Test
        activationHelper.createStandardActivation(true, null);
        assertFalse(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

        final byte[] eek = new RandomGenerator().generateBytes(16);
        powerAuthSDK.addExternalEncryptionKey(eek);

        assertTrue(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

        powerAuthSDK.removeExternalEncryptionKey();
        assertFalse(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
    }

    @Test
    public void testEEKFromConfiguration() throws Exception {
        // Setup
        final byte[] eek = new RandomGenerator().generateBytes(16);
        testHelper = new PowerAuthTestHelper.Builder()
                .configurationObserver(new PowerAuthTestHelper.IConfigurationObserver() {
                    @Override
                    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
                        builder.externalEncryptionKey(eek);
                    }

                    @Override
                    public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
                    }

                    @Override
                    public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
                    }
                })
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);

        // Test
        activationHelper.createStandardActivation(true, null);
        assertTrue(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

        powerAuthSDK.removeExternalEncryptionKey();
        assertFalse(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
    }
}
