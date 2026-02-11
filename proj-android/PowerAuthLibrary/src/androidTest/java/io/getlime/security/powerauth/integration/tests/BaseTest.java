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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import androidx.annotation.NonNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.sdk.impl.HttpConnectionFailureSimulator;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Base class for parameterized PowerAuth integration and unit tests.
 */
@RunWith(Parameterized.class)
public abstract class BaseTest {

    @Parameterized.Parameter(0) public String alg;
    @Parameterized.Parameters(name = " {0} ")
    public static Iterable<Object[]> testParameters() {
        return TestParameters.getParameters();
    }

    @PowerAuthAlgorithm
    int getAlgorithmForTest() {
        return PowerAuthTestHelper.getAlgorithmForName(alg);
    }

    PowerAuthTestHelper testHelper;
    PowerAuthSDK powerAuthSDK;
    ActivationHelper activationHelper;
    AuthenticationHelper authenticationHelper;

    @Before
    public void setUp() throws Exception {
        PowerAuthLog.setEnabled(true);
        PowerAuthLog.setVerbose(true);
        testHelper = new PowerAuthTestHelper.Builder()
                .powerAuthAlgorithm(getAlgorithmForTest())
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
        authenticationHelper = new AuthenticationHelper(testHelper);
        assertEquals(getAlgorithmForTest(), getCurrentAlgorithm());
        if (isRequestFailureSimulatorAvailable()) {
            clearAllSimulateFailures();
        }
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
        if (isRequestFailureSimulatorAvailable()) {
            clearAllSimulateFailures();
        }
    }

    /**
     * Keep new instance of {@link PowerAuthTestHelper} and create all supporting objects, with using
     * this new instance.
     * @param newHelper New instance of test helper.
     */
    public void reAssignTestHelper(@NonNull PowerAuthTestHelper newHelper) {
        testHelper = newHelper;
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
        authenticationHelper = new AuthenticationHelper(testHelper);
    }

    @PowerAuthAlgorithm
    public int getCurrentAlgorithm() {
        return powerAuthSDK.getCurrentAlgorithm();
    }

    boolean isRequestFailureSimulatorAvailable() {
        return HttpConnectionFailureSimulator.isRequestFailureSimulatorAvailable();
    }

    void simulateNextResponseFailure(final String relativePath, final int statusCode) {
        assertTrue(statusCode > 400);
        HttpConnectionFailureSimulator.setNextResponseFailure(patchRelativePathForSimulatedFailure(relativePath), statusCode);
    }

    void simulateNetworkErrorOnSend(final String relativePath, final int repeatCount) {
        assertTrue(repeatCount > 0);
        HttpConnectionFailureSimulator.setNextRequestNetworkFailureOnSend(patchRelativePathForSimulatedFailure(relativePath), repeatCount);
    }

    void simulateNetworkErrorOnSend(final String relativePath) {
        simulateNetworkErrorOnSend(relativePath, 1);
    }

    void simulateNetworkErrorOnReceive(final String relativePath) {
        HttpConnectionFailureSimulator.setNextRequestNetworkFailureOnReceive(patchRelativePathForSimulatedFailure(relativePath));
    }

    void clearAllSimulateFailures() {
        HttpConnectionFailureSimulator.clearAllFailureHooks();
    }

    String patchRelativePathForSimulatedFailure(final String relativePath) {
        if (relativePath == null) {
            return "*";
        }

        if (relativePath.equals("*") || relativePath.startsWith("/pa/")) {
            return relativePath;
        }

        assertTrue(relativePath.startsWith("/"));
        return ("LEGACY_P256".equals(alg) ? "/pa/v3" : "/pa/v4") + relativePath;
    }

}
