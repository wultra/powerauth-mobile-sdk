/*
 * Copyright 2025 Wultra s.r.o.
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

import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import io.getlime.security.powerauth.biometry.IAddBiometryFactorListener;
import io.getlime.security.powerauth.biometry.IRemoveBiometryFactorListener;
import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.*;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.sdk.*;
import org.junit.Test;

import androidx.annotation.NonNull;

import static org.junit.Assert.*;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

public class BiometricTest extends BaseTest implements PowerAuthTestHelper.IConfigurationObserver {

    private ActivityScenario<TestActivity> activityScenario;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        activityScenario = ActivityScenario.launch(TestActivity.class);
    }

    @Override
    public void tearDown() {
        super.tearDown();
        activityScenario.close();
    }

    private void runWithFragmentActivity(final ITestExecution execution) throws Exception {
        runWithFragmentActivity(this, execution);
    }

    private void runWithFragmentActivity(final PowerAuthTestHelper.IConfigurationObserver configurationObserver,
                                         final ITestExecution execution) throws Exception {
        FragmentActivity[] capturedActivity = new FragmentActivity[1];
        TestFragment fragment = new TestFragment();

        // Create supporting UI
        activityScenario.moveToState(Lifecycle.State.STARTED);
        activityScenario.onActivity(activity -> {
            capturedActivity[0] = activity;
            activity.getSupportFragmentManager()
                    .beginTransaction()
                    .add(android.R.id.content, fragment)
                    .commitNow(); // Synchronously attach the fragment
        });
        assertNotNull(capturedActivity[0]);
        // Setup
        testHelper = new PowerAuthTestHelper.Builder()
                .configurationObserver(configurationObserver)
                .powerAuthAlgorithm(getAlgorithmForTest())
                .testFragmentActivity(capturedActivity[0])
                .testFragment(fragment)
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);

        // Tun test in the same thread
        execution.execute();
    }

    private void removeBiometryFactor() throws Exception {
        AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.removeBiometryFactor(testHelper.getContext(), new IRemoveBiometryFactorListener() {
                @Override
                public void onRemoveBiometryFactorSucceed() {
                    resultCatcher.completeWithSuccess();
                }

                @Override
                public void onRemoveBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithError(error);
                }
            });
        });
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
    }

    /** @noinspection deprecation*/
    private void removeBiometricFactorDeprecated() throws Exception {
        assertTrue(powerAuthSDK.removeBiometryFactor(testHelper.getContext()));
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
    }

    @Test
    public void testPersistWithBiometryFragmentActivity() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometryFactor();
        });
    }

    @Test
    public void testPersistWithBiometryFragmentActivityCorePass() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometryFactor();
        });
    }

    @Test
    public void testPersistWithBiometryFragment() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometryFactor();
        });
    }

    @Test
    public void testPersistWithBiometryFragmentCorePass() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometryFactor();
        });
    }

    @Test
    public void testPersistWithDeprecatedFragment() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }

        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometricFactorDeprecated();
        });
    }

    @Test
    public void testPersistWithDeprecatedFragmentActivity() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }

        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY | ActivationHelper.TF_PERSIST_WITH_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometricFactorDeprecated();
        });
    }

    @Test
    public void testPersistWithDeprecatedFragmentCorePass() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }

        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometricFactorDeprecated();
        });
    }

    @Test
    public void testPersistWithDeprecatedFragmentActivityCorePass() throws Exception {
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            // persist will fail in this test if other than legacy algorithm is used.
            return;
        }

        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
            removeBiometricFactorDeprecated();
        });
    }

    @Test
    public void testAddBiometryFactorFragmentActivityCorePass() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            AsyncHelper.await(resultCatcher -> {
                PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), biometricPrompt, new IAddBiometryFactorListener() {

                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
        });
    }

    @Test
    public void testAddBiometryFactorFragmentCorePass() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            AsyncHelper.await(resultCatcher -> {
                PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragment());
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), biometricPrompt, new IAddBiometryFactorListener() {

                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
        });
    }

    @Test
    public void testAddBiometryFactor_customBiometryKek() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

        final SecureData biometryKek = CryptoUtils.randomSecureData(powerAuthSDK.getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256 ? 16 : 32);
        AsyncHelper.await(resultCatcher ->
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), biometryKek, new IAddBiometryFactorListener() {
                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                })
        );

        // Validate added biometry
        final byte[] data = Base64.encodeToString(CryptoUtils.randomBytes(63), Base64.NO_WRAP).getBytes(StandardCharsets.UTF_8);
        final PowerAuthAuthentication auth = PowerAuthAuthentication.possessionWithBiometry(biometryKek);
        AuthenticationResult result = activationHelper.validateAuthentication(auth, data, "POST", "/hello/biohacker", true);
        assertTrue(result.isAuthenticationValid());
        assertEquals(AuthCodeType.POSSESSION_BIOMETRY, result.getAuthenticationCodeType());

        // Remove biometry and validate biometry factor unavailability
        removeBiometryFactor();
        final var exception = assertThrows(PowerAuthErrorException.class, () -> activationHelper.validateAuthentication(auth, data, "POST", "/hello/biohacker", true));
        assertEquals(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, exception.getPowerAuthErrorCode());
        assertEquals("powerAuth::PowerAuthException: Biometric factor is not configured", exception.getMessage());

        // Add biometry again
        final SecureData newBiometryKek = CryptoUtils.randomSecureData(powerAuthSDK.getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256 ? 16 : 32);
        AsyncHelper.await(resultCatcher ->
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), newBiometryKek, new IAddBiometryFactorListener() {
                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                })
        );
        // Authentication using previous auth object should fail
        result = activationHelper.validateAuthentication(auth, data, "POST", "/hello/biohacker", true);
        assertFalse(result.isAuthenticationValid());
        assertEquals(AuthCodeType.POSSESSION_BIOMETRY, result.getAuthenticationCodeType());

        // Authenticate using the new auth object
        final PowerAuthAuthentication newAuth = PowerAuthAuthentication.possessionWithBiometry(newBiometryKek);
        result = activationHelper.validateAuthentication(newAuth, data, "POST", "/hello/biohacker", true);
        assertTrue(result.isAuthenticationValid());
        assertEquals(AuthCodeType.POSSESSION_BIOMETRY, result.getAuthenticationCodeType());
    }

    @Override
    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder) {
        builder.authenticateOnBiometricKeySetup(false);
    }

    @Override
    public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
    }
}
