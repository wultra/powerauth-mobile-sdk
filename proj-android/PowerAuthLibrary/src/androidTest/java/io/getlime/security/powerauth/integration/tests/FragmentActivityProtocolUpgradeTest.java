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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.test.core.app.ActivityScenario;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import io.getlime.security.powerauth.biometry.IAddBiometryFactorListener;
import io.getlime.security.powerauth.biometry.IAuthenticateWithBiometricsListener;
import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.TestActivity;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.networking.response.ProtocolUpgradeResult;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthBiometricPrompt;
import io.getlime.security.powerauth.sdk.PowerAuthHttpHeader;
import io.getlime.security.powerauth.sdk.impl.MainThreadExecutor;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Test of protocol upgrade procedure from protocol V3 to V4.
 * While {@link ProtocolUpgradeTest} includes the main tests of protocol upgrade process,
 * set of tests contained in this class is focused on biometry key upgrade, which uses
 * activity fragments.
 */
public class FragmentActivityProtocolUpgradeTest extends FragmentActivityBaseTest {

    /**
     * If set to {@code true}, test will need interactions, such as touch sensor on a simulator.
     * Otherwise, such interactions are skipped, which may lead to not validating the biometry.
     */
    private final boolean RUN_INTERACTIVE_SECTIONS = false;

    /**
     * Override the setUp method to force legacy algorithm, that can be upgraded.
     */
    @Override
    public void setUp() throws Exception {
        PowerAuthLog.setEnabled(true);
        PowerAuthLog.setVerbose(true);
        testHelper = new PowerAuthTestHelper.Builder()
                .powerAuthAlgorithm(PowerAuthAlgorithm.LEGACY_P256)
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
        authenticationHelper = new AuthenticationHelper(testHelper);
        if (isRequestFailureSimulatorAvailable()) {
            clearAllSimulateFailures();
        }
        activityScenario = ActivityScenario.launch(TestActivity.class);
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated. It is expected the protocol
     * upgrade process completes successfully and the biometry key is upgraded and valid.
     * The new biometry key is not validated if {@link #RUN_INTERACTIVE_SECTIONS} is {@code false}.
     */
    @Test
    public void testProtocolUpgrade_noBiometrySetupAuthentication() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, false);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());
            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), biometricPrompt);

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
            } else {
                assertFalse(result.isActivationStatusFetchRequired());
                assertNotNull(result.getActivationFingerprint());
                assertFalse(result.isBiometryFactorRemoved());
            }

            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

            if (RUN_INTERACTIVE_SECTIONS) {
                assertTrue(validateBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated with missing biometric prompt.
     * It is expected the protocol upgrade process completes successfully and the biometry is removed.
     */
    @Test
    public void testProtocolUpgrade_noBiometrySetupAuthentication_missingPrompt() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, false);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), CryptoUtils.randomSecureData(32));

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
                assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            } else {
                assertFalse(result.isActivationStatusFetchRequired());
                assertNotNull(result.getActivationFingerprint());
                assertTrue(result.isBiometryFactorRemoved());
                assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated.
     * Because of a simulated error during biometric authentication, the biometry key cannot be
     * upgraded and biometry should be removed completely.
     */
    @Test
    public void testProtocolUpgrade_noBiometrySetupAuthentication_authenticationFailure() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, false);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());

            simulateNextAuthenticationUsingBiometricsFailure();
            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), biometricPrompt);

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
                assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            } else {
                assertFalse(result.isActivationStatusFetchRequired());
                assertNotNull(result.getActivationFingerprint());
                assertTrue(result.isBiometryFactorRemoved());
                assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated.
     * Because of a simulated error during biometric authentication, the biometry key cannot be
     * upgraded and biometry should be removed completely. Because of a response failure when
     * trying the remove biometry, protocol upgrade result shows the activation status should be
     * fetched to synchronize biometry.
     */
    @Test
    public void testProtocolUpgrade_noBiometrySetupAuthentication_authenticationFailure_biometryRemoveResponseFailure() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, false);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());

            simulateNextAuthenticationUsingBiometricsFailure();
            simulateNextResponseFailure("/biometry/remove", 500);
            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), biometricPrompt);

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
                assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            } else {
                // Protocol upgrade returns activation status fetch required to synchronize biometry
                assertTrue(result.isActivationStatusFetchRequired());
                assertNotNull(result.getActivationFingerprint());
                assertTrue(result.isBiometryFactorRemoved());

                assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());

                // Biometry remove API is not called as it was response failure before
                simulateNetworkErrorOnSend("/biometry/remove");
                activationHelper.fetchActivationStatus();

                assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated.
     * Because of a simulated error during biometric authentication, the biometry key cannot be
     * upgraded and biometry should be removed completely. Because of a request failure when
     * trying the remove biometry, protocol upgrade result shows the activation status should be
     * fetched to synchronize biometry.
     */
    @Test
    public void testProtocolUpgrade_noBiometrySetupAuthentication_authenticationFailure_biometryRemoveRequestSendFailure() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_FRAGMENT | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, false);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());

            simulateNextAuthenticationUsingBiometricsFailure();
            simulateNetworkErrorOnSend("/biometry/remove");
            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), biometricPrompt);

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
                assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                return;
            }

            // Protocol upgrade returns activation status fetch required to synchronize biometry
            assertTrue(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertTrue(result.isBiometryFactorRemoved());

            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());

            final Exception exception = assertThrows(Exception.class, this::validateBiometryFactor);
            assertEquals("Asynchronous operation failed with exception: Biometric authentication failed due to missing biometric key.", exception.getMessage());

            // Simulate error to make sure the API is called on activation status fetch
            simulateNetworkErrorOnSend("/biometry/remove");
            assertThrows(Exception.class, () -> activationHelper.fetchActivationStatus());
            activationHelper.fetchActivationStatus();

            AsyncHelper.await(resultCatcher -> {
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), biometricPrompt, new IAddBiometryFactorListener() {
                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull Throwable throwable) {
                        resultCatcher.completeWithError(throwable);
                    }
                });
            });

            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());

            if (RUN_INTERACTIVE_SECTIONS) {
                assertTrue(validateBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated. It is expected the protocol
     * upgrade process fails, as method variant with prompt is used and SDK is configured to require
     * authentication on biometric key setup.
     */
    @Test
    public void testProtocolUpgrade_withBiometrySetupAuthentication_failOnPassedPrompt() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, true);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());
            final Throwable error = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest(), biometricPrompt);
            assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());

            assertTrue(error instanceof PowerAuthErrorException);
            assertEquals(15, ((PowerAuthErrorException) error).getPowerAuthErrorCode());
            assertEquals("Biometric key cannot be upgraded when authenticateOnBiometricKeySetup is enabled", error.getMessage());
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated. It is expected the protocol
     * upgrade process completes successfully and the biometry key is removed during the process.
     */
    @Test
    public void testProtocolUpgrade_withBiometrySetupAuthentication_removeBiometry() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_BIOMETRY_ACTIVITY | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, true);
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest());

            assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                assertNull(result);
                assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                if (RUN_INTERACTIVE_SECTIONS) {
                    assertTrue(validateBiometryFactor());
                }
            } else {
                assertFalse(result.isActivationStatusFetchRequired());
                assertNotNull(result.getActivationFingerprint());
                assertTrue(result.isBiometryFactorRemoved());
                assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
                assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
            }
        });
    }

    /**
     * Test protocol upgrade from V3 to V4. First, upgradable activation with biometry factor enabled
     * is created, then the protocol upgrade process is initiated. It is expected the protocol
     * upgrade process fails, as method variant with prompt is used and SDK uses external key.
     */
    @Test
    public void testProtocolUpgrade_externalBiometryKey_failOnPassedPrompt() throws Exception {
        assertBiometryEnrolled();

        runWithFragmentActivity(() -> {
            powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY | ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD);
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());
            assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

            final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(testHelper.getFragmentActivity());
            final Throwable error = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest(), biometricPrompt);
            assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());

            assertTrue(error instanceof PowerAuthErrorException);
            assertEquals(15, ((PowerAuthErrorException) error).getPowerAuthErrorCode());
            assertEquals("Biometric key cannot be upgraded using biometric prompt", error.getMessage());
        });
    }

    /**
     * Validate biometry factor with an interactive prompt.
     *
     * @return {@code true} if biometry factor is valid, {@code false} otherwise.
     * @throws Exception In case of an unexpected error.
     */
    private boolean validateBiometryFactor() throws Exception {
        final String uriId = "/test/biometry";
        final String method = "POST";
        final byte[] data = Base64.encodeToString(CryptoUtils.randomBytes(63), Base64.NO_WRAP).getBytes(StandardCharsets.UTF_8);
        final PowerAuthBiometricPrompt biometricPrompt = PowerAuthBiometricPrompt.prompt(testHelper.getFragmentActivity(), "Authenticate", "Authenticate with biometry\ntestAlgorithm=" + getAlgorithmForTest() + "\ncurrentAlgorithm=" + powerAuthSDK.getCurrentAlgorithm());

        final PowerAuthAuthentication authentication = AsyncHelper.await(resultCatcher -> {
            MainThreadExecutor.getInstance().execute(() -> powerAuthSDK.authenticateUsingBiometrics(testHelper.getContext(), biometricPrompt, new IAuthenticateWithBiometricsListener() {
                @Override
                public void onBiometricDialogCancelled(boolean userCancel) {
                    resultCatcher.completeWithResult(null);
                }

                @Override
                public void onBiometricDialogSuccess(@NonNull PowerAuthAuthentication authentication) {
                    resultCatcher.completeWithResult(authentication);
                }

                @Override
                public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithError(error);
                }
            }));
        });

        final PowerAuthHttpHeader header = powerAuthSDK.authenticationHeaderForRequestWithBody(authentication, method, uriId, data);
        final AuthenticationResult authenticationResult = authenticationHelper.verifyAuthenticationHeader(header, data, uriId, method);

        assertEquals(AuthCodeType.POSSESSION_BIOMETRY, authenticationResult.getAuthenticationCodeType());
        return authenticationResult.isAuthenticationValid();
    }

}
