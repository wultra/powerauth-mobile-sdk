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

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.networking.response.IOfflineAuthenticationCodeListener;
import io.getlime.security.powerauth.networking.response.ProtocolUpgradeResult;
import io.getlime.security.powerauth.sdk.PowerAuthActivationState;
import io.getlime.security.powerauth.sdk.PowerAuthActivationStatus;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthHttpHeader;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Test of protocol upgrade procedure from protocol V3 to V4.
 */
public class ProtocolUpgradeTest extends BaseTest {

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
    }

    /**
     * Test successful upgrade from V3 to V4 protocol.
     */
    @Test
    public void testProtocolUpgrade() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);
        assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

        activationHelper.createTokenAndValidateTokenHeader("TestToken", true);

        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest());

        // Activation now runs on the tested algorithm
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());

        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
            // Server still offers an upgrade, but it is not possible due to the legacy configuration
            assertTrue(status.isProtocolUpgradeAvailable());
        } else {
            assertFalse(status.isProtocolUpgradeAvailable());
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertFalse(result.isBiometryFactorRemoved());
        }

        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        activationHelper.createTokenAndValidateTokenHeader("TestToken", false);
        if (getAlgorithmForTest() != PowerAuthAlgorithm.LEGACY_P256) {
            var keys = activationHelper.fetchSecureVaultKeys(null, null);
            activationHelper.reCreateSdk();
            activationHelper.fetchSecureVaultKeys(keys.get(0), keys.get(1));
        }
    }

    /**
     * Test successful upgrade from V3 to V4 protocol. In this case the activation has also biometry
     * factor enabled and so the test also covers the upgrade to longer biometry KEK.
     */
    @Test
    public void testProtocolUpgrade_withFakeBiometry() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);
        assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

        // Start protocol upgrade with custom new biometry KEK.
        final SecureData newBiometryKek = CryptoUtils.randomSecureData(32);
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), newBiometryKek);

        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
        } else {
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertFalse(result.isBiometryFactorRemoved());
        }

        activationHelper.fetchActivationStatus();
        activationHelper.reCreateSdk();

        assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

        final PowerAuthAuthentication auth = getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256
                ? activationHelper.getBiometricAuthentication(null)
                : PowerAuthAuthentication.possessionWithBiometry(newBiometryKek);

        assertTrue(biometryFactorIsValid(auth, true));
    }

    /**
     * Test protocol upgrade attempt. In this case the activation has also biometry
     * factor enabled via external biometry, but a new biometry KEK is not passed
     * to the start protocol upgrade task, which results in removing the biometry factor.
     */
    @Test
    public void testProtocolUpgrade_withFakeBiometryNewKekNotPassed() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);
        assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

        // Start protocol upgrade with custom new biometry KEK.
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest());
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
            assertTrue(powerAuthSDK.getCoreSession().hasBiometryFactor());
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
        } else {
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertTrue(result.isBiometryFactorRemoved());
            assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
        }
    }

    /**
     * Test unsuccessful upgrade from V3 to V4 protocol. In this case there is a simulated
     * network error when fetching the activation status. Meaning the upgrade procedure cannot
     * actually start. Upgrade task should fail, the system state must remain unchanged.
     */
    @Test
    public void testProtocolUpgrade_fetchStatusFailure() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);

        // Activation status fetch fails for this test.
        simulateNetworkErrorOnSend("/pa/v3/activation/status");
        final Throwable throwable = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest());

        // Assert expected error occurred
        assertNotNull("Protocol upgrade should fail with exception", throwable);
        assertTrue(throwable instanceof PowerAuthErrorException);
        assertEquals(PowerAuthErrorCodes.NETWORK_ERROR, ((PowerAuthErrorException) throwable).getPowerAuthErrorCode());
        assertNotNull(throwable.getMessage());
        assertTrue(throwable.getMessage().startsWith("powerAuth::PowerAuthException: Simulated error on data send"));

        // Protocol version did not change
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());

        // Activation is still active and upgrade is available.
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(status.isProtocolUpgradeAvailable());
        assertEquals(getAlgorithmForTest() > PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.hasProtocolUpgradeAvailable());

        // Assert the old biometry factor key still works
        assertTrue(biometryFactorIsValid(activationHelper.getBiometricAuthentication(null), true));
    }

    /**
     * Test unsuccessful upgrade from V3 to V4 protocol. In this case there is a simulated
     * response failure when starting the upgrade.
     * Upgrade task should fail, the system state must remain unchanged.
     */
    @Test
    public void testProtocolUpgrade_upgradeStartResponseFailure() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);

        final SecureData newBiometryKek = CryptoUtils.randomSecureData(32);

        simulateNextResponseFailure("/pa/v4/upgrade/start", 500);
        final Throwable upgradeException = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest(), newBiometryKek);

        // Assert expected error occurred
        assertNotNull("Protocol upgrade should fail with exception", upgradeException);
        assertTrue(upgradeException instanceof PowerAuthErrorException);
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            // Attempt to upgrade with only legacy configuration
            assertEquals("powerAuth::PowerAuthException: Protocol upgrade is not possible with current configuration", upgradeException.getMessage());
        } else {
            // Simulated response failure
            assertEquals(PowerAuthErrorCodes.NETWORK_ERROR, ((PowerAuthErrorException) upgradeException).getPowerAuthErrorCode());
            assertEquals("powerAuth::PowerAuthException: Network error", upgradeException.getMessage());
        }

        // Protocol version did not change
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());

        // Activation is still active and upgrade is available.
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(status.isProtocolUpgradeAvailable());
        assertEquals(getAlgorithmForTest() > PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.hasProtocolUpgradeAvailable());

        // Assert the old biometry factor key still works
        assertTrue(biometryFactorIsValid(activationHelper.getBiometricAuthentication(null), true));

        // Second attempt to upgrade protocol should succeed
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), newBiometryKek);
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
        } else {
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertFalse(result.isBiometryFactorRemoved());
        }
    }

    /**
     * Test successful upgrade from V3 to V4 protocol. In this case there is a simulated
     * response failure when confirming the upgrade. Even though the upgrade confirm response
     * was not received, server has processed the confirm request, and so the following activation
     * status shows the upgrade is completed.
     */
    @Test
    public void testProtocolUpgrade_upgradeConfirmResponseFailure() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);

        final SecureData newBiometryKek = CryptoUtils.randomSecureData(32);

        simulateNextResponseFailure("/pa/v4/upgrade/confirm", 500);
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), newBiometryKek);

        if (getAlgorithmForTest() <= PowerAuthAlgorithm.LEGACY_P256) {
            // Exit this test when on legacy protocol, cannot upgrade due to missing configuration
            assertNull(result);
            assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
            return;
        }

        // Protocol version upgraded locally
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        // Upgrade is not confirmed, still in progress
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        // Result of the protocol upgrade shows that activation status should be fetched
        assertTrue(result.isActivationStatusFetchRequired());
        assertNull(result.getActivationFingerprint());
        assertFalse(result.isBiometryFactorRemoved());

        // Upgrade still in progress, functionality limited for online authentication code
        PowerAuthErrorException exception = assertThrows(PowerAuthErrorException.class, () -> biometryFactorIsValid(activationHelper.getBiometricAuthentication(null), true));
        assertEquals("powerAuth::PowerAuthException: Authentication header calculation is not allowed during pending protocol upgrade", exception.getMessage());
        assertEquals(17, exception.getPowerAuthErrorCode());

        // Upgrade still in progress, functionality limited for offline authentication code
        exception = (PowerAuthErrorException) assertThrows(Exception.class, () -> biometryFactorIsValid(activationHelper.getBiometricAuthentication(null), false)).getCause();
        assertEquals("powerAuth::PowerAuthException: Offline authentication code calculation is not allowed during protocol upgrade", exception.getMessage());
        assertEquals(17, exception.getPowerAuthErrorCode());

        // The activation status shows upgrade is completed
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertFalse(status.isProtocolUpgradeAvailable());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());

        // Check that the old biometry factor does not work anymore.
        exception = assertThrows(PowerAuthErrorException.class, () -> biometryFactorIsValid(activationHelper.getBiometricAuthentication(null), true));
        assertEquals("powerAuth::PowerAuthException: Invalid credentials provided", exception.getMessage());
        assertEquals(15, exception.getPowerAuthErrorCode());
    }

    /**
     * Test successful upgrade from V3 to V4 protocol. In this case there is a simulated network
     * error 3 times in the row when sending the upgrade confirm request. Meaning that the task
     * completes while the server still awaits the upgrade confirm. To finish the protocol upgrade,
     * activation status fetch is required to confirm the protocol upgrade in the background.
     *
     */
    @Test
    public void testProtocolUpgrade_upgradeConfirmRequestFailure() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY);

        final SecureData newBiometryKek = CryptoUtils.randomSecureData(32);

        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm", 3);
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), newBiometryKek);

        if (getAlgorithmForTest() <= PowerAuthAlgorithm.LEGACY_P256) {
            // Exit this test when on legacy protocol, cannot upgrade due to missing configuration
            assertNull(result);
            assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
            return;
        }

        // Protocol version upgraded locally
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        // Upgrade is not confirmed, still in progress
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        // Result of the protocol upgrade shows that activation status should be fetched
        assertTrue(result.isActivationStatusFetchRequired());
        assertNull(result.getActivationFingerprint());
        assertFalse(result.isBiometryFactorRemoved());

        // Make the background confirm request fail too.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm");
        assertThrows(Exception.class, () -> activationHelper.fetchActivationStatus());
        // Fetch failed, because the background confirm failed.
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // Fetch status again, which should complete the protocol upgrade
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // Simulate application restart before testing authentication
        activationHelper.reCreateSdk();
        assertTrue(biometryFactorIsValid(PowerAuthAuthentication.possessionWithBiometry(newBiometryKek), true));
    }

    /**
     * Test successful upgrade from V3 to V4 protocol. In this case there is a simulated network
     * error when sending the upgrade confirm request followed by activation status response
     * failure. Meaning that the task completes without multiple attempts, while the server still
     * awaits the upgrade confirm. To finish the protocol upgrade, activation status fetch
     * is required to confirm the protocol upgrade in the background.
     */
    @Test
    public void testProtocolUpgrade_upgradeConfirmRequestAndStatusResponseFailure() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        // Fail the upgrade confirm, and the following status to fail without trying more attempts.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm");
        simulateNextResponseFailure("/pa/v4/activation/status", 500);
        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest());

        if (getAlgorithmForTest() <= PowerAuthAlgorithm.LEGACY_P256) {
            // Exit this test when on legacy protocol, cannot upgrade due to missing configuration
            assertNull(result);
            assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
            return;
        }

        // Protocol version upgraded locally
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        // Upgrade is not confirmed, still in progress
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        // Result of the protocol upgrade shows that activation status should be fetched
        assertTrue(result.isActivationStatusFetchRequired());
        assertNull(result.getActivationFingerprint());
        assertFalse(result.isBiometryFactorRemoved());

        // Fetch status to complete the protocol upgrade
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
    }

    /**
     * Test successful upgrade from V3 to V4 protocol. In this case a new biometry KEK is passed to
     * the protocol upgrade task, even though the biometry factor is not set for the V3.
     */
    @Test
    public void testProtocolUpgrade_newBiometryKekWithoutBiometryFactorSet() throws Exception {
        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        final SecureData newBiometryKek = CryptoUtils.randomSecureData(32);

        final ProtocolUpgradeResult result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest(), newBiometryKek);
        assertFalse(powerAuthSDK.getCoreSession().hasBiometryFactor());

        // Protocol version is upgraded.
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
        } else {
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
            assertFalse(result.isBiometryFactorRemoved());

            // Check biometry factor not set
            final PowerAuthErrorException exception = assertThrows(PowerAuthErrorException.class, () -> biometryFactorIsValid(PowerAuthAuthentication.possessionWithBiometry(newBiometryKek), true));
            assertEquals("powerAuth::PowerAuthException: Biometric factor is not configured", exception.getMessage());
            assertEquals(19, exception.getPowerAuthErrorCode());
        }
    }

    /**
     * Test upgrade from V3 to V4 protocol.
     * In this case there are simulated errors and restarts of the application.
     */
    @Test
    public void testProtocolUpgrade_withRestarts() throws Exception {
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            System.out.println("This test is irrelevant for PowerAuthAlgorithm.LEGACY_P256");
            return;
        }

        powerAuthSDK = activationHelper.prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        ProtocolUpgradeResult result;
        Throwable throwable;
        PowerAuthActivationStatus status;

        // The upgrade start request fails, keeping the application state as it was
        // before the upgrade attempt. Even after restart of the application.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/start");
        throwable = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest());
        assertNotNull(throwable);
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertTrue(powerAuthSDK.hasProtocolUpgradeAvailable());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable()); // No info after restart
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(status.isProtocolUpgradeAvailable());
        assertTrue(powerAuthSDK.hasProtocolUpgradeAvailable());

        // The upgrade start response fails, keeping the application state as it was
        // before the upgrade attempt. Even after restart of the application.
        simulateNextResponseFailure("/pa/v4/upgrade/start", 500);
        throwable = activationHelper.startProtocolUpgradeExpectFailure(getAlgorithmForTest());
        assertNotNull(throwable);
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertTrue(powerAuthSDK.hasProtocolUpgradeAvailable());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable()); // No info after restart
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(powerAuthSDK.hasProtocolUpgradeAvailable());

        // The upgrade has started, but confirm request fails and status cannot be fetched.
        // SDK protocol was upgraded locally, but the confirm is still pending. The pending
        // upgrade state should be preserved despite application restart.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm");
        simulateNextResponseFailure("/pa/v4/activation/status", 500);
        result = activationHelper.startProtocolUpgradeExpectResult(getAlgorithmForTest());
        assertNotNull(result);
        assertTrue(result.isActivationStatusFetchRequired());
        assertFalse(result.isBiometryFactorRemoved());
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // After application restart, the status could not be fetched, meaning the upgrade
        // confirm cannot be requested. After another application restart, the protocol
        // upgrade process is still pending.
        simulateNextResponseFailure("/pa/v4/activation/status", 500);
        assertThrows(Exception.class, () -> activationHelper.fetchActivationStatus());
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        assertTrue(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // Activation status fetch now succeeds. After application restart
        // the protocol upgrade should be already confirmed.
        status = activationHelper.fetchActivationStatus();
        assertTrue(status.isProtocolUpgradeAvailable());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        powerAuthSDK = activationHelper.reCreateSdk();
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());

        // Final activation status fetch shows the protocol upgrade is completed.
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
    }

    private boolean biometryFactorIsValid(final PowerAuthAuthentication authentication, final boolean online) throws Exception {
        final String uriId = "/test/biometry";
        final String method = "POST";
        final byte[] data = Base64.encodeToString(CryptoUtils.randomBytes(63), Base64.NO_WRAP).getBytes(StandardCharsets.UTF_8);

        final AuthenticationResult authenticationResult;
        if (online) {
            final PowerAuthHttpHeader header = powerAuthSDK.authenticationHeaderForRequestWithBody(authentication, method, uriId, data);
            authenticationResult = authenticationHelper.verifyAuthenticationHeader(header, data, uriId, method);

        } else {
            final String nonce = testHelper.getRandomGenerator().generateBase64Bytes(16);
            final String offlineAuthCode = AsyncHelper.await(resultCatcher ->
                    powerAuthSDK.offlineAuthenticationCode(testHelper.getContext(), authentication, uriId, data, nonce, new IOfflineAuthenticationCodeListener() {
                        @Override
                        public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                            resultCatcher.completeWithResult(authenticationCode);
                        }

                        @Override
                        public void onOfflineAuthenticationCodeFailed(@NonNull Throwable throwable) {
                            resultCatcher.completeWithError(throwable);
                        }
                    })
            );

            final String normalizedData = AuthenticationHelper.normalizeOfflineData(data, "/offline/test", nonce);
            AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
            authenticationCodeData.setActivationId(powerAuthSDK.getActivationIdentifier());
            authenticationCodeData.setData(normalizedData);
            authenticationCodeData.setAuthenticationCode(offlineAuthCode);
            authenticationCodeData.setAllowBiometry(false);

            authenticationResult = testHelper.getServerApi().verifyOfflineAuthenticationCode(authenticationCodeData);
        }

        assertEquals(AuthCodeType.POSSESSION_BIOMETRY, authenticationResult.getAuthenticationCodeType());
        return authenticationResult.isAuthenticationValid();
    }

}
