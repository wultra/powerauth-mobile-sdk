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

import androidx.annotation.NonNull;

import org.junit.Test;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.networking.response.IProtocolUpgradeListener;
import io.getlime.security.powerauth.networking.response.ProtocolUpgradeResult;
import io.getlime.security.powerauth.sdk.PowerAuthActivationState;
import io.getlime.security.powerauth.sdk.PowerAuthActivationStatus;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
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
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        final ProtocolUpgradeResult result = startProtocolUpgradeExpectResult();

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
        }

        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
    }

    /**
     * Test unsuccessful upgrade from V3 to V4 protocol. In this case there is a simulated
     * network error when fetching the activation status. Meaning the upgrade procedure cannot
     * actually start. Upgrade task should fail, the system state must remain unchanged.
     */
    @Test
    public void testProtocolUpgrade_fetchStatusFailure() throws Exception {
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        // Activation status fetch fails for this test.
        simulateNetworkErrorOnSend("/pa/v3/activation/status");
        final Throwable throwable = startProtocolUpgradeExpectFailure();

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
    }

    /**
     * Test unsuccessful upgrade from V3 to V4 protocol. In this case there is a simulated
     * response failure when starting the upgrade.
     * Upgrade task should fail, the system state must remain unchanged.
     */
    @Test
    public void testProtocolUpgrade_upgradeStartResponseFailure() throws Exception {
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        simulateNextResponseFailure("/pa/v4/upgrade/start", 500);
        final Throwable upgradeException = startProtocolUpgradeExpectFailure();

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

        // Second attempt to upgrade protocol should succeed
        final ProtocolUpgradeResult result = startProtocolUpgradeExpectResult();
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getCurrentAlgorithm());
        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            assertNull(result);
        } else {
            assertNotNull(result);
            assertFalse(result.isActivationStatusFetchRequired());
            assertNotNull(result.getActivationFingerprint());
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
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        simulateNextResponseFailure("/pa/v4/upgrade/confirm", 500);
        final ProtocolUpgradeResult result = startProtocolUpgradeExpectResult();

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

        // The activation status shows upgrade is completed
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertFalse(status.isProtocolUpgradeAvailable());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
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
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm", 3);
        final ProtocolUpgradeResult result = startProtocolUpgradeExpectResult();

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
        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        // Fail the upgrade confirm, and the following status to fail without trying more attempts.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/confirm");
        simulateNextResponseFailure("/pa/v4/activation/status", 500);
        final ProtocolUpgradeResult result = startProtocolUpgradeExpectResult();

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

        // Fetch status to complete the protocol upgrade
        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertFalse(powerAuthSDK.hasPendingProtocolUpgrade());
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());
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

        prepareActivationForUpgradeTest(getAlgorithmForTest(), 0);

        ProtocolUpgradeResult result;
        Throwable throwable;
        PowerAuthActivationStatus status;

        // The upgrade start request fails, keeping the application state as it was
        // before the upgrade attempt. Even after restart of the application.
        simulateNetworkErrorOnSend("/pa/v4/upgrade/start");
        throwable = startProtocolUpgradeExpectFailure();
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
        throwable = startProtocolUpgradeExpectFailure();
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
        result = startProtocolUpgradeExpectResult();
        assertNotNull(result);
        assertTrue(result.isActivationStatusFetchRequired());
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

    /**
     * Prepare an activation that uses {@link PowerAuthAlgorithm#LEGACY_P256} protocol
     * and is configured to support a future upgrade to the specified target algorithm.
     *
     * @param targetAlgorithm The algorithm to which this activation should be upgradable.
     * @param flags Flags that are forwarded to the {@link ActivationHelper#createStandardActivation(int, String)}.
     * @throws Exception In case of a failure.
     */
    private void prepareActivationForUpgradeTest(final @PowerAuthAlgorithm int targetAlgorithm, final int flags) throws Exception {
        // Protocol upgrade not available before calling a fetch activation status.
        assertFalse(powerAuthSDK.hasProtocolUpgradeAvailable());

        // Create activation
        final ActivationDetail activationDetail = activationHelper.createStandardActivation(flags, null);

        // Extract session data
        final byte[] sessionData = powerAuthSDK.getCoreSession().getSerializedState();

        // Reconfigure SDK to support target algorithm
        final PowerAuthConfiguration currentConfiguration = powerAuthSDK.getConfiguration();
        final PowerAuthConfiguration targetConfiguration = new PowerAuthConfiguration.Builder(currentConfiguration.getInstanceId(), currentConfiguration.getBaseEndpointUrl(), currentConfiguration.getConfiguration())
                .algorithm(targetAlgorithm)
                .build();
        powerAuthSDK = activationHelper.reCreateSdk(targetConfiguration);

        // Load the old V3 session
        powerAuthSDK.getCoreSession().deserializeState(sessionData);
        assertTrue(powerAuthSDK.hasValidActivation());
        assertEquals(activationDetail.getActivationId(), powerAuthSDK.getActivationIdentifier());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));

        // Activation now uses legacy protocol, but is configured to support tested algorithm
        assertEquals(PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.getCurrentAlgorithm());
        assertEquals(getAlgorithmForTest(), powerAuthSDK.getConfiguration().getAlgorithm());

        final PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
        assertTrue(status.isProtocolUpgradeAvailable());
        assertEquals(targetAlgorithm > PowerAuthAlgorithm.LEGACY_P256, powerAuthSDK.hasProtocolUpgradeAvailable());
    }

    /**
     * Start protocol upgrade and expect a failure.
     *
     * @return {@link Throwable} representing an expected error during protocol upgrade.
     * @throws Exception In case of unexpected error.
     */
    private Throwable startProtocolUpgradeExpectFailure() throws Exception {
        return AsyncHelper.await(resultCatcher ->
                powerAuthSDK.startProtocolUpgrade(testHelper.getContext(), activationHelper.getValidPassword(), new IProtocolUpgradeListener() {
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
     * Start protocol upgrade and expect valid {@link ProtocolUpgradeResult}.
     * If the {@link #getAlgorithmForTest()} is {@link PowerAuthAlgorithm#LEGACY_P256},
     * then the protocol upgrade request is not valid and {@code null} is returned.
     *
     * @return Valid protocol upgrade result for newer protocols and {@code null} for legacy protocol.
     * @throws Exception in case of upgrade process failure.
     */
    private ProtocolUpgradeResult startProtocolUpgradeExpectResult() throws Exception {
        return AsyncHelper.await(resultCatcher ->
                powerAuthSDK.startProtocolUpgrade(testHelper.getContext(), activationHelper.getValidPassword(), new IProtocolUpgradeListener() {
                    @Override
                    public void onProtocolUpgradeSucceed(@NonNull ProtocolUpgradeResult result) {
                        resultCatcher.completeWithResult(result);
                    }

                    @Override
                    public void onProtocolUpgradeFailed(@NonNull Throwable throwable) {
                        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                            assertTrue(throwable instanceof PowerAuthErrorException);
                            assertEquals("powerAuth::PowerAuthException: Protocol upgrade is not possible with current configuration", throwable.getMessage());
                            resultCatcher.completeWithResult(null);
                        } else {
                            resultCatcher.completeWithError(throwable);
                        }
                    }
                })
        );
    }

}
