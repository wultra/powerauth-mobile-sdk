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

import android.content.Context;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.networking.response.IOfflineAuthenticationCodeListener;
import io.getlime.security.powerauth.sdk.*;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;

import static org.junit.Assert.*;

public class AuthenticationCodeTest extends BaseTest {

    @Test
    public void testOfflineAuthCodeCalculation() throws Exception {

        final Context context = testHelper.getContext();

        activationHelper.createStandardActivation(true, null);

        // Possession + Knowledge factor
        PowerAuthAuthentication authentication = activationHelper.getValidAuthentication();
        for (int iteration = 0; iteration < 10; iteration++) {
            final String testString = "OFFLINE AuthCode test\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);
            final byte[] dataToSign = testString.getBytes(Charset.defaultCharset());
            final String nonce = testHelper.getRandomGenerator().generateBase64Bytes(16);
            final String offlineAuthCode = AsyncHelper.await((resultCatcher) -> {
                powerAuthSDK.offlineAuthenticationCode(context, authentication, "/offline/test", dataToSign, nonce, new IOfflineAuthenticationCodeListener() {
                    @Override
                    public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                        resultCatcher.completeWithResult(authenticationCode);
                    }

                    @Override
                    public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            assertNotNull(offlineAuthCode);

            // Now verify auth code on the server
            final String normalizedData = authenticationHelper.normalizeOfflineData(dataToSign, "/offline/test", nonce);
            AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
            authenticationCodeData.setActivationId(powerAuthSDK.getActivationIdentifier());
            authenticationCodeData.setData(normalizedData);
            authenticationCodeData.setAuthenticationCode(offlineAuthCode);
            authenticationCodeData.setAllowBiometry(false);

            // Verify on server
            final AuthenticationResult verifyResult = testHelper.getServerApi().verifyOfflineAuthenticationCode(authenticationCodeData);
            assertNotNull(verifyResult);
            assertTrue(verifyResult.isAuthenticationValid());
            assertEquals(AuthCodeType.POSSESSION_KNOWLEDGE, verifyResult.getAuthenticationCodeType());
        }
    }

    @Test
    public void testCustomOfflineAuthCodeCalculation() throws Exception {
        final int OFFLINE_AUTH_CODE_LENGTH = 4;
        // Re-configure test helper
        reAssingTestHelper(new PowerAuthTestHelper.Builder()
                .configurationObserver(new PowerAuthTestHelper.IConfigurationObserver() {
                    @Override
                    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
                        builder.offlineAuthenticationCodeComponentLength(OFFLINE_AUTH_CODE_LENGTH);
                    }

                    @Override
                    public void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder) {
                    }

                    @Override
                    public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
                    }

                    @Override
                    public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
                    }
                })
                .build()
        );

        // Create activation and test the auth code calculation
        activationHelper.createStandardActivation(true, null);

        final PowerAuthAuthentication authentication = PowerAuthAuthentication.possession();
        final String nonce = testHelper.getRandomGenerator().generateBase64Bytes(16);
        final String authCode = AsyncHelper.await((resultCatcher) -> {
            powerAuthSDK.offlineAuthenticationCode(testHelper.getContext(), authentication, "/some/uri-id", null, nonce, new IOfflineAuthenticationCodeListener() {

                @Override
                public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                    resultCatcher.completeWithResult(authenticationCode);
                }

                @Override
                public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithError(error);
                }
            });
        });
        assertNotNull(authCode);
        assertEquals(OFFLINE_AUTH_CODE_LENGTH, authCode.length());
    }

    @Test
    public void testOnlineAuthCodeCalculation() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY, null);

        // Count is important, due to fact that we have 8-bit local counter since V3.1
        for (int iteration = 0; iteration < 264; iteration++) {
            final String testString = "ONLINE AuthCode test\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);

            // Auth & expected result
            final PowerAuthAuthentication authentication;
            final AuthCodeType expectedAuthCodeType;
            final boolean expectedValidationResult;
            switch (iteration % 4) {
                case 0:
                    authentication = activationHelper.getValidAuthentication();
                    expectedAuthCodeType = AuthCodeType.POSSESSION_KNOWLEDGE;
                    expectedValidationResult = true;
                    break;
                case 1:
                    authentication = activationHelper.getPossessionAuthentication();
                    expectedAuthCodeType = AuthCodeType.POSSESSION;
                    expectedValidationResult = true;
                    break;
                case 2:
                    authentication = activationHelper.getBiometricAuthentication(null);
                    expectedAuthCodeType = AuthCodeType.POSSESSION_BIOMETRY;
                    expectedValidationResult = true;
                    break;
                default:
                    authentication = activationHelper.getInvalidAuthentication();
                    expectedAuthCodeType = AuthCodeType.POSSESSION_KNOWLEDGE;
                    expectedValidationResult = false;
                    break;
            }

            // URI identifier
            final String uriId;
            if ((iteration % 3) == 0) {
                uriId = "/test/online/post";
            } else if ((iteration % 3) == 1) {
                uriId = "/other/uriId";
            } else {
                uriId = "/last/test/variant";
            }

            // Method
            final String method = (iteration & 1) == 0 ? "POST" : "GET";

            //System.out.println("Iteration " + iteration + ": " + expectedAuthCodeType + ", " + method);

            final byte[] dataToSign = testString.getBytes(Charset.defaultCharset());
            final PowerAuthHttpHeader onlineHeader = powerAuthSDK.authenticationHeaderForRequestWithBody(authentication, method, uriId, dataToSign);
            assertNotNull(onlineHeader);
            assertEquals("X-PowerAuth-Authorization", onlineHeader.getKey());

            // Verify on server
            final AuthenticationResult verifyResult = authenticationHelper.verifyAuthenticationHeader(onlineHeader, dataToSign, uriId, method);

            assertNotNull(verifyResult);
            assertEquals(expectedValidationResult, verifyResult.isAuthenticationValid());
            assertEquals(expectedAuthCodeType, verifyResult.getAuthenticationCodeType());

            if ((iteration & 0x3f) == 1) {
                PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
                assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
            }

            if (iteration == 58 || iteration == 129 || iteration == 251) {
                // simulate app restart at some points
                powerAuthSDK = activationHelper.reCreateSdk();
            }
        }
    }


    /**
     * Counter look ahead set by default on server.
     */
    static final int CTR_LOOKAHEAD = 20;

    @Test
    public void testClientCounterIsAhead() throws Exception {
        activationHelper.createStandardActivation(false, null);

        PowerAuthAuthentication auth = activationHelper.getValidAuthentication();
        PowerAuthActivationStatus status;
        // Positive scenario, we should recover from it
        for (int i = 0; i < CTR_LOOKAHEAD + 2; ++i) {
            // calculate header and do not use it
            powerAuthSDK.authenticationHeaderForRequestWithBody(auth, "POST", "/some/identifier", null);
            if ((i % 4) == 0) {
                // Every 4th auth code calculation try to get the status
                status = activationHelper.fetchActivationStatus();
                assertEquals(PowerAuthActivationState.ACTIVE, status.getState());
            }

        }
        // fetch status at the end
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        // Negative scenario, try to calculate too many auth code that server will never catch.
        for (int i = 0; i < CTR_LOOKAHEAD + 2; ++i) {
            // calculate header and do not use it
            powerAuthSDK.authenticationHeaderForRequestWithBody(auth, "POST", "/some/identifier", null);
        }
        // fetch status at the end
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.DEADLOCK, status.getState());
    }

    @Test
    public void testServerCounterIsAhead() throws Exception {
        activationHelper.createStandardActivation(false, null);

        byte[] dataToAuth = "Hello world!".getBytes(StandardCharsets.UTF_8);

        PowerAuthAuthentication auth = activationHelper.getValidAuthentication();
        PowerAuthActivationStatus status;
        final Context context = testHelper.getContext();
        final String uriId = "/test/id";
        final String offlineNonce = "QVZlcnlDbGV2ZXJOb25jZQ==";

        // Just calculate auth code on the server.
        // This is a little bit tricky, because we need to calculate a valid auth code, to move server's counter forward. To do that,
        // we have to calculate also a local auth code, but that moves also local counter forward.
        // To trick the system, we need to keep old persistent data and restore it later.
        byte[] previousState = powerAuthSDK.getCoreSession().getSerializedState();
        for (int i = 0; i < CTR_LOOKAHEAD/2; ++i) {
            String localAuthCode = AsyncHelper.await(resultCatcher -> {
                powerAuthSDK.offlineAuthenticationCode(context, auth, uriId, dataToAuth, offlineNonce, new IOfflineAuthenticationCodeListener() {
                    @Override
                    public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                        resultCatcher.completeWithResult(authenticationCode);
                    }

                    @Override
                    public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            // Verify on server
            final AuthenticationResult verifyResult = authenticationHelper.verifyAuthenticationCode(
                    localAuthCode,
                    offlineNonce,
                    dataToAuth,
                    uriId,
                    activationHelper.getActivation().getActivationId(),
                    false,
                    null);
            assertNotNull(verifyResult);
        }
        // Rollback counter to some previous state, to simulate state when the server's counter is ahead
        powerAuthSDK.getCoreSession().deserializeState(previousState);
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        // negative scenario

        previousState = powerAuthSDK.getCoreSession().getSerializedState();
        for (int i = 0; i < CTR_LOOKAHEAD + 2; ++i) {
            String localAuthCode = AsyncHelper.await(resultCatcher -> {
                powerAuthSDK.offlineAuthenticationCode(context, auth, uriId, dataToAuth, offlineNonce, new IOfflineAuthenticationCodeListener() {
                    @Override
                    public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                        resultCatcher.completeWithResult(authenticationCode);
                    }

                    @Override
                    public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            // Verify on server
            final AuthenticationResult verifyResult = authenticationHelper.verifyAuthenticationCode(
                    localAuthCode,
                    offlineNonce,
                    dataToAuth,
                    uriId,
                    activationHelper.getActivation().getActivationId(),
                    false,
                    null);
            assertNotNull(verifyResult);
        }
        // Rollback counter to some previous state, to simulate state when the server's counter is ahead
        powerAuthSDK.getCoreSession().deserializeState(previousState);
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.DEADLOCK, status.getState());
    }
}
