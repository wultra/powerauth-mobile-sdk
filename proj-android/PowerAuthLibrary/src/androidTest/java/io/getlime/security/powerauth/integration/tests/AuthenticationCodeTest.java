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
import io.getlime.security.powerauth.networking.response.IOfflineAuthorizationCodeListener;
import io.getlime.security.powerauth.sdk.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.charset.Charset;
import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class AuthenticationCodeTest {

    @Parameterized.Parameter(0) public String alg;
    @Parameterized.Parameters(name = " {0} ")
    public static Iterable<Object[]> testParameters() {
        return CommonTestParameters.getParameters();
    }

    @PowerAuthAlgorithm
    public int getAlgorithmForTest() {
        return PowerAuthTestHelper.getAlgorithmForName(alg);
    }

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;
    private SignatureHelper signatureHelper;

    @Before
    public void setUp() throws Exception {
        testHelper = new PowerAuthTestHelper.Builder()
                .powerAuthAlgorithm(getAlgorithmForTest())
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
        signatureHelper = new SignatureHelper();
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
    }


    @Test
    public void testOfflineSignatureCalculation() throws Exception {

        final Context context = testHelper.getContext();

        activationHelper.createStandardActivation(true, null);

        // Possession + Knowledge factor
        PowerAuthAuthentication authentication = activationHelper.getValidAuthentication();
        for (int iteration = 0; iteration < 10; iteration++) {
            final String testString = "OFFLINE signature test\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);
            final byte[] dataToSign = testString.getBytes(Charset.defaultCharset());
            final String nonce = testHelper.getRandomGenerator().generateBase64Bytes(16);
            final String offlineAuthCode = AsyncHelper.await((resultCatcher) -> {
                powerAuthSDK.offlineAuthorizationCode(context, authentication, "/offline/test", dataToSign, nonce, new IOfflineAuthorizationCodeListener() {
                    @Override
                    public void onOfflineAuthorizationCodeSucceed(@NonNull String authorizationCode) {
                        resultCatcher.completeWithResult(authorizationCode);
                    }

                    @Override
                    public void onOfflineAuthorizationCodeFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            assertNotNull(offlineAuthCode);

            // Now verify signature on the server
            final String dataToVerifySignature = signatureHelper.normalizeOfflineData(testString, "/offline/test", nonce);
            AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
            authenticationCodeData.setActivationId(powerAuthSDK.getActivationIdentifier());
            authenticationCodeData.setData(dataToVerifySignature);
            authenticationCodeData.setAuthenticationCode(offlineAuthCode);
            authenticationCodeData.setAllowBiometry(false);

            // Verify on server
            final AuthenticationResult verifyResult = testHelper.getServerApi().verifyOfflineAuthenticationCode(authenticationCodeData);
            assertNotNull(verifyResult);
            assertTrue(verifyResult.isSignatureValid());
            assertEquals(AuthCodeType.POSSESSION_KNOWLEDGE, verifyResult.getSignatureType());
        }
    }

    @Test
    public void testCustomOfflineSignatureCalculation() throws Exception {
        final int OFFLINE_SIGNATURE_LENGTH = 4;
        // Re-configure test helper
        testHelper = new PowerAuthTestHelper.Builder()
                .configurationObserver(new PowerAuthTestHelper.IConfigurationObserver() {
                    @Override
                    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
                        builder.offlineAuthorizationCodeComponentLength(OFFLINE_SIGNATURE_LENGTH);
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
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);

        // Create activation and test the signature calculation
        activationHelper.createStandardActivation(true, null);

        final PowerAuthAuthentication authentication = PowerAuthAuthentication.possession();
        final String nonce = testHelper.getRandomGenerator().generateBase64Bytes(16);
        final String authCode = AsyncHelper.await((resultCatcher) -> {
            powerAuthSDK.offlineAuthorizationCode(testHelper.getContext(), authentication, "/some/uri-id", null, nonce, new IOfflineAuthorizationCodeListener() {

                @Override
                public void onOfflineAuthorizationCodeSucceed(@NonNull String authorizationCode) {
                    resultCatcher.completeWithResult(authorizationCode);
                }

                @Override
                public void onOfflineAuthorizationCodeFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithError(error);
                }
            });
        });
        assertNotNull(authCode);
        assertEquals(OFFLINE_SIGNATURE_LENGTH, authCode.length());
    }

    @Test
    public void testOnlineSignatureCalculation() throws Exception {
        final Context context = testHelper.getContext();

        activationHelper.createStandardActivation(true, null);

        for (int iteration = 0; iteration < 33; iteration++) {

            final String testString = "ONLINE signature test\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);

            // Auth & expected result
            final PowerAuthAuthentication authentication;
            final AuthCodeType expectedSignatureType;
            final boolean expectedValidationResult;
            if ((iteration % 3) == 0) {
                authentication = activationHelper.getValidAuthentication();
                expectedSignatureType = AuthCodeType.POSSESSION_KNOWLEDGE;
                expectedValidationResult = true;
            } else if ((iteration % 3) == 1){
                authentication = activationHelper.getPossessionAuthentication();
                expectedSignatureType = AuthCodeType.POSSESSION;
                expectedValidationResult = true;
            } else {
                authentication = activationHelper.getInvalidAuthentication();
                expectedSignatureType = AuthCodeType.POSSESSION_KNOWLEDGE;
                expectedValidationResult = false;
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

            final byte[] dataToSign = testString.getBytes(Charset.defaultCharset());
            final PowerAuthAuthorizationHttpHeader onlineSignature = powerAuthSDK.authorizationHeaderForRequestWithBody(context, authentication, method, uriId, dataToSign);
            assertNotNull(onlineSignature);
            assertEquals("X-PowerAuth-Authorization", onlineSignature.getKey());

            // Parse header value
            Map<String, String> sigComponents = signatureHelper.parseAuthorizationHeader(onlineSignature);

            final String sigVersion = sigComponents.get("pa_version");
            final String sigActivationId = sigComponents.get("pa_activation_id");
            final String sigNonce = sigComponents.get("pa_nonce");
            final String sigAppKey = sigComponents.get("pa_application_key");
            final String sigType = Objects.requireNonNull(sigComponents.get("pa_signature_type")).toUpperCase();
            final String sigValue = sigComponents.get("pa_signature");

            assertEquals(testHelper.getProtocolVersionForHeader(), sigVersion);
            assertNotNull(sigActivationId);
            assertNotNull(sigNonce);
            assertNotNull(sigAppKey);
            assertNotNull(sigType);
            assertNotNull(sigValue);

            // Now verify signature on the server
            final String dataToVerifySignature = signatureHelper.normalizeOnlineData(dataToSign, method, uriId, sigNonce);
            AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
            authenticationCodeData.setActivationId(sigActivationId);
            authenticationCodeData.setData(dataToVerifySignature);
            authenticationCodeData.setAuthenticationCode(sigValue);
            authenticationCodeData.setAuthenticationCodeType(AuthCodeType.valueOf(sigType));
            authenticationCodeData.setAuthenticationVersion(sigVersion);
            authenticationCodeData.setApplicationKey(sigAppKey);

            // Verify on server
            final AuthenticationResult verifyResult = testHelper.getServerApi().verifyOnlineAuthenticationCode(authenticationCodeData);

            assertNotNull(verifyResult);
            assertEquals(expectedValidationResult, verifyResult.isSignatureValid());
            assertEquals(expectedSignatureType, verifyResult.getSignatureType());
        }
    }
}
