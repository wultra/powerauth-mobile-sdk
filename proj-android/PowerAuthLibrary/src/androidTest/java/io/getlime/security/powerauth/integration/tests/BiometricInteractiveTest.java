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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.junit.Ignore;
import org.junit.Test;

import io.getlime.security.powerauth.biometry.IAddBiometryFactorListener;
import io.getlime.security.powerauth.biometry.IAuthenticateWithBiometricsListener;
import io.getlime.security.powerauth.biometry.IRemoveBiometryFactorListener;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthBiometricConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthBiometricPrompt;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthHttpHeader;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;

import static org.junit.Assert.*;

@Ignore("Comment when you ready for interactive tests")
public class BiometricInteractiveTest extends FragmentActivityBaseTest {
    @Test
    public void testHmacAuthentication() throws Exception {
        assertBiometryEnrolled();
        runWithFragmentActivity(getHmacConfig(), this::doStandardTest);
    }

    @Test
    public void testAesAuthentication() throws Exception {
        assertBiometryEnrolled();
        runWithFragmentActivity(getAesConfig(), this::doStandardTest);
    }

    @Test
    public void testRsaAuthentication() throws Exception {
        assertBiometryEnrolled();
        runWithFragmentActivity(getRsaConfig(), this::doStandardTest);
    }

    @Test
    public void testMigrateFromAesToHmac() throws Exception {
        assertBiometryEnrolled();
        runWithFragmentActivity(getAesConfig(), () -> {
            activationHelper.createStandardActivation(false, null);
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
            addBiometricFactor();
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

            doSingleAuthentication("Authenticate with legacy AES");

            // Now reconfigure SDK
            powerAuthSDK = testHelper.reCreateSdk(
                    null,
                    new PowerAuthBiometricConfiguration.Builder()
                            .useLegacySymmetricKey(false)
                            .build(),
                    null,
                    null);
            activationHelper = new ActivationHelper(testHelper, activationHelper.getHelperState());
            authenticationHelper = new AuthenticationHelper(testHelper);

            doSingleAuthentication("Authenticate with legacy AES with new config");

            removeBiometricFactor();
            assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

            addBiometricFactor();
            assertTrue(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));

            doSingleAuthentication("Authenticate with HMAC");
        });
    }

    void doStandardTest() throws Exception {
        activationHelper.createStandardActivation(false, null);
        assertFalse(powerAuthSDK.hasBiometryFactor(testHelper.getContext()));
        // Add biometric factor
        addBiometricFactor();
        // Authenticate
        doSingleAuthentication(null);
    }

    void doSingleAuthentication(@Nullable String authReason) throws Exception {
        if (authReason == null) {
            authReason = "Sign data";
        }
        final byte[] data = "HELLO".getBytes();
        final String uriId = "/test/uri";
        final String method = "POST";
        PowerAuthAuthentication authentication = authenticateWithBiometry(authReason);
        PowerAuthHttpHeader header =  powerAuthSDK.authenticationHeaderForRequestWithBody(authentication, method, uriId, data);
        AuthenticationResult result = authenticationHelper.verifyAuthenticationHeader(header, data, uriId, method);
        assertTrue(result.isAuthenticationValid());
    }

    void addBiometricFactor() throws Exception {
        // Add biometric factor
        AsyncHelper.awaitForMainThread(resultCatcher -> {
            PowerAuthBiometricPrompt prompt = PowerAuthBiometricPrompt.prompt(testHelper.getFragmentActivity(), "Authenticate", "Authenticate to configure biometry");
            powerAuthSDK.addBiometryFactor(testHelper.getContext(), activationHelper.getValidPassword(), prompt, new IAddBiometryFactorListener() {
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
        // Wait for prompt disappear
        Thread.sleep(500);
    }

    void removeBiometricFactor() throws Exception {
        AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.removeBiometryFactor(testHelper.getContext(), new IRemoveBiometryFactorListener() {
                @Override
                public void onRemoveBiometryFactorSucceed() {
                    resultCatcher.completeWithSuccess();
                }

                @Override
                public void onRemoveBiometryFactorFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithError(throwable);
                }
            });
        });
    }

    @NonNull
    PowerAuthAuthentication authenticateWithBiometry(@NonNull String reason) throws Exception {
         PowerAuthAuthentication authentication = AsyncHelper.awaitForMainThread(resultCatcher -> {
            PowerAuthBiometricPrompt prompt = PowerAuthBiometricPrompt.prompt(testHelper.getFragmentActivity(), "Authenticate", reason);
            powerAuthSDK.authenticateUsingBiometrics(testHelper.getContext(), prompt, new IAuthenticateWithBiometricsListener() {
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
            });
        });
        assertNotNull(authentication);
        Thread.sleep(500);
        return authentication;
    }

    /**
     * @return Configuration observer that changes biometric configuration to use HMAC KDF.
     */
    PowerAuthTestHelper.IConfigurationObserver getHmacConfig() {
        return new PowerAuthTestHelper.IConfigurationObserver() {
            @Override
            public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
            }

            @Override
            public void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder) {
                builder.authenticateOnBiometricKeySetup(true);
                builder.useLegacySymmetricKey(false);
            }

            @Override
            public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
            }

            @Override
            public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
            }
        };
    }

    /**
     * @return Configuration observer that changes biometric configuration to use AES KDF.
     */
    PowerAuthTestHelper.IConfigurationObserver getAesConfig() {
        return new PowerAuthTestHelper.IConfigurationObserver() {
            @Override
            public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
            }

            @Override
            public void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder) {
                builder.authenticateOnBiometricKeySetup(true);
                builder.useLegacySymmetricKey(true);
            }

            @Override
            public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
            }

            @Override
            public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
            }
        };
    }

    /**
     * @return Configuration observer that changes biometric configuration to use RSA for key protection.
     */
    PowerAuthTestHelper.IConfigurationObserver getRsaConfig() {
        return new PowerAuthTestHelper.IConfigurationObserver() {
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
        };
    }
}
