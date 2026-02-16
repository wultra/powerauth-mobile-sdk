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

import io.getlime.security.powerauth.core.CoreProtocolVersion;
import io.getlime.security.powerauth.core.CoreSession;
import io.getlime.security.powerauth.core.CryptoUtils;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.networking.response.IOfflineAuthenticationCodeListener;
import io.getlime.security.powerauth.sdk.*;
import org.junit.Test;

import androidx.annotation.NonNull;

import static org.junit.Assert.*;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

public class EEKTests extends BaseTest {

    @Test
    public void testExternalEncryptionKeyDiscontinue() throws Exception {
        // Generate EEKs
        final SecureData goodEEK = CoreSession.generateFactorKekForProtocolVersion(CoreProtocolVersion.V3);
        final SecureData badEEK = CoreSession.generateFactorKekForProtocolVersion(CoreProtocolVersion.V4);
        // Before activation, EEK flag is always false.
        assertFalse(powerAuthSDK.hasExternalEncryptionKey());

        // Attempts to remove or add, should fail for all protocol versions
        try {
            powerAuthSDK.removeExternalEncryptionKey(goodEEK);
            fail();
        } catch (PowerAuthErrorException exception) {
            assertEquals(PowerAuthErrorCodes.MISSING_ACTIVATION, exception.getPowerAuthErrorCode());
        }
        try {
            powerAuthSDK.addExternalEncryptionKeyForTest(goodEEK);
            fail();
        } catch (PowerAuthErrorException exception) {
            assertEquals(PowerAuthErrorCodes.MISSING_ACTIVATION, exception.getPowerAuthErrorCode());
        }

        // Now create activation
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY, null);

        // By default, EEK is not set
        assertFalse(powerAuthSDK.hasExternalEncryptionKey());
        assertTrue(activationHelper.validateUserPassword(activationHelper.getValidPassword()));
        assertTrue(validateOfflineSignature(activationHelper.getValidAuthentication()));
        assertTrue(validateOfflineSignature(activationHelper.getBiometricAuthentication(null)));

        if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
            // V3 activations
            // Try to remove EEK first
            expectFail(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, () -> powerAuthSDK.removeExternalEncryptionKey(goodEEK));
            expectFail(PowerAuthErrorCodes.WRONG_PARAMETER, () -> powerAuthSDK.addExternalEncryptionKeyForTest(badEEK));
            // Try with good EEK
            powerAuthSDK.addExternalEncryptionKeyForTest(goodEEK);
            assertTrue(powerAuthSDK.hasExternalEncryptionKey());
            // validate signatures
            expectFail(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, () -> validateOnlineSignature(activationHelper.getValidAuthentication()));
            assertFalse(validateOfflineSignature(activationHelper.getValidAuthentication()));
            assertFalse(validateOfflineSignature(activationHelper.getBiometricAuthentication(null)));

            // simulate app restart
            powerAuthSDK = activationHelper.reCreateSdk();

            // validate EEK presence
            assertTrue(powerAuthSDK.hasExternalEncryptionKey());
            // validate signatures (should not work)
            expectFail(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, () -> validateOnlineSignature(activationHelper.getValidAuthentication()));
            assertFalse(validateOfflineSignature(activationHelper.getValidAuthentication()));
            assertFalse(validateOfflineSignature(activationHelper.getBiometricAuthentication(null)));

            // Try to remove wrong sized EEK
            expectFail(PowerAuthErrorCodes.WRONG_PARAMETER, () -> powerAuthSDK.removeExternalEncryptionKey(badEEK));
            assertTrue(powerAuthSDK.hasExternalEncryptionKey());
            // Try with good EEK
            powerAuthSDK.removeExternalEncryptionKey(goodEEK);

            // EEK is no longer present
            assertFalse(powerAuthSDK.hasExternalEncryptionKey());
            // And signatures should work
            assertTrue(validateOnlineSignature(activationHelper.getValidAuthentication()));
            assertTrue(validateOfflineSignature(activationHelper.getValidAuthentication()));
            assertTrue(validateOfflineSignature(activationHelper.getBiometricAuthentication(null)));

        } else {
            // V4 activations
            // All EEK related methods should fail
            expectFail(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, () -> powerAuthSDK.addExternalEncryptionKeyForTest(goodEEK));
            expectFail(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, () -> powerAuthSDK.removeExternalEncryptionKey(goodEEK));
        }
    }

    interface TestClosure {
        void test() throws Exception;
    }

    void expectFail(@PowerAuthErrorCodes int errorCode, TestClosure closure) {
        PowerAuthErrorException exception = assertThrows(PowerAuthErrorException.class, closure::test);
        assertEquals(errorCode, exception.getPowerAuthErrorCode());
    }

    boolean validateOnlineSignature(PowerAuthAuthentication authentication) throws Exception {
        final String uriId = "/test/online";
        final byte[] body = "HELLO".getBytes(StandardCharsets.UTF_8);
        final String method = "POST";
        PowerAuthHttpHeader header = powerAuthSDK.authenticationHeaderForRequestWithBody(authentication, method, uriId, body);
        AuthenticationResult result = authenticationHelper.verifyAuthenticationHeader(header, body, uriId, method);
        return result.isAuthenticationValid();
    }

    boolean validateOfflineSignature(PowerAuthAuthentication authentication) throws Exception {
        final boolean enableBiometry = authentication.useBiometricFactor();
        final String uriId = "/test/offline";
        final byte[] body = "HELLO".getBytes(StandardCharsets.UTF_8);
        final String nonce = Base64.encodeToString(CryptoUtils.randomBytes((16)), Base64.NO_WRAP);
        String authCode = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.offlineAuthenticationCode(testHelper.getContext(), authentication, uriId, body, nonce, new IOfflineAuthenticationCodeListener() {
                @Override
                public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                    resultCatcher.completeWithResult(authenticationCode);
                }

                @Override
                public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithResult(null);
                }
            });
        });
        if (authCode == null) {
            return false;
        }
        AuthenticationResult result = authenticationHelper.verifyAuthenticationCode(
                authCode,
                nonce,
                body,
                uriId,
                activationHelper.getActivation().getActivationId(),
                enableBiometry,
                null);
        return result.isAuthenticationValid();
    }
}
