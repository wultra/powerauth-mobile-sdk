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

import org.junit.Test;

import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.IFetchEncryptionKeyListener;
import io.getlime.security.powerauth.networking.response.IFetchSecureVaultKeyListener;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthSecureVaultKey;
import io.getlime.security.powerauth.sdk.PowerAuthSecureVaultKeyId;

import static org.junit.Assert.*;

public class SecureVaultKeyTest extends BaseTest {

    @Test
    public void testVaultEncryptionKeys() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_FAKE_BIOMETRY, null);
        PowerAuthAuthentication validKnowledge = activationHelper.getValidAuthentication();
        PowerAuthAuthentication validBiometry = activationHelper.getBiometricAuthentication(null);
        PowerAuthSecureVaultKey any2fa, knowledge, otherKDK;
        SecureData legacy, other, another;
        if (getCurrentAlgorithm() != PowerAuthAlgorithm.LEGACY_P256) {
            // V4
            any2fa = fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE_OR_BIOMETRY, validKnowledge, true);
            otherKDK = fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE_OR_BIOMETRY, validKnowledge, true);
            assertEquals(any2fa, otherKDK);
            otherKDK = fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE_OR_BIOMETRY, validBiometry, true);
            assertEquals(any2fa, otherKDK);
            knowledge = fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE, validKnowledge, true);
            assertNotEquals(any2fa, knowledge);
            otherKDK = fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE, validKnowledge, true);
            assertEquals(knowledge, otherKDK);

            // derive other keys
            other = any2fa.deriveKey(1000, 32);
            assertEquals(32, other.length());
            another = any2fa.deriveKey(1000, 32);
            assertEquals(another, other);

            other = knowledge.deriveKey(1000, 32);
            assertEquals(32, other.length());
            another = knowledge.deriveKey(1000, 32);
            assertEquals(other, another);

            another = knowledge.deriveKey(1000, 16);
            assertEquals(16, another.length());
            assertNotEquals(other, another);

            // Following fetch operations should fail
            fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE, validBiometry, false);
            fetchLegacyVaultKey(validKnowledge, 500, false);
            fetchLegacyVaultKey(validBiometry, 1000, false);
            // Min size is 16
            try {
                knowledge.deriveKey(1000, 8);
                fail("Previous statement should fail");
            } catch (PowerAuthErrorException e) {
                assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, e.getPowerAuthErrorCode());
            }
        } else {
            // V3
            legacy = fetchLegacyVaultKey(validKnowledge, 10, true);
            assertEquals(16, legacy.length());
            other = fetchLegacyVaultKey(validKnowledge, 10, true);
            assertEquals(legacy, other);
            // Following fetch operations should fail
            fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE, validKnowledge, false);
            fetchVaultEncryptionKey(PowerAuthSecureVaultKeyId.KNOWLEDGE_OR_BIOMETRY, validKnowledge, false);
            fetchLegacyVaultKey(validBiometry, 10, false);
        }
    }

    // Helper functions

    PowerAuthSecureVaultKey fetchVaultEncryptionKey(@PowerAuthSecureVaultKeyId int keyId,
                                                    PowerAuthAuthentication authentication,
                                                    boolean shouldPass) throws Exception {
        PowerAuthSecureVaultKey result = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.fetchSecureVaultKey(testHelper.getContext(), authentication, keyId, new IFetchSecureVaultKeyListener() {
                @Override
                public void onFetchSecureVaultKeySucceed(@NonNull PowerAuthSecureVaultKey vaultKey) {
                    resultCatcher.completeWithResult(vaultKey);
                }

                @Override
                public void onFetchSecureVaultKeyFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithResult(null);
                }
            });
            if (shouldPass) {
                assertNotNull(task);
            }
        });
        if (shouldPass) {
            assertNotNull(result);
        } else {
            assertNull(result);
        }
        return result;
    }

    SecureData fetchLegacyVaultKey(PowerAuthAuthentication authentication,
                                   long derivationIndex,
                                   boolean shouldPass) throws Exception {
        SecureData result = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.fetchEncryptionKey(testHelper.getContext(), authentication, derivationIndex, new IFetchEncryptionKeyListener() {
                @Override
                public void onFetchEncryptionKeySucceed(@NonNull SecureData encryptionKey) {
                    resultCatcher.completeWithResult(encryptionKey);
                }

                @Override
                public void onFetchEncryptionKeyFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(null);
                }
            });
            if (shouldPass) {
                assertNotNull(task);
            }
        });
        if (shouldPass) {
            assertNotNull(result);
        } else {
            assertNull(result);
        }
        return result;
    }
}
