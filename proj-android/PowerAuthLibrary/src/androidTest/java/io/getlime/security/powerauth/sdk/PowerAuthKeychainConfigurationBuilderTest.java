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

package io.getlime.security.powerauth.sdk;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import io.getlime.security.powerauth.keychain.KeychainProtection;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthKeychainConfigurationBuilderTest {

    @Test
    public void testDefaultParameters() throws Exception {
        PowerAuthKeychainConfiguration configuration = new PowerAuthKeychainConfiguration.Builder()
                .build();
        assertEquals(PowerAuthKeychainConfiguration.KEYCHAIN_ID_BIOMETRY, configuration.getKeychainBiometryId());
        assertEquals(PowerAuthKeychainConfiguration.KEYCHAIN_ID_STATUS, configuration.getKeychainStatusId());
        assertEquals(PowerAuthKeychainConfiguration.KEYCHAIN_ID_TOKEN_STORE, configuration.getKeychainTokenStoreId());
        assertEquals(PowerAuthKeychainConfiguration.KEYCHAIN_KEY_BIOMETRY_DEFAULT, configuration.getKeychainBiometryDefaultKey());
        assertEquals(KeychainProtection.NONE, configuration.getMinimalRequiredKeychainProtection());
        assertFalse(configuration.isConfirmBiometricAuthentication());
        assertTrue(configuration.isLinkBiometricItemsToCurrentSet());
        assertTrue(configuration.isAuthenticateOnBiometricKeySetup());
    }

    @Test
    public void testCustomParameters() throws Exception {
        PowerAuthKeychainConfiguration configuration = new PowerAuthKeychainConfiguration.Builder()
                .confirmBiometricAuthentication(true)
                .linkBiometricItemsToCurrentSet(false)
                .keychainBiometryId("keychain.biometry")
                .keychainStatusId("keychain.status")
                .keychainTokenStoreId("keychain.tokens")
                .keychainBiometryDefaultKey("biometryKey")
                .minimalRequiredKeychainProtection(KeychainProtection.HARDWARE)
                .authenticateOnBiometricKeySetup(false)
                .build();
        assertEquals("keychain.biometry", configuration.getKeychainBiometryId());
        assertEquals("keychain.status", configuration.getKeychainStatusId());
        assertEquals("keychain.tokens", configuration.getKeychainTokenStoreId());
        assertEquals("biometryKey", configuration.getKeychainBiometryDefaultKey());
        assertEquals(KeychainProtection.HARDWARE, configuration.getMinimalRequiredKeychainProtection());
        assertTrue(configuration.isConfirmBiometricAuthentication());
        assertFalse(configuration.isLinkBiometricItemsToCurrentSet());
        assertFalse(configuration.isAuthenticateOnBiometricKeySetup());
    }
}
