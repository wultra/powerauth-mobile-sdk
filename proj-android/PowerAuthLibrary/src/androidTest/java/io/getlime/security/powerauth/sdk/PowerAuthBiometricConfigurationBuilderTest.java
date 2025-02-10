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

package io.getlime.security.powerauth.sdk;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class PowerAuthBiometricConfigurationBuilderTest {

    @Test
    public void testDefaultParameters() {
        PowerAuthBiometricConfiguration configuration = new PowerAuthBiometricConfiguration.Builder()
                .build();
        assertFalse(configuration.isConfirmBiometricAuthentication());
        assertTrue(configuration.isInvalidateBiometricFactorAfterChange());
        assertTrue(configuration.isAuthenticateOnBiometricKeySetup());
        assertTrue(configuration.isFallbackToSharedBiometryKeyEnabled());
    }

    @Test
    public void testCustomParameters() {
        for (int i = 1; i <= 4; i++) {
            final boolean isConfirmBiometricAuthentication = i == 1;
            final boolean isInvalidateBiometricFactorAfterChange = i == 2;
            final boolean isAuthenticateOnBiometricKeySetup = i == 3;
            final boolean isFallbackToSharedBiometryKeyEnabled = i == 4;
            PowerAuthBiometricConfiguration configuration = new PowerAuthBiometricConfiguration.Builder()
                    .confirmBiometricAuthentication(isConfirmBiometricAuthentication)
                    .invalidateBiometricFactorAfterChange(isInvalidateBiometricFactorAfterChange)
                    .authenticateOnBiometricKeySetup(isAuthenticateOnBiometricKeySetup)
                    .enableFallbackToSharedBiometryKey(isFallbackToSharedBiometryKeyEnabled)
                    .build();
            assertEquals(isConfirmBiometricAuthentication, configuration.isConfirmBiometricAuthentication());
            assertEquals(isInvalidateBiometricFactorAfterChange, configuration.isInvalidateBiometricFactorAfterChange());
            assertEquals(isAuthenticateOnBiometricKeySetup, configuration.isAuthenticateOnBiometricKeySetup());
            assertEquals(isFallbackToSharedBiometryKeyEnabled, configuration.isFallbackToSharedBiometryKeyEnabled());
        }
        for (int i = 1; i <= 4; i++) {
            final boolean isConfirmBiometricAuthentication = i != 1;
            final boolean isInvalidateBiometricFactorAfterChange = i != 2;
            final boolean isAuthenticateOnBiometricKeySetup = i != 3;
            final boolean isFallbackToSharedBiometryKeyEnabled = i != 4;
            PowerAuthBiometricConfiguration configuration = new PowerAuthBiometricConfiguration.Builder()
                    .confirmBiometricAuthentication(isConfirmBiometricAuthentication)
                    .invalidateBiometricFactorAfterChange(isInvalidateBiometricFactorAfterChange)
                    .authenticateOnBiometricKeySetup(isAuthenticateOnBiometricKeySetup)
                    .enableFallbackToSharedBiometryKey(isFallbackToSharedBiometryKeyEnabled)
                    .build();
            assertEquals(isConfirmBiometricAuthentication, configuration.isConfirmBiometricAuthentication());
            assertEquals(isInvalidateBiometricFactorAfterChange, configuration.isInvalidateBiometricFactorAfterChange());
            assertEquals(isAuthenticateOnBiometricKeySetup, configuration.isAuthenticateOnBiometricKeySetup());
            assertEquals(isFallbackToSharedBiometryKeyEnabled, configuration.isFallbackToSharedBiometryKeyEnabled());
        }
    }
}
