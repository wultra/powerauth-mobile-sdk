/*
 * Copyright 2022 Wultra s.r.o.
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

import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.integration.support.RandomGenerator;
import io.getlime.security.powerauth.system.PowerAuthLog;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthAuthenticationTests {

    final RandomGenerator randomGenerator;
    final byte[] customPossessionKey;
    final byte[] biometryKey;
    final String password;

    public PowerAuthAuthenticationTests() {
        this.randomGenerator = new RandomGenerator();
        this.customPossessionKey = randomGenerator.generateBytes(16);
        this.biometryKey = randomGenerator.generateBytes(16);
        this.password = "1234";

        PowerAuthLog.setEnabled(true);
    }

    @Test
    public void testCommitWithPassword() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.commitWithPassword(password);
        assertTrue(authentication.validateAuthenticationUsage(true));
        assertEquals(password, authentication.getPassword());

        authentication = PowerAuthAuthentication.commitWithPassword(password, customPossessionKey);
        assertTrue(authentication.validateAuthenticationUsage(true));
        assertEquals(password, authentication.getPassword());
        assertArrayEquals(customPossessionKey, authentication.getOverriddenPossessionKey());
    }

    @Test
    public void testCommitWithPasswordAndBiometry() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.commitWithPasswordAndBiometry(password, biometryKey);
        assertTrue(authentication.validateAuthenticationUsage(true));
        assertEquals(password, authentication.getPassword());
        assertArrayEquals(biometryKey, authentication.getBiometryFactorRelatedKey());

        authentication = PowerAuthAuthentication.commitWithPasswordAndBiometry(password, biometryKey, customPossessionKey);
        assertTrue(authentication.validateAuthenticationUsage(true));
        assertEquals(password, authentication.getPassword());
        assertArrayEquals(biometryKey, authentication.getBiometryFactorRelatedKey());
        assertArrayEquals(customPossessionKey, authentication.getOverriddenPossessionKey());
    }

    @Test
    public void testPossessionOnly() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possession();
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertEquals(1, authentication.getSignatureFactorsMask());
        
        authentication = PowerAuthAuthentication.possession(customPossessionKey);
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertArrayEquals(customPossessionKey, authentication.getOverriddenPossessionKey());
        assertEquals(1, authentication.getSignatureFactorsMask());
    }

    @Test
    public void testPossessionWithPassword() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword(password);
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertEquals(password, authentication.getPassword());
        assertEquals(1 + 2, authentication.getSignatureFactorsMask());

        authentication = PowerAuthAuthentication.possessionWithPassword(password, customPossessionKey);
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertEquals(password, authentication.getPassword());
        assertArrayEquals(customPossessionKey, authentication.getOverriddenPossessionKey());
        assertEquals(1 + 2, authentication.getSignatureFactorsMask());
    }

    @Test
    public void testPossessionWithBiometry() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithBiometry(biometryKey);
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertArrayEquals(biometryKey, authentication.getBiometryFactorRelatedKey());
        assertEquals(1 + 4, authentication.getSignatureFactorsMask());

        authentication = PowerAuthAuthentication.possessionWithBiometry(biometryKey, customPossessionKey);
        assertTrue(authentication.validateAuthenticationUsage(false));
        assertArrayEquals(biometryKey, authentication.getBiometryFactorRelatedKey());
        assertArrayEquals(customPossessionKey, authentication.getOverriddenPossessionKey());
        assertEquals(1 + 4, authentication.getSignatureFactorsMask());
    }

    @Test
    public void testLegacyObjectConstructor() throws Exception {
        PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        assertFalse(authentication.validateAuthenticationUsage(false));
        assertFalse(authentication.validateAuthenticationUsage(true));
    }
}
