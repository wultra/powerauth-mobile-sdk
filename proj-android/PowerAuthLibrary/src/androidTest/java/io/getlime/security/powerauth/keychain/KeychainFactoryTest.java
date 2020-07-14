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

package io.getlime.security.powerauth.keychain;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class KeychainFactoryTest {

    private Context androidContext;

    private static final String KEYCHAIN_1_NAME = "com.wultra.test.keychain1";
    private static final String KEYCHAIN_2_NAME = "com.wultra.test.keychain2";

    @Before
    public void setUp() {
        androidContext = InstrumentationRegistry.getInstrumentation().getContext();
        assertNotNull(androidContext);
    }

    @Test
    public void testCachedKeychains() throws Exception {
        final Keychain keychain1_a = KeychainFactory.getKeychain(androidContext, KEYCHAIN_1_NAME, KeychainProtection.NONE);
        final Keychain keychain1_b = KeychainFactory.getKeychain(androidContext, KEYCHAIN_1_NAME, KeychainProtection.NONE);
        assertEquals(keychain1_a, keychain1_b);
        final Keychain keychain2_a = KeychainFactory.getKeychain(androidContext, KEYCHAIN_2_NAME, KeychainProtection.NONE);
        final Keychain keychain2_b = KeychainFactory.getKeychain(androidContext, KEYCHAIN_2_NAME, KeychainProtection.NONE);
        assertEquals(keychain2_a, keychain2_b);
    }

    @Test
    public void testMaximumKeychainProtection() throws Exception {
        final @KeychainProtection int currentProtection = KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext);
        if (currentProtection == KeychainProtection.STRONGBOX) {
            // Nothing to do in this test, when the device supports maximum keychain protection.
            return;
        }
        try {
            final Keychain keychain = KeychainFactory.getKeychain(androidContext, KEYCHAIN_2_NAME, KeychainProtection.STRONGBOX);
            fail();
        } catch (PowerAuthErrorException e) {
            assertEquals(PowerAuthErrorCodes.PA2ErrorCodeInsufficientKeychainProtection, e.getPowerAuthErrorCode());
        }
    }
}
