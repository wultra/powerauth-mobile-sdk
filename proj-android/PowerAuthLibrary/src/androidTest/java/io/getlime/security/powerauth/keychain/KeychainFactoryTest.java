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

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

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
        eraseAllKeychainData(KEYCHAIN_1_NAME);
        eraseAllKeychainData(KEYCHAIN_2_NAME);
    }

    @Test
    public void testCachedKeychains() throws Exception {
        final Keychain keychain1_a = KeychainFactory.getKeychain(androidContext, KEYCHAIN_1_NAME, KeychainProtection.NONE);
        final Keychain keychain2_a = KeychainFactory.getKeychain(androidContext, KEYCHAIN_2_NAME, KeychainProtection.NONE);
        final Keychain keychain1_b = KeychainFactory.getKeychain(androidContext, KEYCHAIN_1_NAME, KeychainProtection.NONE);
        final Keychain keychain2_b = KeychainFactory.getKeychain(androidContext, KEYCHAIN_2_NAME, KeychainProtection.NONE);
        assertEquals(keychain1_a, keychain1_b);
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
            assertEquals(PowerAuthErrorCodes.INSUFFICIENT_KEYCHAIN_PROTECTION, e.getPowerAuthErrorCode());
        }
    }

    /**
     * Erase all data (including version markers) for given keychain.
     * @param identifier Keychain identifier.
     */
    void eraseAllKeychainData(String identifier) {
        androidContext.getSharedPreferences(identifier, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply();
    }
}
