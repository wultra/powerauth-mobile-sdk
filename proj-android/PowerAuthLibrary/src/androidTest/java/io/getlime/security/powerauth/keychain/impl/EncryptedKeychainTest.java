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

package io.getlime.security.powerauth.keychain.impl;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.keychain.KeychainFactory;
import io.getlime.security.powerauth.keychain.KeychainProtection;
import io.getlime.security.powerauth.keychain.SymmetricKeyProvider;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class EncryptedKeychainTest extends BaseKeychainTest {

    private static final String KEYCHAIN_NAME = "com.wultra.test.encryptedKeychain";

    private Keychain keychain;
    private @KeychainProtection int currentProtectionLevel;

    @Before
    public void setUp() throws Exception {

        Context androidContext = InstrumentationRegistry.getInstrumentation().getContext();
        assertNotNull(androidContext);

        // At first test, whether the device supports at least SOFTWARE keychain protection.
        currentProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext);
        // Do not run this test, in case that device doesn't support enough protection level.
        if (currentProtectionLevel == KeychainProtection.NONE) {
            return;
        }

        SymmetricKeyProvider symmetricKeyProvider = SymmetricKeyProvider.getAesGcmKeyProvider("com.wultra.test.symmetricAesGcmKey", 256, true, null);
        assertNotNull(symmetricKeyProvider);
        symmetricKeyProvider.deleteSecretKey();

        keychain = new EncryptedKeychain(androidContext, KEYCHAIN_NAME, symmetricKeyProvider);
        assertNotNull(keychain);
        keychain.removeAll();

        setupTestData();
    }

    @Test
    public void testKeychainUsage() throws Exception {

        // Do not run this test, in case that device doesn't support enough protection level.
        if (currentProtectionLevel > KeychainProtection.NONE) {
            runAllStandardTests(keychain);
        }
    }
}
