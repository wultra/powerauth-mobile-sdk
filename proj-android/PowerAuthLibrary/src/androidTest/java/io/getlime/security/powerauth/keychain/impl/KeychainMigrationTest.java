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
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Set;

import io.getlime.security.powerauth.keychain.KeychainFactory;
import io.getlime.security.powerauth.keychain.KeychainProtection;
import io.getlime.security.powerauth.keychain.SymmetricKeyProvider;
import io.getlime.security.powerauth.keychain.impl.EncryptedKeychain;
import io.getlime.security.powerauth.keychain.impl.LegacyKeychain;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class KeychainMigrationTest extends BaseKeychainTest {

    private Context androidContext;
    private SymmetricKeyProvider symmetricKeyProvider;
    private SharedPreferences backingSharedPreferences;
    private @KeychainProtection
    int currentProtectionLevel;

    private static final String KEYCHAIN_NAME = "com.wultra.test.migrationTest.keychainId";

    @Before
    public void setUp() {
        androidContext = InstrumentationRegistry.getInstrumentation().getContext();
        assertNotNull(androidContext);

        // At first test, whether the device supports at least SOFTWARE keychain protection.
        currentProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext);
        // Do not run this test, in case that device doesn't support enough protection level.
        if (currentProtectionLevel == KeychainProtection.NONE) {
            return;
        }

        symmetricKeyProvider = SymmetricKeyProvider.getAesGcmKeyProvider("com.wultra.test.symmetricAesGcmKey", 256, true, null);
        assertNotNull(symmetricKeyProvider);
        symmetricKeyProvider.deleteSecretKey();

        backingSharedPreferences =  androidContext.getSharedPreferences(KEYCHAIN_NAME, Context.MODE_PRIVATE);
        assertNotNull(backingSharedPreferences);

        setupTestData();
    }

    @Test
    public void testKeychainMigration() throws Exception {

        // Do not run this test, in case that device doesn't support enough protection level.
        if (currentProtectionLevel == KeychainProtection.NONE) {
            return;
        }

        // Prepare symmetric key provider
        assertFalse(symmetricKeyProvider.containsSecretKey());

        // Prepare legacy keychain
        final LegacyKeychain legacyKeychain = new LegacyKeychain(androidContext, KEYCHAIN_NAME);
        assertFalse(legacyKeychain.isEncrypted());

        legacyKeychain.removeAll();

        fillTestValues(legacyKeychain);
        testFilledValues(legacyKeychain, false);

        // Now try to migrate the keychain
        assertFalse(EncryptedKeychain.isEncryptedContentInSharedPreferences(backingSharedPreferences));
        final EncryptedKeychain encryptedKeychain = new EncryptedKeychain(androidContext, KEYCHAIN_NAME, symmetricKeyProvider);
        assertTrue(encryptedKeychain.importFromLegacyKeychain(backingSharedPreferences));
        assertTrue(symmetricKeyProvider.containsSecretKey());
        assertTrue(EncryptedKeychain.isEncryptedContentInSharedPreferences(backingSharedPreferences));

        testFilledValues(encryptedKeychain, true);  // Empty string is treated as null after migration.
    }

}
