/*
 * Copyright 2021 Wultra s.r.o.
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import io.getlime.security.powerauth.keychain.impl.BaseKeychainTest;
import io.getlime.security.powerauth.keychain.impl.DefaultStrongBoxSupport;
import io.getlime.security.powerauth.keychain.impl.EncryptedKeychain;
import io.getlime.security.powerauth.keychain.impl.LegacyKeychain;
import io.getlime.security.powerauth.system.PA2Log;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class StrongBoxSupportTest extends BaseKeychainTest {

    private static final String KEYCHAIN_NAME1 = "com.wultra.test.strongBox.keychain1";
    private static final String KEYCHAIN_NAME2 = "com.wultra.test.strongBox.keychain2";
    private static final String PRIMARY_KEY_NAME = "com.wultra.test.strongBox.primary";
    private static final String BACKUP_KEY_NAME = "com.wultra.test.strongBox.backup";

    // Primary key name from SDK impl.
    private static final String MASTER_KEY_ALIAS = "com.wultra.PowerAuthKeychain.MasterKey";
    // Backup key name from SDK impl.
    private static final String MASTER_BACK_KEY_ALIAS = "com.wultra.PowerAuthKeychain.BackupKey";


    private Context androidContext;
    private StrongBoxSupport realStrongBoxSupport;
    private boolean isLegacyOnly;

    @Before
    public void setUp() {
        androidContext = InstrumentationRegistry.getInstrumentation().getContext();
        assertNotNull(androidContext);
        realStrongBoxSupport = new DefaultStrongBoxSupport(androidContext);
        isLegacyOnly = KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) == KeychainProtection.NONE;

        setupTestData();

        // Clear encryption keys
        final String[] keysToRemove = { MASTER_KEY_ALIAS, MASTER_BACK_KEY_ALIAS, PRIMARY_KEY_NAME, BACKUP_KEY_NAME };
        for (String key : keysToRemove) {
            final SymmetricKeyProvider provider = SymmetricKeyProvider.getAesGcmKeyProvider(key, true, realStrongBoxSupport, 256, true, null);
            if (provider != null) {
                provider.deleteSecretKey();
            } else {
                throw new IllegalStateException("Failed to acquire SymmetricKeyProvider for alias " + key);
            }
        }
    }

    /**
     * Test validate whether EncryptedKeychain can select right key provider depending on
     * StrongBox support.
     */
    @Test
    public void testSymmetricKeyProviderSelection() {
        StrongBoxSupport strongBoxSupport;
        SymmetricKeyProvider regularKP, backupKP, determinedKP;

        // null vs null must produce null
        assertNull(EncryptedKeychain.determineEffectiveSymmetricKeyProvider(null, null));

        // strongbox support off
        strongBoxSupport = new FakeStrongBoxSupport(false, false);
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, strongBoxSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, null);
        assertEquals(regularKP, determinedKP);

        // strongbox support on, enabled on
        strongBoxSupport = new FakeStrongBoxSupport(true, true);
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, strongBoxSupport, 256, true, null);
        backupKP = SymmetricKeyProvider.getAesGcmKeyProvider(BACKUP_KEY_NAME, false, strongBoxSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, backupKP);
        assertEquals(regularKP, determinedKP);

        // strongbox support on, enabled off
        strongBoxSupport = new FakeStrongBoxSupport(true, false);
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, strongBoxSupport, 256, true, null);
        backupKP = SymmetricKeyProvider.getAesGcmKeyProvider(BACKUP_KEY_NAME, false, strongBoxSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, backupKP);
        assertEquals(backupKP, determinedKP);
    }

    @Test
    public void testMigrationFromV0toStrongBoxNotSupported() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationFromV0toStrongBoxNotSupported - test is not supported on this device.");
            return;
        }
        final Keychain k1_legacy = prepareV0Keychain(KEYCHAIN_NAME1);
        final Keychain k2_legacy = prepareV0Keychain(KEYCHAIN_NAME2);
        // Set StrongBox not supported
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(false, false));
        // Now get keychains via factory
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertNotEquals(k1_legacy, k1);
        assertNotEquals(k2_legacy, k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());

        // Empty string is treated as null after migration.
        runAllStandardValidations(k1, true);
        runAllStandardValidations(k2, true);
    }

    @Test
    public void testMigrationFromV0toStrongBoxDisabled() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationFromV0toStrongBoxDisabled - test is not supported on this device.");
            return;
        }
        final Keychain k1_legacy = prepareV0Keychain(KEYCHAIN_NAME1);
        final Keychain k2_legacy = prepareV0Keychain(KEYCHAIN_NAME2);
        // Disable StrongBox support
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, false));
        // Now get keychains via factory
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertNotEquals(k1_legacy, k1);
        assertNotEquals(k2_legacy, k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());

        // Empty string is treated as null after migration.
        runAllStandardValidations(k1, true);
        runAllStandardValidations(k2, true);
    }

    @Test
    public void testMigrationFromV0toStrongBoxEnabled() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationFromV0toStrongBoxEnabled - test is not supported on this device.");
            return;
        }
        if (!realStrongBoxSupport.isStrongBoxSupported()) {
            PA2Log.e("testMigrationFromV0toStrongBoxEnabled - test require real StrongBox device.");
            return;
        }

        // Prepare legacy keychain data
        final Keychain k1_legacy = prepareV0Keychain(KEYCHAIN_NAME1);
        final Keychain k2_legacy = prepareV0Keychain(KEYCHAIN_NAME2);
        // Enable StrongBox support
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, true));
        // Now get keychains via factory
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertNotEquals(k1_legacy, k1);
        assertNotEquals(k2_legacy, k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertTrue(k1.isStrongBoxBacked());
        assertTrue(k2.isStrongBoxBacked());

        // Empty string is treated as null after migration.
        runAllStandardValidations(k1, true);
        runAllStandardValidations(k2, true);
    }

    @Test
    public void testStrongBoxSupportChange() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test is not supported on this device.");
            return;
        }
        if (!realStrongBoxSupport.isStrongBoxSupported()) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test require real StrongBox device.");
            return;
        }

        // This test simulates data migration between StrongBox support modes. The transparent data
        // migration happens typically when next SDK version adds or removes support for StrongBox.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Enable StrongBox support
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, true));

        // Now get keychains via factory
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertTrue(k1.isStrongBoxBacked());
        assertTrue(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.STRONGBOX, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Prepare test values
        fillTestValues(k1);
        fillTestValues(k2);

        // Now switch StrongBox as disabled
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, false));
        // KeychainFactory did reset its cache, so we need to acquire keychains again.
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.HARDWARE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Validate stored values
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        // Set test values again
        fillTestValues(k1);
        fillTestValues(k2);

        // Now enable StrongBox support again
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, true));
        // KeychainFactory did reset its cache, so we need to acquire keychains again.
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertTrue(k1.isStrongBoxBacked());
        assertTrue(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.STRONGBOX, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Validate test values again
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
    }

    @Test
    public void testStrongBoxSupportChangeFromV1() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test is not supported on this device.");
            return;
        }
        if (!realStrongBoxSupport.isStrongBoxSupported()) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test require real StrongBox device.");
            return;
        }

        // This test simulates migration from older SDK. In this situation, keychain must be in V1
        // version. The only difference between V1 and V2 is the additional information about last
        // known StrongBox support. So we can create V2 keychain in standard StrongBox support mode
        // (e.g. the same as do older SDK) and then remove V2 version and support marker.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Enable StrongBox support
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, true));
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        fillTestValues(k1);
        fillTestValues(k2);
        downgradeKeychainToV1(KEYCHAIN_NAME1);
        downgradeKeychainToV1(KEYCHAIN_NAME2);

        // We have V1 data prepared, so now we can simulate situation when SDK determine that
        // StrongBox is not reliable.
        KeychainFactory.setStrongBoxSupport(new FakeStrongBoxSupport(true, false));

        // Get keychains again
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.HARDWARE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Validate stored values
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
    }

    /**
     * Prepare legacy keychain and fill it with test data.
     * @param identifier Keychain identifier.
     * @return Legacy keychain.
     * @throws Exception In case of failure.
     */
    @NonNull
    Keychain prepareV0Keychain(@NonNull String identifier) throws Exception {
        final LegacyKeychain keychain = new LegacyKeychain(androidContext, identifier);
        keychain.removeAll();
        fillTestValues(keychain);
        return keychain;
    }

    /**
     * Downgrade given keychain's data to EncryptedKeychain V1.
     * @param identifier Keychain identifier.
     */
    void downgradeKeychainToV1(@NonNull String identifier) {
        androidContext.getSharedPreferences(identifier, Context.MODE_PRIVATE)
                .edit()
                .remove(EncryptedKeychain.ENCRYPTED_KEYCHAIN_STRONGBOX_KEY)
                .putInt(EncryptedKeychain.ENCRYPTED_KEYCHAIN_VERSION_KEY, EncryptedKeychain.KEYCHAIN_V1)
                .apply();
    }

    /**
     * Erase all data (including version markers) for given keychain.
     * @param identifier Keychain identifier.
     */
    void eraseAllKeychainData(@NonNull String identifier) {
        androidContext.getSharedPreferences(identifier, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply();
    }
}
