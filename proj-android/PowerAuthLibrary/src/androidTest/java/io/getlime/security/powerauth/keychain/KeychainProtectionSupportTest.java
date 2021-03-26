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
import android.content.SharedPreferences;
import android.util.Base64;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import android.support.annotation.NonNull;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.impl.AesGcmImpl;
import io.getlime.security.powerauth.keychain.impl.BaseKeychainTest;
import io.getlime.security.powerauth.keychain.impl.DefaultKeychainProtectionSupport;
import io.getlime.security.powerauth.keychain.impl.EncryptedKeychain;
import io.getlime.security.powerauth.keychain.impl.LegacyKeychain;
import io.getlime.security.powerauth.system.PA2Log;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class KeychainProtectionSupportTest extends BaseKeychainTest {

    private static final String KEYCHAIN_NAME1 = "com.wultra.test.strongBox.keychain1";
    private static final String KEYCHAIN_NAME2 = "com.wultra.test.strongBox.keychain2";
    private static final String PRIMARY_KEY_NAME = "com.wultra.test.strongBox.primary";
    private static final String BACKUP_KEY_NAME = "com.wultra.test.strongBox.backup";

    // Primary key name from SDK impl.
    private static final String MASTER_KEY_ALIAS = "com.wultra.PowerAuthKeychain.MasterKey";
    // Backup key name from SDK impl.
    private static final String MASTER_BACK_KEY_ALIAS = "com.wultra.PowerAuthKeychain.BackupKey";


    private Context androidContext;
    private KeychainProtectionSupport realKeychainProtectionSupport;
    private boolean isLegacyOnly;

    @Before
    public void setUp() {
        androidContext = InstrumentationRegistry.getInstrumentation().getContext();
        assertNotNull(androidContext);
        realKeychainProtectionSupport = new DefaultKeychainProtectionSupport(androidContext, false);
        isLegacyOnly = KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) == KeychainProtection.NONE;

        setupTestData();

        // Clear encryption keys
        final String[] keysToRemove = { MASTER_KEY_ALIAS, MASTER_BACK_KEY_ALIAS, PRIMARY_KEY_NAME, BACKUP_KEY_NAME };
        for (String key : keysToRemove) {
            final SymmetricKeyProvider provider = SymmetricKeyProvider.getAesGcmKeyProvider(key, true, realKeychainProtectionSupport, 256, true, null);
            if (provider != null) {
                provider.deleteSecretKey();
            } else {
                throw new IllegalStateException("Failed to acquire SymmetricKeyProvider for alias " + key);
            }
        }
        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Reset possible cached keychains
        KeychainFactory.setKeychainProtectionSupport(null);
    }

    @After
    public void tearDown() {
        // Reset factory after test.
        KeychainFactory.setKeychainProtectionSupport(null);
    }

    /**
     * Test whether EncryptedKeychain can select right key provider depending on
     * StrongBox support.
     */
    @Test
    public void testSymmetricKeyProviderSelection() {
        KeychainProtectionSupport keychainProtectionSupport;
        SymmetricKeyProvider regularKP, backupKP, determinedKP;

        // null vs null must produce null
        assertNull(EncryptedKeychain.determineEffectiveSymmetricKeyProvider(null, null));

        // strongbox support off
        keychainProtectionSupport = FakeKeychainProtectionSupport.NO_STRONGBOX;
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, keychainProtectionSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, null);
        assertEquals(regularKP, determinedKP);

        // strongbox support on, enabled on
        keychainProtectionSupport = FakeKeychainProtectionSupport.HAS_STRONGBOX;
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, keychainProtectionSupport, 256, true, null);
        backupKP = SymmetricKeyProvider.getAesGcmKeyProvider(BACKUP_KEY_NAME, false, keychainProtectionSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, backupKP);
        assertEquals(regularKP, determinedKP);

        // strongbox support on, enabled off
        keychainProtectionSupport = FakeKeychainProtectionSupport.HAS_STRONGBOX_DISABLED;
        regularKP = SymmetricKeyProvider.getAesGcmKeyProvider(PRIMARY_KEY_NAME, true, keychainProtectionSupport, 256, true, null);
        backupKP = SymmetricKeyProvider.getAesGcmKeyProvider(BACKUP_KEY_NAME, false, keychainProtectionSupport, 256, true, null);
        determinedKP = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(regularKP, backupKP);
        assertEquals(backupKP, determinedKP);
    }

    @Test
    public void testStrongBoxEnabledDisabled() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testStrongBoxEnabledDisabled - test is not supported on this device.");
            return;
        }
        if (!realKeychainProtectionSupport.isStrongBoxSupported()) {
            PA2Log.e("testStrongBoxEnabledDisabled - test require real StrongBox device.");
            return;
        }

        // :::::::::
        // ::  1  ::
        // :::::::::

        // By default, StrongBox is disabled.
        assertFalse(KeychainFactory.isStrongBoxEnabled(androidContext));
        // Setting false should do nothing.
        KeychainFactory.setStrongBoxEnabled(androidContext, false);
        // Still false, after change.
        assertFalse(KeychainFactory.isStrongBoxEnabled(androidContext));
        // By default, there's HARDWARE level of KeychainProtection
        assertEquals(KeychainProtection.HARDWARE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Now acquire some keychain.
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        assertNotNull(k1);
        fillTestValues(k1);
        verifyEncryptedData(KEYCHAIN_NAME1, false, "test.string_NotEmpty");

        try {
            // The following statement must fail, even when there's no change in configuration.
            KeychainFactory.setStrongBoxEnabled(androidContext, false);
            fail("Must fail");
        } catch (PowerAuthErrorException e) {
            assertEquals(PowerAuthErrorCodes.PA2ErrorCodeWrongParameter, e.getPowerAuthErrorCode());
        }

        // :::::::::
        // ::  2  ::
        // :::::::::

        // Reset factory to default state and try to turn support ON.
        KeychainFactory.setKeychainProtectionSupport(null);

        assertFalse(KeychainFactory.isStrongBoxEnabled(androidContext));

        // Now enable support
        KeychainFactory.setStrongBoxEnabled(androidContext, true);
        // Must be true, after change
        assertTrue(KeychainFactory.isStrongBoxEnabled(androidContext));
        // After the change, the default keychain protection level must be STRONGBOX
        assertEquals(KeychainProtection.STRONGBOX, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Now acquire some keychain.
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        assertNotNull(k1);
        testFilledValues(k1, false);
        verifyEncryptedData(KEYCHAIN_NAME1, true, "test.string_NotEmpty");

        try {
            // The following statement must fail, even when there's no change in configuration.
            KeychainFactory.setStrongBoxEnabled(androidContext, true);
            fail("Must fail");
        } catch (PowerAuthErrorException e) {
            assertEquals(PowerAuthErrorCodes.PA2ErrorCodeWrongParameter, e.getPowerAuthErrorCode());
        }

        // :::::::::
        // ::  3  ::
        // :::::::::

        // Reset factory to default state and test typical scenario, when application wants to
        // change support, but there's already keychain created.

        KeychainFactory.setKeychainProtectionSupport(null);

        // Now acquire some keychain.
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        assertNotNull(k1);

        try {
            // The following statement must fail, even when there's no change in configuration.
            KeychainFactory.setStrongBoxEnabled(androidContext, true);
            fail("Must fail");
        } catch (PowerAuthErrorException e) {
            assertEquals(PowerAuthErrorCodes.PA2ErrorCodeWrongParameter, e.getPowerAuthErrorCode());
        }
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
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
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

        verifyEncryptedData(KEYCHAIN_NAME1, true, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, true, "test.data_NotEmpty");
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
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX_DISABLED);
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

        verifyEncryptedData(KEYCHAIN_NAME1, false, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, false, "test.data_NotEmpty");
    }

    @Test
    public void testMigrationFromV0toStrongBoxEnabled() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationFromV0toStrongBoxEnabled - test is not supported on this device.");
            return;
        }
        if (!realKeychainProtectionSupport.isStrongBoxSupported()) {
            PA2Log.e("testMigrationFromV0toStrongBoxEnabled - test require real StrongBox device.");
            return;
        }

        // Prepare legacy keychain data
        final Keychain k1_legacy = prepareV0Keychain(KEYCHAIN_NAME1);
        final Keychain k2_legacy = prepareV0Keychain(KEYCHAIN_NAME2);
        // Enable StrongBox support
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX);
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

        verifyEncryptedData(KEYCHAIN_NAME1, true, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, true, "test.data_NotEmpty");
    }

    @Test
    public void testStrongBoxSupportChange() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test is not supported on this device.");
            return;
        }
        if (!realKeychainProtectionSupport.isStrongBoxSupported()) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test require real StrongBox device.");
            return;
        }

        // This test simulates data migration between StrongBox support modes. The transparent data
        // migration happens typically when next SDK version adds or removes support for StrongBox.

        // Enable StrongBox support
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX);

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
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX_DISABLED);
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

        verifyEncryptedData(KEYCHAIN_NAME1, false, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, false, "test.data_NotEmpty");

        // Now enable StrongBox support again
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX);
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

        verifyEncryptedData(KEYCHAIN_NAME1, true, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, true, "test.data_NotEmpty");
    }

    @Test
    public void testStrongBoxSupportChangeFromV1() throws Exception {
        if (isLegacyOnly) {
            PA2Log.e("testMigrationBetweenStrongBoxModes - test is not supported on this device.");
            return;
        }
        if (!realKeychainProtectionSupport.isStrongBoxSupported()) {
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
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        fillTestValues(k1);
        fillTestValues(k2);
        downgradeKeychainToV1(KEYCHAIN_NAME1);
        downgradeKeychainToV1(KEYCHAIN_NAME2);

        verifyEncryptedData(KEYCHAIN_NAME1, true, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, true, "test.data_NotEmpty");

        // We have V1 data prepared, so now we can simulate situation when SDK determine that
        // StrongBox is not reliable.
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_STRONGBOX_DISABLED);

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

        verifyEncryptedData(KEYCHAIN_NAME1, false, "test.string_NotEmpty");
        verifyEncryptedData(KEYCHAIN_NAME2, false, "test.data_NotEmpty");
    }


    @Test
    public void testMigrationFromV0ToNoEncryption() throws Exception {

        // Simulate SDK upgrade from pre 1.4.2 version, when encryption is not supported.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        prepareV0Keychain(KEYCHAIN_NAME1);
        prepareV0Keychain(KEYCHAIN_NAME2);

        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_ENCRYPTION);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
    }

    @Test
    public void testMigrationFromV0ToEncryptionDisabled() throws Exception {

        // Simulate SDK upgrade from pre 1.4.2 version when encryption is disabled.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        prepareV0Keychain(KEYCHAIN_NAME1);
        prepareV0Keychain(KEYCHAIN_NAME2);

        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        assertFalse(k1.isStrongBoxBacked());
        assertFalse(k2.isStrongBoxBacked());
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
    }

    @Test
    public void testMigrationFromV0ToEncryptionEnabled() throws Exception {

        // Simulate SDK upgrade from pre 1.4.2 version when encryption is supported.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        prepareV0Keychain(KEYCHAIN_NAME1);
        prepareV0Keychain(KEYCHAIN_NAME2);

        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);
        runAllStandardValidations(k1, true);
        runAllStandardValidations(k2, true);
    }

    @Test
    public void testMigrationFromV1ToEncryptionEnabled() throws Exception {

        // Simulate SDK upgrade from V1 keychain data when encryption is supported.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Prepare V1 keychain data
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        fillTestValues(k1);
        fillTestValues(k2);
        downgradeKeychainToV1(KEYCHAIN_NAME1);
        downgradeKeychainToV1(KEYCHAIN_NAME2);
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);

        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertNotNull(k1);
        assertNotNull(k2);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
    }

    @Test
    public void testDowngradeEncryptionFromV1() throws Exception {

        // Test downgrade encrypted keychain in V1 format to legacy keychain.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Prepare V1 keychain data
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        fillTestValues(k1);
        fillTestValues(k2);
        downgradeKeychainToV1(KEYCHAIN_NAME1);
        downgradeKeychainToV1(KEYCHAIN_NAME2);
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);

        // Disable encryption
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        fillTestValues(k1);
        fillTestValues(k2);
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Run the same test again, to validate whether KeychainFactory will not re-encrypt content later.
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));
    }

    @Test
    public void testDowngradeEncryption() throws Exception {

        // Test downgrade encrypted keychain in current format to legacy keychain.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Prepare keychain data
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        fillTestValues(k1);
        fillTestValues(k2);
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);

        // Disable encryption
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        fillTestValues(k1);
        fillTestValues(k2);
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));

        // Run the same test again, to validate whether KeychainFactory will not re-encrypt content later.
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        assertEquals(KeychainProtection.NONE, KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext));
    }

    @Test
    public void testDowngradeUpgradeEncryption() throws Exception {

        // Test downgrade from encrypted keychain to a legacy keychain and then upgrade back
        // to encrypted keychain.

        // Cleanup keychains
        eraseAllKeychainData(KEYCHAIN_NAME1);
        eraseAllKeychainData(KEYCHAIN_NAME2);

        // Prepare keychain data
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        Keychain k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        Keychain k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        fillTestValues(k1);
        fillTestValues(k2);

        // Disable encryption
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.HAS_ENCRYPTION_DISABLED);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertFalse(k1.isEncrypted());
        assertFalse(k2.isEncrypted());
        runAllStandardValidations(k1, false);
        runAllStandardValidations(k2, false);
        fillTestValues(k1);
        fillTestValues(k2);

        // Enable encryption
        KeychainFactory.setKeychainProtectionSupport(FakeKeychainProtectionSupport.NO_STRONGBOX);
        k1 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME1, KeychainProtection.NONE);
        k2 = KeychainFactory.getKeychain(androidContext, KEYCHAIN_NAME2, KeychainProtection.NONE);
        assertTrue(k1.isEncrypted());
        assertTrue(k2.isEncrypted());
        runAllStandardValidations(k1, true);
        runAllStandardValidations(k2, true);
        assertTrue(KeychainFactory.getKeychainProtectionSupportedOnDevice(androidContext) > KeychainProtection.NONE);
    }


    // Helper functions

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
                .remove(EncryptedKeychain.ENCRYPTED_KEYCHAIN_MODE_KEY)
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

    /**
     * Verify whether there's value stored in keychain and encrypted with the right key.
     *
     * @param keychainIdentifier Keychain identifier.
     * @param primaryKey Use primary or backup key.
     * @param dataKey Data to be verified.
     */
    void verifyEncryptedData(@NonNull String keychainIdentifier, boolean primaryKey, @NonNull String dataKey) {
        final String keyIdentifier = primaryKey ? MASTER_KEY_ALIAS : MASTER_BACK_KEY_ALIAS;

        // Get raw data from keychain
        final SharedPreferences preferences = androidContext.getSharedPreferences(keychainIdentifier, Context.MODE_PRIVATE);
        assertNotNull(preferences);
        final String encodedEncryptedData = preferences.getString(dataKey, null);
        assertNotNull(encodedEncryptedData);

        // Decode from Base64
        final byte[] encryptedData = Base64.decode(encodedEncryptedData, Base64.NO_WRAP);
        assertNotNull(encryptedData);
        assertTrue(encryptedData.length > 0);

        // Acquire secret key
        final SymmetricKeyProvider keyProvider = SymmetricKeyProvider.getAesGcmKeyProvider(keyIdentifier, primaryKey, realKeychainProtectionSupport, 256, true, null);
        assertNotNull(keyProvider);
        assertTrue(keyProvider.containsSecretKey());
        final SecretKey secretKey = keyProvider.getOrCreateSecretKey(androidContext, false);
        assertNotNull(secretKey);

        // Try decrypt data
        final byte[] plainData = AesGcmImpl.decrypt(encryptedData, secretKey, keychainIdentifier);
        assertNotNull(plainData);
    }
}
