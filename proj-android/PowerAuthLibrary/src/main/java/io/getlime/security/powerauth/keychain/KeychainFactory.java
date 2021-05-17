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
import android.os.Build;
import android.security.keystore.KeyInfo;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.impl.DefaultKeychainProtectionSupport;
import io.getlime.security.powerauth.keychain.impl.EncryptedKeychain;
import io.getlime.security.powerauth.keychain.impl.LegacyKeychain;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The {@code KeychainFactory} provides an instances of {@link Keychain} objects that implements
 * simple and secure data storage for the application and PowerAuth mobile SDK.
 */
public class KeychainFactory {

    /**
     * Get {@link Keychain} object that implements simple and secure data storage. Note that
     * the underlying implementation is using cache for an already created keychains. That means that
     * if the same keychain is accessed for multiple times, then the same instance of {@code Keychain}
     * is returned.
     *
     * @param context Android context object.
     * @param identifier String with keychain identifier.
     * @param minimumKeychainProtection Minimum required keychain protection that must be supported on the device to create the keychain.
     * @return Instance of {@link Keychain} object.
     * @throws PowerAuthErrorException In case that device provides insufficient keychain protection than is required in {@code minimumKeychainProtection} parameter.
     */
    @NonNull
    public static Keychain getKeychain(@NonNull Context context, @NonNull String identifier, @KeychainProtection int minimumKeychainProtection) throws PowerAuthErrorException {
        synchronized (SharedData.class) {
            final SharedData sharedData = getSharedData();
            final Context appContext = context.getApplicationContext();
            if (minimumKeychainProtection > sharedData.getKeychainProtection(context)) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INSUFFICIENT_KEYCHAIN_PROTECTION, "Device doesn't support required level of keychain protection.");
            }
            Keychain keychain = sharedData.getKeychainMap().get(identifier);
            if (keychain == null) {
                keychain = createKeychain(appContext, sharedData, identifier);
                PowerAuthLog.d("KeychainFactory: " + identifier + ": Created " + (keychain.isEncrypted() ? "encrypted keychain." : "legacy keychain."));
                sharedData.getKeychainMap().put(identifier, keychain);
            }
            return keychain;
        }
    }

    /**
     * Get current keychain protection level supported on the device.
     *
     * @param context Android context.
     * @return {@link KeychainProtection} representing the level of the keychain protection.
     */
    public static @KeychainProtection int getKeychainProtectionSupportedOnDevice(@NonNull Context context) {
        synchronized (SharedData.class) {
            return getSharedData().getKeychainProtection(context);
        }
    }

    /**
     * Determine whether StrongBox is enabled on this device and Keychain encrypts data with
     * StrongBox-backed key. By default, StrongBox is disabled on all devices.
     *
     * @param context Android context.
     * @return {@code true} in case that StrongBox is enabled on this device and Keychain encrypts
     *         data with StrongBox-backed key.
     */
    public static boolean isStrongBoxEnabled(@NonNull Context context) {
        synchronized (SharedData.class) {
            return getSharedData().getStrongBoxSupport(context).isStrongBoxEnabled();
        }
    }

    /**
     * Enable or disable StrongBox support on this device. By default, StrongBox is disabled on all
     * devices. It's required to alter the default configuration at application's startup and before
     * you create any instance of {@link Keychain} or any {@code PowerAuthSDK} class. Otherwise the
     * {@link PowerAuthErrorException} is produced.
     *
     * @param context Android context.
     * @param enabled {@code true} to enable.
     * @throws PowerAuthErrorException In case that {@code KeychainFactory} already created some {@link Keychain} instances.
     */
    public static void setStrongBoxEnabled(@NonNull Context context, boolean enabled) throws PowerAuthErrorException {
        synchronized (SharedData.class) {
            final SharedData sharedData = getSharedData();
            if (!sharedData.getKeychainMap().isEmpty()) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "There are already created keychains in KeychainFactory.");
            }
            if (sharedData.getStrongBoxSupport(context).isStrongBoxEnabled() != enabled) {
                final KeychainProtectionSupport newKeychainProtectionSupport = new DefaultKeychainProtectionSupport(context, enabled);
                sharedData.setKeychainProtectionSupportAndResetSharedData(newKeychainProtectionSupport);
                PowerAuthLog.d("KeychainFactory: StrongBox support is now " + (enabled ? "enabled." : "disabled."));
            }
        }
    }

    /**
     * Set alternate implementation of {@link KeychainProtectionSupport} used internally to determine current StrongBox
     * support. The method is useful only for unit testing, so it's not declared as public. Be aware that
     * calling this function also reset internal shared data object, so {@code KeychainFactory} will end
     * in not-initialized state.
     *
     * @param keychainProtectionSupport Testing {@link KeychainProtectionSupport} implementation, or {@code null} if you want
     *                         to reset shared data object only.
     */
    static void setKeychainProtectionSupport(@Nullable KeychainProtectionSupport keychainProtectionSupport) {
        synchronized (SharedData.class) {
            getSharedData().setKeychainProtectionSupportAndResetSharedData(keychainProtectionSupport);
        }
    }

    /**
     * @return Object with shared data.
     */
    private static @NonNull SharedData getSharedData() {
        return SharedData.INSTANCE;
    }

    /**
     * Create a new instance of {@link Keychain} object with given identifier.
     *
     * @param context Android context.
     * @param sharedData Shared KeychainFactory data.
     * @param identifier Keychain identifier.
     * @return Instance of {@link Keychain}.
     */
    @NonNull
    private static Keychain createKeychain(@NonNull Context context, @NonNull SharedData sharedData, @NonNull String identifier) {
        final SharedPreferences preferences = context.getSharedPreferences(identifier, Context.MODE_PRIVATE);
        final boolean isAlreadyEncrypted = EncryptedKeychain.isEncryptedContentInSharedPreferences(preferences);
        final int keychainProtection = sharedData.getKeychainProtection(context);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (keychainProtection != KeychainProtection.NONE || isAlreadyEncrypted) {
                // If Android "M" and later, then create a secret key provider and try to create an encrypted keychain.
                final SymmetricKeyProvider masterKeyProvider = sharedData.getMasterEncryptionKeyProvider(context);
                final SymmetricKeyProvider backupKeyProvider = sharedData.getBackupEncryptionKeyProvider(context);
                if (masterKeyProvider != null) {
                    final EncryptedKeychain encryptedKeychain = new EncryptedKeychain(context, identifier, masterKeyProvider, backupKeyProvider);
                    if (isAlreadyEncrypted) {
                        // If keychain is already encrypted, then just validate encryption support.
                        // The update function may fail in case that re-encryption did not end well,
                        // and the previously encrypted content was stored back to the legacy keychain.
                        if (encryptedKeychain.updateEncryptionSupport(preferences)) {
                            return encryptedKeychain;
                        }
                    } else if (encryptedKeychain.importFromLegacyKeychain(preferences)) {
                        // Import from legacy keychain succeeded, so return encrypted keychain.
                        return encryptedKeychain;
                    }
                }
            }
        }

        // Otherwise just return the legacy keychain.
        final Keychain keychain =  new LegacyKeychain(context, identifier);
        if (EncryptedKeychain.isEncryptedContentInSharedPreferences(preferences)) {
            // Print error in case that keychain was previously encrypted and now it's not.
            PowerAuthLog.e("KeychainFactory: " + identifier + ": The content was previously encrypted but the encryption is no longer available.");
            keychain.removeAll();
        }
        return keychain;
    }

    /**
     * The {@code SharedData} nested class contains shared data, required for the keychain management.
     */
    private static class SharedData {

        /**
         * Shared instance of this class.
         */
        private static final SharedData INSTANCE = new SharedData();

        /**
         * Map that contains an already instantiated keychain objects.
         */
        private final Map<String, Keychain> keychainMap = new HashMap<>();

        /**
         * Instance of {@link KeychainProtectionSupport} that provides information about StrongBox support
         * on this device.
         */
        private KeychainProtectionSupport keychainProtectionSupport;

        /**
         * Instance of {@link SymmetricKeyProvider} that provides encryption key for all encrypted keychains.
         */
        private SymmetricKeyProvider masterEncryptionKeyProvider;

        /**
         * Instance of backup {@link SymmetricKeyProvider} that provides encryption key for all encrypted keychains.
         * The value is valid only for devices that support StrongBox.
         */
        private SymmetricKeyProvider backupEncryptionKeyProvider;

        /**
         * Contains {@code 0} if keychain protection level is not determined yet, or the determined
         * level of {@link KeychainProtection}.
         */
        private @KeychainProtection int keychainProtection;

        /**
         * @return Map containing an already instantiated keychain objects.
         */
        Map<String, Keychain> getKeychainMap() {
            return keychainMap;
        }

        /**
         * Master key alias identifying key in the Android KeyStore.
         */
        private static final String MASTER_KEY_ALIAS = "com.wultra.PowerAuthKeychain.MasterKey";
        /**
         * Master key alias identifying secondary key in the Android KeyStore. This key may be used
         * in case that the device supports unreliable StrongBox.
         */
        private static final String MASTER_BACK_KEY_ALIAS = "com.wultra.PowerAuthKeychain.BackupKey";

        /**
         * Master key size in bits (e.g. AES256-GCM key is used)
         */
        private static final int MASTER_KEY_SIZE = 256;

        /**
         * Reset {@code SharedData} object to non-initialized state.
         */
        private void resetSharedData() {
            keychainMap.clear();
            keychainProtection = 0;
            keychainProtectionSupport = null;
            masterEncryptionKeyProvider = null;
            backupEncryptionKeyProvider = null;
        }

        /**
         * Return shared instance of {@link KeychainProtectionSupport} interface.
         * @param context Android context.
         * @return Shared instance of {@link KeychainProtectionSupport} interface.
         */
        @NonNull
        KeychainProtectionSupport getStrongBoxSupport(@NonNull Context context) {
            if (keychainProtectionSupport == null) {
                // StrongBox is disabled by default.
                // Check https://github.com/wultra/powerauth-mobile-sdk/issues/354 for more details.
                keychainProtectionSupport = new DefaultKeychainProtectionSupport(context, false);
            }
            return keychainProtectionSupport;
        }

        /**
         * Change internal {@link KeychainProtectionSupport} implementation and reset shared data object
         * to default, non-initialized state. The method is useful only when application want's
         * to change default StrongBox support or for an unit testing purposes.
         *
         * @param keychainProtectionSupport New {@link KeychainProtectionSupport} implementation.
         */
        void setKeychainProtectionSupportAndResetSharedData(@Nullable KeychainProtectionSupport keychainProtectionSupport) {
            resetSharedData();
            this.keychainProtectionSupport = keychainProtectionSupport;
        }

        /**
         * Return shared instance of master {@link SymmetricKeyProvider} configured for AES-GCM with 256bit key.
         * @param context Android context.
         * @return Instance of {@link SymmetricKeyProvider} configured for AES-GCM with 256bit key.
         */
        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        SymmetricKeyProvider getMasterEncryptionKeyProvider(@NonNull Context context) {
            if (masterEncryptionKeyProvider == null) {
                masterEncryptionKeyProvider = SymmetricKeyProvider.getAesGcmKeyProvider(MASTER_KEY_ALIAS, true, getStrongBoxSupport(context), MASTER_KEY_SIZE, true,null);
                if (masterEncryptionKeyProvider == null) {
                    PowerAuthLog.e("KeychainFactory: Unable to acquire common master key provider for EncryptedKeychain.");
                }
            }
            return masterEncryptionKeyProvider;
        }

        /**
         * Return shared instance of backup {@link SymmetricKeyProvider} configured for AES-GCM with 256bit key.
         * This key provider is available only if device supports StrongBox.
         * @param context Android context.
         * @return Instance of backup {@link SymmetricKeyProvider} configured for AES-GCM with 256bit key.
         */
        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        SymmetricKeyProvider getBackupEncryptionKeyProvider(@NonNull Context context) {
            if (backupEncryptionKeyProvider == null) {
                final KeychainProtectionSupport keychainProtectionSupport = getStrongBoxSupport(context);
                if (keychainProtectionSupport.isStrongBoxSupported()) {
                    backupEncryptionKeyProvider = SymmetricKeyProvider.getAesGcmKeyProvider(MASTER_BACK_KEY_ALIAS, false, keychainProtectionSupport, MASTER_KEY_SIZE, true, null);
                    if (backupEncryptionKeyProvider == null) {
                        PowerAuthLog.e("KeychainFactory: Unable to acquire common backup key provider for EncryptedKeychain.");
                    }
                }
            }
            return backupEncryptionKeyProvider;
        }
        /**
         * Determine the keychain protection level.
         *
         * @param context Android context
         * @return Constant from {@link KeychainProtection} representing the level of keychain protection.
         */
        @KeychainProtection int getKeychainProtection(@NonNull Context context) {
            if (keychainProtection == 0) {
                // Protection level is not determined yet (e.g. value is equal to `0`)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    final SymmetricKeyProvider keyProvider = EncryptedKeychain.determineEffectiveSymmetricKeyProvider(
                            getMasterEncryptionKeyProvider(context),
                            getBackupEncryptionKeyProvider(context));
                    final SecretKey secretKey = keyProvider != null ? keyProvider.getOrCreateSecretKey(context, false) : null;
                    final KeyInfo secretKeyInfo = keyProvider != null ? keyProvider.getSecretKeyInfo(context) : null;
                    if (secretKey != null && secretKeyInfo != null) {
                        final KeychainProtectionSupport keychainProtectionSupport = keyProvider.getKeychainProtectionSupport();
                        if (keychainProtectionSupport.isKeyStoreEncryptionEnabled()) {
                            if (EncryptedKeychain.verifyKeystoreEncryption(context, keyProvider)) {
                                // We can trust KeyStore, just determine the level of protection
                                if (secretKeyInfo.isInsideSecureHardware()) {
                                    if (keychainProtectionSupport.isStrongBoxSupported()) {
                                        if (keychainProtectionSupport.isStrongBoxEnabled()) {
                                            // Keychain encryption key is stored in StrongBox.
                                            keychainProtection = KeychainProtection.STRONGBOX;
                                        } else {
                                            // Keychain encryption key should not be stored in StrongBox due to its poor reliability.
                                            PowerAuthLog.e("KeychainFactory: StrongBox is supported but not enabled on this device.");
                                            keychainProtection = KeychainProtection.HARDWARE;
                                        }
                                    } else {
                                        // Keychain encryption key is stored in the dedicated secure hardware, but is not StrongBox backed.
                                        keychainProtection = KeychainProtection.HARDWARE;
                                    }
                                } else {
                                    // Keychain encryption key is not stored in the dedicated secure hardware.
                                    keychainProtection = KeychainProtection.SOFTWARE;
                                }
                            }
                        } else if (keychainProtectionSupport.isKeyStoreEncryptionSupported()) {
                            // Keychain encryption is supported but not enabled for this device de to poor KeyStore reliability.
                            PowerAuthLog.e("KeychainFactory: Android KeyStore is supported but not enabled on this device.");
                            keychainProtection = KeychainProtection.NONE;
                        }
                    }
                }
                // If keychain protection is still undetermined, then it means that some operation
                // above failed. So, we have to fallback to NONE.
                if (keychainProtection == 0) {
                    keychainProtection = KeychainProtection.NONE;
                }
            }
            return keychainProtection;
        }
    }
}
