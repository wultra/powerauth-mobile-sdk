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
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyInfo;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.impl.EncryptedKeychain;
import io.getlime.security.powerauth.keychain.impl.LegacyKeychain;
import io.getlime.security.powerauth.system.PA2Log;

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
                throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInsufficientKeychainProtection, "Device doesn't support required level of keychain protection.");
            }
            Keychain keychain = sharedData.getKeychainMap().get(identifier);
            if (keychain == null) {
                keychain = createKeychain(appContext, sharedData, identifier);
                PA2Log.d("KeychainFactory: " + identifier + ": Created " + (keychain.isEncrypted() ? "encrypted keychain." : "legacy keychain."));
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
            if (keychainProtection != KeychainProtection.NONE) {
                // If Android "M" and later, then create a secret key provider and try to create an encrypted keychain.
                final SymmetricKeyProvider masterKeyProvider = sharedData.getMasterEncryptionKeyProvider();
                if (masterKeyProvider != null) {
                    final EncryptedKeychain encryptedKeychain = new EncryptedKeychain(context, identifier, masterKeyProvider);
                    // Return encrypted keychain, if it's already encrypted or import is successful.
                    if (isAlreadyEncrypted || encryptedKeychain.importFromLegacyKeychain(preferences)) {
                        return encryptedKeychain;
                    }
                }
            }
        }

        // Otherwise just return the legacy keychain.
        final Keychain keychain =  new LegacyKeychain(context, identifier);
        if (isAlreadyEncrypted) {
            // Print error in case that keychain was previously encrypted and now it's not.
            PA2Log.e("KeychainFactory: " + identifier + ": The content was previously encrypted but the encryption is no longer available.");
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
        private Map<String, Keychain> keychainMap = new HashMap<>();

        /**
         * Instance of {@link SymmetricKeyProvider} that provides encryption key for all encrypted keychains.
         */
        private SymmetricKeyProvider masterEncryptionKeyProvider;

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
         * Master key size in bits (e.g. AES256-GCM key is used)
         */
        private static final int MASTER_KEY_SIZE = 256;

        /**
         * @return Instance of {@link SymmetricKeyProvider} configured for AES-GCM with 256bit key.
         */
        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        SymmetricKeyProvider getMasterEncryptionKeyProvider() {
            if (masterEncryptionKeyProvider == null) {
                masterEncryptionKeyProvider = SymmetricKeyProvider.getAesGcmKeyProvider(MASTER_KEY_ALIAS, MASTER_KEY_SIZE, true,null);
                if (masterEncryptionKeyProvider == null) {
                    PA2Log.e("KeychainFactory: Unable to acquire common master key provider for EncryptedKeychain.");
                }
            }
            return masterEncryptionKeyProvider;
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
                    final SymmetricKeyProvider keyProvider = getMasterEncryptionKeyProvider();
                    final SecretKey secretKey = keyProvider != null ? keyProvider.getOrCreateSecretKey(context, false) : null;
                    final KeyInfo secretKeyInfo = keyProvider != null ? keyProvider.getSecretKeyInfo(context) : null;
                    if (secretKey != null && secretKeyInfo != null) {
                        if (EncryptedKeychain.verifyKeystoreEncryption(context, keyProvider)) {
                            // We can trust KeyStore, just determine the level of protection
                            if (secretKeyInfo.isInsideSecureHardware()) {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                                        context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                                    // Keychain encryption key is stored in StrongBox.
                                    keychainProtection = KeychainProtection.STRONGBOX;
                                } else {
                                    // Keychain encryption key is stored in the dedicated secure hardware, but is not StrongBox backed.
                                    keychainProtection = KeychainProtection.HARDWARE;
                                }
                            } else {
                                // Keychain encryption key is not stored in the dedicated secure hardware.
                                keychainProtection = KeychainProtection.SOFTWARE;
                            }
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
