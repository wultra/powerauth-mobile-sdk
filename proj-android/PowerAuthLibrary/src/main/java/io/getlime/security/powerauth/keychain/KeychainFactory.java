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
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import java.util.HashMap;
import java.util.Map;

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
     * @return Instance of {@link Keychain} object.
     */
    @NonNull
    public static Keychain getKeychain(@NonNull Context context, @NonNull String identifier) {
        synchronized (SharedData.class) {
            final SharedData sharedData = getSharedData();
            final Context appContext = context.getApplicationContext();
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
     * Disable keychain encryption for the testing only purposes. The configuration change is not applied
     * to the already created keychains. So, it's recommended to disable the encryption before any keychain
     * is accessed in the method {@link #getKeychain(Context, String)}.
     *
     * <p>
     * <strong>WARNING:</strong> It's not recommended to use this method in the production application.
     * Misuse of this method may lead to the PowerAuth activation lost.
     *
     * @param disable If {@code true} then encryption will be disabled for all subsequently created keychains.
     */
    public static void setKeychainEncryptionDisabled(boolean disable) {
        synchronized (SharedData.class) {
            final SharedData sharedData = getSharedData();
            sharedData.setKeychainEncryptionDisabled(disable);
            PA2Log.d("KeychainFactory: Keychain encryption is now " + (disable ? "disabled" : "enabled"));
        }
    }

    /**
     * @return {@code true} is the keychain encryption is globally disabled.
     */
    public static boolean isKeychainEncryptionDisabled() {
        synchronized (SharedData.class) {
            final SharedData sharedData = getSharedData();
            return sharedData.isKeychainEncryptionDisabled();
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

        final boolean isEncryptionDisabled = sharedData.isKeychainEncryptionDisabled();
        final boolean isAlreadyEncrypted = EncryptedKeychain.isEncryptedContentInSharedPreferences(preferences);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // If Android "M" and later, then create a secret key provider and try to create an encrypted keychain.
            final SymmetricKeyProvider masterKeyProvider = sharedData.getMasterEncryptionKeyProvider();
            if (masterKeyProvider != null) {
                // If this is the first time that the encrypted keychain is instantiated, then verify its functionality.
                if (sharedData.shouldVerifyKeystoreEncryption()) {
                    sharedData.setKeystoreEncryptionVerified(EncryptedKeychain.verifyKeystoreEncryption(context, masterKeyProvider));
                }
                if (sharedData.isKeystoreEncryptionTrusted()) {
                    if (!isEncryptionDisabled) {
                        final EncryptedKeychain encryptedKeychain = new EncryptedKeychain(context, identifier, masterKeyProvider);
                        // Return encrypted keychain, if it's already encrypted or import is successful.
                        if (isAlreadyEncrypted || encryptedKeychain.importFromLegacyKeychain(preferences)) {
                            return encryptedKeychain;
                        }
                    } else {
                        PA2Log.e("KeychainFactory: " + identifier + ": Encryption is supported, but it's disabled.");
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
         * If set to {@code true} then the keychain encryption is disabled globally.
         */
        private boolean disableEncryptedKeychain = false;

        /**
         * Map that contains an already instantiated keychain objects.
         */
        private Map<String, Keychain> keychainMap = new HashMap<>();

        /**
         * Instance of {@link SymmetricKeyProvider} that provides encryption key for all encrypted keychains.
         */
        private SymmetricKeyProvider masterEncryptionKeyProvider;

        /**
         * If true, then Android Keystore encryption should be verified.
         */
        private boolean verifyKeystoreEncryption = true;

        /**
         * If true, then Android Keystore is already verified and trusted.
         */
        private boolean trustedKeystoreEncryption = false;

        /**
         * Disable keychain encryption.
         * @param disable If set to {@code true} then the keychain encryption will be disabled.
         */
        void setKeychainEncryptionDisabled(boolean disable) {
            disableEncryptedKeychain = disable;
        }

        /**
         * @return {@code true} if the keychain encryption is disabled.
         */
        boolean isKeychainEncryptionDisabled() {
            return disableEncryptedKeychain;
        }

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
         * @return {@code true} in case that Android Keystore encryption should be verified for its functionality.
         */
        boolean shouldVerifyKeystoreEncryption() {
            return verifyKeystoreEncryption;
        }

        /**
         * Set Android Keystore encryption as verified with verification result.
         * @param isTrusted {@code true} in case that Android Keystore encryption is trusted.
         */
        void setKeystoreEncryptionVerified(boolean isTrusted) {
            verifyKeystoreEncryption = false;
            trustedKeystoreEncryption = isTrusted;
        }

        /**
         * @return {@code true} in case that Android Keystore encryption is already verified and trusted.
          */
        public boolean isKeystoreEncryptionTrusted() {
            return trustedKeystoreEncryption;
        }
    }
}
