/*
 * Copyright 2017 Wultra s.r.o.
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

/**
 * Class representing the keychain settings.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthKeychainConfiguration {

    private static final String KEYCHAIN_ID_STATUS = "io.getlime.PowerAuthKeychain.StatusKeychain";
    private static final String KEYCHAIN_ID_BIOMETRY = "io.getlime.PowerAuthKeychain.BiometryKeychain";
    private static final String KEYCHAIN_ID_TOKEN_STORE = "io.getlime.PowerAuthKeychain.TokenStoreKeychain";
    private static final String KEYCHAIN_KEY_BIOMETRY_DEFAULT = "io.getlime.PowerAuthKeychain.BiometryKeychain.DefaultKey";

    private final String customKeychainIdStatus;
    private final String customKeychainIdBiometry;
    private final String customKeychainKeyBiometryDefault;
    private final String customKeychainIdTokenStore;
    private final boolean associateBiometricItemsToCurrentSet;

    /**
     * Default public constructor.
     */
    public PowerAuthKeychainConfiguration() {
        this.customKeychainIdStatus = null;
        this.customKeychainIdBiometry = null;
        this.customKeychainKeyBiometryDefault = null;
        this.customKeychainIdTokenStore = null;
        this.associateBiometricItemsToCurrentSet = true;
    }

    /**
     * Constructor that allows key name customization, in case it is required.
     *
     * @param customKeychainIdStatus Name of the Keychain file used for storing the status information.
     * @param customKeychainIdBiometry Name of the Keychain file used for storing the biometry key information.
     * @param customKeychainKeyBiometryDefault Name of the Keychain key used to store the default biometry key.
     */
    public PowerAuthKeychainConfiguration(
            String customKeychainIdStatus,
            String customKeychainIdBiometry,
            String customKeychainKeyBiometryDefault) {
        this.customKeychainIdStatus = customKeychainIdStatus;
        this.customKeychainIdBiometry = customKeychainIdBiometry;
        this.customKeychainKeyBiometryDefault = customKeychainKeyBiometryDefault;
        this.customKeychainIdTokenStore = null;
        this.associateBiometricItemsToCurrentSet = true;
    }

    /**
     * Constructor that allows token store keychain file customization, in case it is required.
     *
     * @param customKeychainIdStatus Name of the Keychain file used for storing the status information.
     * @param customKeychainIdBiometry Name of the Keychain file used for storing the biometry key information.
     * @param customKeychainKeyBiometryDefault Name of the Keychain key used to store the default biometry key.
     * @param customKeychainIdTokenStore Name of the Keychain file used for storing the access tokens.
     * @param associateBiometricItemsToCurrentSet If set, then the item protected with the biometry is invalidated
     *                                            if fingers are added or removed, or if the user re-enrolls for face.
     */
    public PowerAuthKeychainConfiguration(
            String customKeychainIdStatus,
            String customKeychainIdBiometry,
            String customKeychainKeyBiometryDefault,
            String customKeychainIdTokenStore,
            boolean associateBiometricItemsToCurrentSet) {
        this.customKeychainIdStatus = customKeychainIdStatus;
        this.customKeychainIdBiometry = customKeychainIdBiometry;
        this.customKeychainKeyBiometryDefault = customKeychainKeyBiometryDefault;
        this.customKeychainIdTokenStore = customKeychainIdTokenStore;
        this.associateBiometricItemsToCurrentSet = associateBiometricItemsToCurrentSet;
    }

    /**
     * Get name of the Keychain file used for storing status information.
     * @return Name of the Keychain file.
     */
    public String getKeychainStatusId() {
        if (customKeychainIdStatus != null) {
            return customKeychainIdStatus;
        }
        return KEYCHAIN_ID_STATUS;
    }

    /**
     * Get name of the Keychain file used for storing biometry key information.
     * @return Name of the Keychain file.
     */
    public String getKeychainBiometryId() {
        if (customKeychainIdBiometry != null) {
            return customKeychainIdBiometry;
        }
        return KEYCHAIN_ID_BIOMETRY;
    }

    /**
     * Get name of the Keychain key used for storing the default biometry key information.
     * @return Name of the biometry Keychain key.
     */
    public String getKeychainBiometryDefaultKey() {
        if (customKeychainKeyBiometryDefault != null) {
            return customKeychainKeyBiometryDefault;
        }
        return KEYCHAIN_KEY_BIOMETRY_DEFAULT;
    }

    /**
     * Get name of the Keychain file used for storing access tokens.
     * @return Name of the Keychain file.
     */
    public String getKeychainTokenStoreId() {
        if (customKeychainIdTokenStore != null) {
            return customKeychainIdTokenStore;
        }
        return KEYCHAIN_ID_TOKEN_STORE;
    }

    /**
     * Get information whether item protected with the biometry is invalidated when the biometric
     * configuration changes in the system.
     *
     * If set, then the item protected with the biometry is invalidated if fingers are added or removed,
     * or if the user re-enrolls for face. The default value is {@code true} (e.g. changing biometry
     * in the system invalidate the entry)
     *
     * @return {@code true} when items protected with biometry are linked to the current set
     *         of biometry, configured in the system.
     */
    public boolean isAssociateBiometricItemsToCurrentSet() {
        return associateBiometricItemsToCurrentSet;
    }
}
