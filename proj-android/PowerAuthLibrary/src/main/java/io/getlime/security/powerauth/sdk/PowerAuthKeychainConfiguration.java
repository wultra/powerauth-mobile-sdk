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

import androidx.annotation.NonNull;

import androidx.annotation.Nullable;
import io.getlime.security.powerauth.keychain.KeychainProtection;

/**
 * Class representing the keychain settings.
 */
public class PowerAuthKeychainConfiguration {

    public static final String KEYCHAIN_ID_STATUS = "io.getlime.PowerAuthKeychain.StatusKeychain";
    public static final String KEYCHAIN_ID_BIOMETRY = "io.getlime.PowerAuthKeychain.BiometryKeychain";
    public static final String KEYCHAIN_ID_TOKEN_STORE = "io.getlime.PowerAuthKeychain.TokenStoreKeychain";
    public static final String KEYCHAIN_KEY_BIOMETRY_DEFAULT = null;
    public static final String KEYCHAIN_KEY_SHARED_BIOMETRY_KEY = "io.getlime.PowerAuthKeychain.BiometryKeychain.DefaultKey";
    public static final boolean DEFAULT_LINK_BIOMETRY_ITEMS_TO_CURRENT_SET = true;
    public static final boolean DEFAULT_CONFIRM_BIOMETRIC_AUTHENTICATION = false;
    public static final boolean DEFAULT_AUTHENTICATE_ON_BIOMETRIC_KEY_SETUP = true;
    public static final boolean DEFAULT_ENABLE_FALLBACK_TO_SHARED_BIOMETRY_KEY = true;
    public static final @KeychainProtection int DEFAULT_REQUIRED_KEYCHAIN_PROTECTION = KeychainProtection.NONE;

    private final @NonNull String keychainIdStatus;
    private final @NonNull String keychainIdBiometry;
    private final @NonNull String keychainIdTokenStore;
    private final @Nullable String keychainKeyBiometry;
    private final boolean linkBiometricItemsToCurrentSet;
    private final boolean confirmBiometricAuthentication;
    private final boolean authenticateOnBiometricKeySetup;
    private final boolean enableFallbackToSharedBiometryKey;
    private final @KeychainProtection int minimalRequiredKeychainProtection;

    /**
     * Get name of the Keychain file used for storing status information.
     * @return Name of the Keychain file.
     */
    public @NonNull String getKeychainStatusId() {
        return keychainIdStatus;
    }

    /**
     * Get name of the Keychain file used for storing biometry key information.
     * @return Name of the Keychain file.
     */
    public @NonNull String getKeychainBiometryId() {
        return keychainIdBiometry;
    }

    /**
     * Get name of the Keychain key used for storing the default biometry key information.
     * @return Name of the default biometry Keychain key.
     * @deprecated Use {@link #getKeychainKeyBiometry()} method instead.
     */
    @Deprecated // 1.7.10 - remove in 1.10.0
    public @NonNull String getKeychainBiometryDefaultKey() {
       return keychainKeyBiometry == null ? KEYCHAIN_KEY_SHARED_BIOMETRY_KEY : keychainKeyBiometry;
    }

    /**
     * Get name of the Keychain key used for storing the biometry key information for the PowerAuthSDK instance. If null
     * then PowerAuthSDK instance will use its instance identifier to store the biometry key information.
     * @return Get name of the Keychain key used for storing the biometry key information for the PowerAuthSDK instance.
     */
    public @Nullable String getKeychainKeyBiometry() {
        return keychainKeyBiometry;
    }

    /**
     * Get name of the Keychain file used for storing access tokens.
     * @return Name of the Keychain file.
     */
    public @NonNull String getKeychainTokenStoreId() {
        return keychainIdTokenStore;
    }

    /**
     * Get information whether item protected with the biometry is invalidated when the biometric
     * configuration changes in the system.
     * <p>
     * If set, then the item protected with the biometry is invalidated if fingers are added or removed,
     * or if the user re-enrolls for face. The default value is {@code true} (e.g. changing biometry
     * in the system invalidate the entry)
     *
     * @return {@code true} when items protected with biometry are linked to the current set
     *         of biometry, configured in the system.
     */
    public boolean isLinkBiometricItemsToCurrentSet() {
        return linkBiometricItemsToCurrentSet;
    }

    /**
     * Get information whether additional user's confirmation should be required after the successful
     * biometric authentication.
     *
     * @return {@code true} if additional user's confirmation should be required after the successful
     *         biometric authentication.
     */
    public boolean isConfirmBiometricAuthentication() {
        return confirmBiometricAuthentication;
    }

    /**
     * Get whether biometric authentication is required also for biometric key setup.
     *
     * @return {@code true} if biometric authentication is required for biometric key setup.
     */
    public boolean isAuthenticateOnBiometricKeySetup() {
        return authenticateOnBiometricKeySetup;
    }

    /**
     * Get whether fallback to shared, legacy biometry key is enabled. By default, this is enabled for the compatibility
     * reasons. If set, then {@code PowerAuthSDK} does additional lookup for a legacy biometric key, previously shared
     * between multiple {@code PowerAuthSDK} object instances.
     *
     * @return {@code true} if fallback to shared, legacy biometry key is enabled.
     */
    public boolean isFallbackToSharedBiometryKeyEnabled() {
        return enableFallbackToSharedBiometryKey;
    }

    /**
     * Get minimal required keychain protection level that must be supported on the current device.
     * If the level of protection on the device is insufficient, then you cannot use PowerAuth
     * mobile SDK on the device. If not configured, then {@link KeychainProtection#NONE} is used
     * as a default value.
     *
     * @return {@link KeychainProtection} constant that represents minimal required protection level
     * that must be supported on the current device.
     */
    public @KeychainProtection int getMinimalRequiredKeychainProtection() {
        return minimalRequiredKeychainProtection;
    }

    /**
     * Private constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param keychainIdStatus                  Name of the Keychain file used for storing the status information.
     * @param keychainIdBiometry                Name of the Keychain file used for storing the biometry key information.
     * @param keychainKeyBiometry               Name of the Keychain key used for storing the biometry key information for the PowerAuthSDK instance.
     * @param keychainIdTokenStore              Name of the Keychain file used for storing the access tokens.
     * @param linkBiometricItemsToCurrentSet    If set, then the item protected with the biometry is invalidated
     *                                          if fingers are added or removed, or if the user re-enrolls for face.
     * @param confirmBiometricAuthentication    If set, then the user's confirmation will be required after the successful
     *                                          biometric authentication. Note that this is just hint for the system
     *                                          and may be ignored.
     * @param authenticateOnBiometricKeySetup   If set, then the biometric key setup always require biometric authentication.
     *                                          If not set, then only usage of biometric key require biometric authentication.
     * @param enableFallbackToSharedBiometryKey If set, then the PowerAuthSDK does one more additional lookup to use legacy
     *                                          key shared between multiple PowerAuthSDK instances.
     * @param minimalRequiredKeychainProtection {@link KeychainProtection} constant with minimal required keychain
     *                                          protection level that must be supported on the current device.
     */
    private PowerAuthKeychainConfiguration(
            @NonNull String keychainIdStatus,
            @NonNull String keychainIdBiometry,
            @Nullable String keychainKeyBiometry,
            @NonNull String keychainIdTokenStore,
            boolean linkBiometricItemsToCurrentSet,
            boolean confirmBiometricAuthentication,
            boolean authenticateOnBiometricKeySetup,
            boolean enableFallbackToSharedBiometryKey,
            @KeychainProtection int minimalRequiredKeychainProtection) {
        this.keychainIdStatus = keychainIdStatus;
        this.keychainIdBiometry = keychainIdBiometry;
        this.keychainKeyBiometry = keychainKeyBiometry;
        this.keychainIdTokenStore = keychainIdTokenStore;
        this.linkBiometricItemsToCurrentSet = linkBiometricItemsToCurrentSet;
        this.confirmBiometricAuthentication = confirmBiometricAuthentication;
        this.authenticateOnBiometricKeySetup = authenticateOnBiometricKeySetup;
        this.enableFallbackToSharedBiometryKey = enableFallbackToSharedBiometryKey;
        this.minimalRequiredKeychainProtection = minimalRequiredKeychainProtection;
    }

    /**
     * A builder that collects arguments for {@link PowerAuthKeychainConfiguration}.
     */
    public static class Builder {

        private @NonNull String keychainStatusId = KEYCHAIN_ID_STATUS;
        private @NonNull String keychainBiometryId = KEYCHAIN_ID_BIOMETRY;
        private @NonNull String keychainTokenStoreId = KEYCHAIN_ID_TOKEN_STORE;
        private @Nullable String keychainKeyBiometry = KEYCHAIN_KEY_BIOMETRY_DEFAULT;
        private boolean linkBiometricItemsToCurrentSet = DEFAULT_LINK_BIOMETRY_ITEMS_TO_CURRENT_SET;
        private boolean confirmBiometricAuthentication = DEFAULT_CONFIRM_BIOMETRIC_AUTHENTICATION;
        private boolean authenticateOnBiometricKeySetup = DEFAULT_AUTHENTICATE_ON_BIOMETRIC_KEY_SETUP;
        private boolean enableFallbackToSharedBiometryKey = DEFAULT_ENABLE_FALLBACK_TO_SHARED_BIOMETRY_KEY;
        private @KeychainProtection int minimalRequiredKeychainProtection = DEFAULT_REQUIRED_KEYCHAIN_PROTECTION;

        /**
         * Creates a builder for {@link PowerAuthKeychainConfiguration}.
         */
        public Builder() {
        }

        /**
         * Set name of the Keychain file used for storing the status information.
         *
         * @param keychainStatusId Name of the Keychain file used for storing the status information.
         * @return {@link Builder}
         */
        public @NonNull Builder keychainStatusId(@NonNull String keychainStatusId) {
            this.keychainStatusId = keychainStatusId;
            return this;
        }

        /**
         * Set name of the Keychain file used for storing the biometry key information.
         *
         * @param keychainBiometryId Name of the Keychain file used for storing the biometry key information.
         * @return {@link Builder}
         */
        public @NonNull Builder keychainBiometryId(@NonNull String keychainBiometryId) {
            this.keychainBiometryId = keychainBiometryId;
            return this;
        }

        /**
         * Set name of the Keychain file used for storing the access tokens.
         *
         * @param keychainTokenStoreId Name of the Keychain file used for storing the access tokens.
         * @return {@link Builder}
         */
        public @NonNull Builder keychainTokenStoreId(@NonNull String keychainTokenStoreId) {
            this.keychainTokenStoreId = keychainTokenStoreId;
            return this;
        }

        /**
         * Set name of the Keychain key used to store the default biometry key.
         *
         * @param keychainKeyBiometry Name of the Keychain key used to store the default biometry key.
         * @return {@link Builder}
         * @deprecated Use {@link #keychainKeyBiometry(String)} as a replacement.
         */
        @Deprecated // 1.7.10 - remove in 1.10.0
        public @NonNull Builder keychainBiometryDefaultKey(@NonNull String keychainKeyBiometry) {
            this.keychainKeyBiometry = keychainKeyBiometry;
            return this;
        }

        /**
         * Set the name of the key to the biometry Keychain to store biometry-factor protection key.
         * @param keychainKeyBiometry name of the key to biometry keychain to store data containing biometry related encryption key.
         * @return {@link Builder}
         */
        public @NonNull Builder keychainKeyBiometry(@NonNull String keychainKeyBiometry) {
            this.keychainKeyBiometry = keychainKeyBiometry;
            return this;
        }

        /**
         * Set whether the item protected with the biometry is invalidated if fingers are added or
         * removed, or if the user re-enrolls for face.
         *
         * @param linkBiometricItemsToCurrentSet If set, then the item protected with the biometry is invalidated
         *                                       if fingers are added or removed, or if the user re-enrolls for face.
         * @return {@link Builder}
         */
        public @NonNull Builder linkBiometricItemsToCurrentSet(boolean linkBiometricItemsToCurrentSet) {
            this.linkBiometricItemsToCurrentSet = linkBiometricItemsToCurrentSet;
            return this;
        }

        /**
         * Set whether the user's confirmation will be required after the successful biometric authentication.
         *
         * @param confirmBiometricAuthentication If set, then the user's confirmation will be required after the successful
         *                                       biometric authentication. Note that this is just hint for the system
         *                                       and may be ignored.
         * @return {@link Builder}
         */
        public @NonNull Builder confirmBiometricAuthentication(boolean confirmBiometricAuthentication) {
            this.confirmBiometricAuthentication = confirmBiometricAuthentication;
            return this;
        }

        /**
         * (Optional) Set, whether biometric key setup always require a biometric authentication.
         * <p>
         * Setting parameter to {@code true} leads to use symmetric AES cipher on the background,
         * so both configuration and usage of biometric key require the biometric authentication.
         * <p>
         * If set to {@code false}, then RSA cipher is used and only the usage of biometric key
         * require the biometric authentication. This is due to fact, that RSA cipher can encrypt
         * data with using its public key available immediate after the key-pair is created in
         * Android KeyStore.
         * <p>
         * The default value is {@code true}.
         *
         * @param authenticate If set, then biometric authentication is required for both setup and usage
         *                     of biometric key.
         * @return {@link Builder}
         */
        public @NonNull Builder authenticateOnBiometricKeySetup(boolean authenticate) {
            this.authenticateOnBiometricKeySetup = authenticate;
            return this;
        }

        /**
         * (Optional) Set, whether PowerAuthSDK instance should also do additional lookup for a legacy biometric key,
         * previously shared between multiple PowerAuthSDK object instances.
         * <p>
         * The default value is {@code true} and the fallback is enabled.
         *
         * @param enable If {@code true} then fallback to legacy key is enabled.
         * @return {@link Builder}
         */
        public @NonNull Builder enableFallbackToSharedBiometryKey(boolean enable) {
            this.enableFallbackToSharedBiometryKey = enable;
            return this;
        }

        /**
         * Set minimal required keychain protection level that must be supported on the current device. Note that
         * if you enforce protection higher that {@link KeychainProtection#NONE}, then your application must target
         * at least Android 6.0.
         *
         * @param minimalRequiredKeychainProtection {@link KeychainProtection} constant with minimal required keychain
         *                                          protection level that must be supported on the current device.
         * @return {@link Builder}
         */
        public @NonNull Builder minimalRequiredKeychainProtection(@KeychainProtection int minimalRequiredKeychainProtection) {
            this.minimalRequiredKeychainProtection = minimalRequiredKeychainProtection;
            return this;
        }

        /**
         * Build final {@link PowerAuthKeychainConfiguration} object.
         *
         * @return New instance of {@link PowerAuthKeychainConfiguration}.
         */
        public @NonNull PowerAuthKeychainConfiguration build() {
            return new PowerAuthKeychainConfiguration(
                    keychainStatusId,
                    keychainBiometryId,
                    keychainKeyBiometry,
                    keychainTokenStoreId,
                    linkBiometricItemsToCurrentSet,
                    confirmBiometricAuthentication,
                    authenticateOnBiometricKeySetup,
                    enableFallbackToSharedBiometryKey,
                    minimalRequiredKeychainProtection);
        }
    }
}
