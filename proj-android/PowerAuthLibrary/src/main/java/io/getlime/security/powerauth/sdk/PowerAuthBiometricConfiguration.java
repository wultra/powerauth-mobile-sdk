/*
 * Copyright 2025 Wultra s.r.o.
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

/**
 * Class representing the biometric settings for {@link PowerAuthSDK} class.
 */
public class PowerAuthBiometricConfiguration {

    private final boolean invalidateBiometricFactorAfterChange;
    private final boolean confirmBiometricAuthentication;
    private final boolean authenticateOnBiometricKeySetup;
    private final boolean enableFallbackToSharedBiometryKey;

    /**
     * Get information whether the biometric factor is invalidated when the biometric configuration changes
     * in the system.
     * <p>
     * If set, then the biometric factor key in {@code PowerAuthSDK} instance is invalidated if fingers are added or removed,
     * or if the user re-enrolls for face. The default value is {@code true} (e.g. changing biometry
     * in the system invalidate the entry)
     *
     * @return {@code true} when items protected with biometry are linked to the current set
     *         of biometry, configured in the system.
     */
    public boolean isInvalidateBiometricFactorAfterChange() {
        return invalidateBiometricFactorAfterChange;
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
     * Private constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param invalidateBiometricFactorAfterChange  If set, then the biometric factor is invalidated
     *                                              if fingers are added or removed, or if the user re-enrolls for face.
     * @param confirmBiometricAuthentication        If set, then the user's confirmation will be required after the successful
     *                                              biometric authentication. Note that this is just hint for the system
     *                                              and may be ignored.
     * @param authenticateOnBiometricKeySetup       If set, then the biometric key setup always require biometric authentication.
     *                                              If not set, then only usage of biometric key require biometric authentication.
     * @param enableFallbackToSharedBiometryKey     If set, then the PowerAuthSDK does one more additional lookup to use legacy
     *                                              key shared between multiple PowerAuthSDK instances.
     */
    private PowerAuthBiometricConfiguration(
            boolean invalidateBiometricFactorAfterChange,
            boolean confirmBiometricAuthentication,
            boolean authenticateOnBiometricKeySetup,
            boolean enableFallbackToSharedBiometryKey) {
        this.invalidateBiometricFactorAfterChange = invalidateBiometricFactorAfterChange;
        this.confirmBiometricAuthentication = confirmBiometricAuthentication;
        this.authenticateOnBiometricKeySetup = authenticateOnBiometricKeySetup;
        this.enableFallbackToSharedBiometryKey = enableFallbackToSharedBiometryKey;
    }

    /**
     * Internal constructor that create the biometric configuration from provided keychain configuration.
     * @noinspection deprecation
     */
    // @Deprecated // 2.0.0
    PowerAuthBiometricConfiguration(@NonNull PowerAuthKeychainConfiguration keychainConfiguration) {
        this.invalidateBiometricFactorAfterChange = keychainConfiguration.isLinkBiometricItemsToCurrentSet();
        this.confirmBiometricAuthentication = keychainConfiguration.isConfirmBiometricAuthentication();
        this.authenticateOnBiometricKeySetup = keychainConfiguration.isAuthenticateOnBiometricKeySetup();
        this.enableFallbackToSharedBiometryKey = keychainConfiguration.isFallbackToSharedBiometryKeyEnabled();
    }

    public static final boolean DEFAULT_INVALIDATE_BIOMETRIC_FACTOR_AFTER_CHANGE = true;
    public static final boolean DEFAULT_CONFIRM_BIOMETRIC_AUTHENTICATION = false;
    public static final boolean DEFAULT_AUTHENTICATE_ON_BIOMETRIC_KEY_SETUP = true;
    public static final boolean DEFAULT_ENABLE_FALLBACK_TO_SHARED_BIOMETRY_KEY = true;

    /**
     * A builder that collects arguments for {@link PowerAuthBiometricConfiguration}.
     */
    public static class Builder {

        private boolean invalidateBiometricFactorAfterChange = DEFAULT_INVALIDATE_BIOMETRIC_FACTOR_AFTER_CHANGE;
        private boolean confirmBiometricAuthentication = DEFAULT_CONFIRM_BIOMETRIC_AUTHENTICATION;
        private boolean authenticateOnBiometricKeySetup = DEFAULT_AUTHENTICATE_ON_BIOMETRIC_KEY_SETUP;
        private boolean enableFallbackToSharedBiometryKey = DEFAULT_ENABLE_FALLBACK_TO_SHARED_BIOMETRY_KEY;

        /**
         * Creates a builder for {@link PowerAuthBiometricConfiguration}.
         */
        public Builder() {
        }

        /**
         * Set whether the biometric factor should be invalidated if fingers are added or removed, or if the user
         * re-enrolls for face.
         *
         * @param invalidateBiometricFactorAfterChange If set, then the biometric factor is invalidated if fingers are
         *                                             added or removed, or if the user re-enrolls for face.
         * @return {@link PowerAuthBiometricConfiguration.Builder}
         */
        public @NonNull PowerAuthBiometricConfiguration.Builder invalidateBiometricFactorAfterChange(boolean invalidateBiometricFactorAfterChange) {
            this.invalidateBiometricFactorAfterChange = invalidateBiometricFactorAfterChange;
            return this;
        }

        /**
         * Set whether the user's confirmation will be required after the successful biometric authentication.
         *
         * @param confirmBiometricAuthentication If set, then the user's confirmation will be required after the successful
         *                                       biometric authentication. Note that this is just hint for the system
         *                                       and may be ignored.
         * @return {@link PowerAuthBiometricConfiguration.Builder}
         */
        public @NonNull PowerAuthBiometricConfiguration.Builder confirmBiometricAuthentication(boolean confirmBiometricAuthentication) {
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
         * @return {@link PowerAuthBiometricConfiguration.Builder}
         */
        public @NonNull PowerAuthBiometricConfiguration.Builder authenticateOnBiometricKeySetup(boolean authenticate) {
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
         * @return {@link PowerAuthBiometricConfiguration.Builder}
         */
        public @NonNull PowerAuthBiometricConfiguration.Builder enableFallbackToSharedBiometryKey(boolean enable) {
            this.enableFallbackToSharedBiometryKey = enable;
            return this;
        }

        /**
         * Build final {@link PowerAuthBiometricConfiguration} object.
         *
         * @return New instance of {@link PowerAuthBiometricConfiguration}.
         */
        public @NonNull PowerAuthBiometricConfiguration build() {
            return new PowerAuthBiometricConfiguration(
                    invalidateBiometricFactorAfterChange,
                    confirmBiometricAuthentication,
                    authenticateOnBiometricKeySetup,
                    enableFallbackToSharedBiometryKey);
        }
    }
}
