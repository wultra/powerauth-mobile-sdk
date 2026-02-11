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

import android.annotation.SuppressLint;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.core.CoreAlgorithm;
import io.getlime.security.powerauth.core.CoreConfig;
import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Class representing a configuration of a single PowerAuthSDK instance.
 */
public class PowerAuthConfiguration {

    private final @NonNull String instanceId;
    private final @NonNull String baseEndpointUrl;
    private final @NonNull String configuration;
    private final int offlineAuthenticationCodeComponentLength;
    private final @PowerAuthAlgorithm int algorithm;

    /**
     * Constant for default PowerAuthSDK instance identifier.
     */
    public static final String DEFAULT_INSTANCE_ID = "defaultPowerAuthInstance";

    /**
     * @return Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
     */
    public @NonNull String getInstanceId() {
        return instanceId;
    }

    /**
     * @return Algorithm specified for communication with the server.
     */
    public @PowerAuthAlgorithm int getAlgorithm() {
        return algorithm;
    }

    /**
     * @return String with base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
     */
    public @NonNull String getBaseEndpointUrl() {
        return baseEndpointUrl;
    }

    /**
     * @return String containing cryptographic configuration.
     */
    public @NonNull String getConfiguration() {
        return configuration;
    }

    /**
     * Property is deprecated. EEK is no longer supported in SDK.
     * @return Always {@code null}.
     * @deprecated EEK is no longer supported in SDK.
     */
    @Deprecated // 2.0.0
    public @Nullable SecureData getExternalEncryptionKey() {
        return null;
    }

    /**
     * Property is deprecated. Disabling protocol upgrade has no effect in this version of SDK.
     * @return Always {@code false}.
     */
    @Deprecated // 2.0.0
    public boolean isAutomaticProtocolUpgradeDisabled() {
        return false;
    }

    /**
     * @return Length of offline authentication code component.
     */
    public int getOfflineAuthenticationCodeComponentLength() {
        return offlineAuthenticationCodeComponentLength;
    }

    /**
     * @return Length of offline authentication code component.
     */
    @Deprecated // 2.0.0
    public int getOfflineSignatureComponentLength() {
        return offlineAuthenticationCodeComponentLength;
    }

    /**
     * Minimum allowed length of offline authentication code component.
     */
    public static final int MIN_OFFLINE_AUTHENTICATION_CODE_COMPONENT_LENGTH = 4;

    /**
     * Maximum allowed length of offline authentication code component.
     */
    public static final int MAX_OFFLINE_AUTHENTICATION_CODE_COMPONENT_LENGTH = 8;

    /**
     * Validate the configuration. Be aware that the method performs just a formal validation, so it cannot detect if you
     * provide a wrong cryptographic keys or secrets.
     *
     * @return Always returns {@code true}. See deprecation.
     * @deprecated Method is deprecated. The configuration is validated at the time of its construction.
     */
    @Deprecated // 2.0.0
    public boolean validateConfiguration() {
        return true;
    }

    /**
     * Private default constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
     * @param baseEndpointUrl Base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
     * @param configuration SDK configuration string.
     * @param algorithm Algorithm selected for communication with the server.
     * @param offlineAuthenticationCodeComponentLength Length of component in offline authentication code.
     */
    private PowerAuthConfiguration(
            @NonNull String instanceId,
            @NonNull String baseEndpointUrl,
            @NonNull String configuration,
            int offlineAuthenticationCodeComponentLength,
            @PowerAuthAlgorithm int algorithm) {
        this.instanceId = instanceId;
        this.baseEndpointUrl = baseEndpointUrl;
        this.configuration = configuration;
        this.offlineAuthenticationCodeComponentLength = offlineAuthenticationCodeComponentLength;
        this.algorithm = algorithm;
    }

    /**
     * A builder that collects arguments for {@link PowerAuthConfiguration}.
     */
    public static class Builder {
        // mandatory
        private final @NonNull String baseEndpointUrl;
        private final @NonNull String configuration;
        // optional
        private String instanceId;
        private int offlineAuthenticationCodeComponentLength = MAX_OFFLINE_AUTHENTICATION_CODE_COMPONENT_LENGTH;
        private @PowerAuthAlgorithm int algorithm = PowerAuthAlgorithm.DEFAULT;

        /**
         * Creates a builder for {@link PowerAuthConfiguration}.
         *
         * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state. If {@code null}, then {@link #DEFAULT_INSTANCE_ID} is used.
         * @param baseEndpointUrl Base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
         * @param configuration String with the cryptographic configuration.
         */
        public Builder(@Nullable String instanceId, @NonNull String baseEndpointUrl, @NonNull String configuration) {
            this.instanceId = instanceId;
            this.configuration = configuration;
            if (baseEndpointUrl.endsWith("/")) { // make sure to remove trailing slash
                this.baseEndpointUrl = baseEndpointUrl.substring(0, baseEndpointUrl.length() - 1);
            } else {
                this.baseEndpointUrl = baseEndpointUrl;
            }
        }

        /**
         * Set instance identifier.
         *
         * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
         * @return {@link Builder}
         */
        public @NonNull Builder instanceId(@NonNull String instanceId) {
            this.instanceId = instanceId;
            return this;
        }

        /**
         * Set algorithm for communication with the server.
         * @param algorithm Algorithm for communication.
         * @return {@link Builder}
         */
        public @NonNull Builder algorithm(@PowerAuthAlgorithm int algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Property is deprecated. EEK is no longer supported in SDK>
         * @param externalEncryptionKey Encryption key provided by an external context.
         * @return {@link Builder}
         * @deprecated EEK is no longer supported in SDK.
         */
        @Deprecated // 2.0.0
        public @NonNull Builder externalEncryptionKey(@NonNull SecureData externalEncryptionKey) {
            return this;
        }

        /**
         * Disable automatic protocol upgrade.
         * @deprecated Option is deprecated and has no effect in PowerAuth Mobile SDK 2.0+.
         * @return {@link Builder}
         */
        @Deprecated // 2.0.0
        public @NonNull Builder disableAutomaticProtocolUpgrade() {
            return this;
        }

        /**
         * Set the alternative length for offline authentication code component.
         * @param length New value for offline signature component length.
         * @return {@link Builder}
         */
        public @NonNull Builder offlineAuthenticationCodeComponentLength(int length) {
            this.offlineAuthenticationCodeComponentLength = length;
            return this;
        }

        /**
         * Set the alternative length for offline authentication code component.
         * @param length New value for offline signature component length.
         * @return {@link Builder}
         * @deprecated Use {@link #offlineAuthenticationCodeComponentLength(int)} as replacement.
         */
        @Deprecated // 2.0.0
        public @NonNull Builder offlineSignatureComponentLength(int length) {
            this.offlineAuthenticationCodeComponentLength = length;
            return this;
        }

        /**
         * Build a final {@link PowerAuthConfiguration} instance.
         * @return New instance of {@link PowerAuthConfiguration}.
         * @throws PowerAuthErrorException With {@link PowerAuthErrorCodes#WRONG_PARAMETER} in case the wrong parameter is used in the configuration.
         */
        public @NonNull PowerAuthConfiguration build() throws PowerAuthErrorException {
            if (!CoreConfig.validateConfiguration(configuration, algorithm)) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid SDK configuration");
            }
            if (offlineAuthenticationCodeComponentLength < MIN_OFFLINE_AUTHENTICATION_CODE_COMPONENT_LENGTH ||
                offlineAuthenticationCodeComponentLength > MAX_OFFLINE_AUTHENTICATION_CODE_COMPONENT_LENGTH) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "offlineAuthenticationCodeComponentLength is out of supported range");
            }
            if (instanceId == null) {
                instanceId = DEFAULT_INSTANCE_ID;
            }
            if (TextUtils.isEmpty(instanceId)) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "instanceId is empty");
            }
            if (TextUtils.isEmpty(baseEndpointUrl)) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "baseEndpointUrl is empty");
            }
            return new PowerAuthConfiguration(
                    instanceId,
                    baseEndpointUrl,
                    configuration,
                    offlineAuthenticationCodeComponentLength,
                    algorithm);
        }
    }

    /**
     * Internal function converts configuration from application into {@link CoreConfig} object.
     * @param deviceSpecificData Device specific data.
     * @return {@link CoreConfig} instance.
     * @throws PowerAuthErrorException In case that configuration is invalid.
     */
    @NonNull
    CoreConfig getCoreConfiguration(@NonNull byte[] deviceSpecificData) throws PowerAuthErrorException {
        try {
            return CoreConfig.build(configuration, deviceSpecificData, instanceId, toCoreAlgorithm(algorithm));
        } catch (CoreException e) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid SDK configuration", e);
        }
    }

    /**
     * Convert {@link PowerAuthAlgorithm} into {@link CoreAlgorithm} constant.
     * @param algorithm {@link PowerAuthAlgorithm} constant.
     * @return {@link CoreAlgorithm} constant.
     */
    @SuppressLint("WrongConstant")
    @CoreAlgorithm
    private static int toCoreAlgorithm(@PowerAuthAlgorithm int algorithm) {
        // @PowerAuthAlgorithm is defined from @CoreAlgorithm constants, so direct return
        // with suppressed warning is OK.
        return algorithm;
    }
}
