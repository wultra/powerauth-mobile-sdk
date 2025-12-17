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

import android.health.connect.datatypes.units.Power;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.core.CoreAlgorithm;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.core.SessionSetup;

/**
 * Class representing a configuration of a single PowerAuthSDK instance.
 */
public class PowerAuthConfiguration {

    private final @NonNull String instanceId;
    private final @NonNull String baseEndpointUrl;
    private final @NonNull SessionSetup sessionSetup;
    private final int offlineAuthorizationCodeComponentLength;
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
        return sessionSetup.configuration;
    }

    /**
     * @return {@link SessionSetup} object with configuration for cryptographic components.
     */
    @NonNull SessionSetup getSessionSetup() {
        return sessionSetup;
    }

    /**
     * @return Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
     */
    public @Nullable SecureData getExternalEncryptionKey() {
        return sessionSetup.externalEncryptionKey;
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
     * @return Length of offline authorization code component.
     */
    public int getOfflineAuthorizationCodeComponentLength() {
        return offlineAuthorizationCodeComponentLength;
    }

    /**
     * @return Length of offline authorization code component.
     */
    @Deprecated // 2.0.0
    public int getOfflineSignatureComponentLength() {
        return offlineAuthorizationCodeComponentLength;
    }

    /**
     * Minimum allowed length of offline authorization code component.
     */
    public static final int MIN_OFFLINE_AUTHORIZATION_CODE_COMPONENT_LENGTH = 4;

    /**
     * Maximum allowed length of offline authorization code component.
     */
    public static final int MAX_OFFLINE_AUTHORIZATION_CODE_COMPONENT_LENGTH = 8;

    /**
     * Validate the configuration. Be aware that the method performs just a formal validation, so it cannot detect if you
     * provide a wrong cryptographic keys or secrets.
     *
     * @return {@code true} if configuration appears to be valid.
     */
    public boolean validateConfiguration() {
        if (!sessionSetup.isValid()) {
            return false;
        }
        return offlineAuthorizationCodeComponentLength >= MIN_OFFLINE_AUTHORIZATION_CODE_COMPONENT_LENGTH &&
                offlineAuthorizationCodeComponentLength <= MAX_OFFLINE_AUTHORIZATION_CODE_COMPONENT_LENGTH;
    }

    /**
     * Private default constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
     * @param baseEndpointUrl Base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
     * @param sessionSetup Setup for core/Session object.
     * @param algorithm Algorithm selected for communication with the server.
     */
    private PowerAuthConfiguration(
            @NonNull String instanceId,
            @NonNull String baseEndpointUrl,
            @NonNull SessionSetup sessionSetup,
            int offlineSignatureComponentLength,
            @PowerAuthAlgorithm int algorithm) {
        this.instanceId = instanceId;
        this.baseEndpointUrl = baseEndpointUrl;
        this.sessionSetup = sessionSetup;
        this.offlineAuthorizationCodeComponentLength = offlineSignatureComponentLength;
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
        private SecureData externalEncryptionKey = null;
        private int offlineAuthorizationCodeComponentLength = MAX_OFFLINE_AUTHORIZATION_CODE_COMPONENT_LENGTH;
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
         * Set external encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
         * @param externalEncryptionKey Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
         * @return {@link Builder}
         */
        public @NonNull Builder externalEncryptionKey(@NonNull SecureData externalEncryptionKey) {
            this.externalEncryptionKey = externalEncryptionKey.copy();
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
         * Set the alternative length for offline authorization code component.
         * @param length New value for offline signature component length.
         * @return {@link Builder}
         */
        public @NonNull Builder offlineAuthorizationCodeComponentLength(int length) {
            this.offlineAuthorizationCodeComponentLength = length;
            return this;
        }

        /**
         * Set the alternative length for offline authorization code component.
         * @param length New value for offline signature component length.
         * @return {@link Builder}
         * @deprecated Use {@link #offlineAuthorizationCodeComponentLength(int)} as replacement.
         */
        @Deprecated // 2.0.0
        public @NonNull Builder offlineSignatureComponentLength(int length) {
            this.offlineAuthorizationCodeComponentLength = length;
            return this;
        }

        /**
         * Build a final {@link PowerAuthConfiguration} instance.
         * @return New instance of {@link PowerAuthConfiguration}.
         */
        public @NonNull PowerAuthConfiguration build() {
            final SessionSetup sessionSetup = new SessionSetup(configuration, externalEncryptionKey);
            return new PowerAuthConfiguration(
                    instanceId != null ? instanceId : DEFAULT_INSTANCE_ID,
                    baseEndpointUrl,
                    sessionSetup,
                    offlineAuthorizationCodeComponentLength,
                    algorithm);
        }
    }
}
