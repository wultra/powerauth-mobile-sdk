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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.Arrays;

import io.getlime.security.powerauth.networking.response.IFetchKeysStrategy;
import io.getlime.security.powerauth.sdk.impl.DefaultFetchKeysStrategy;

/**
 * Class representing a configuration of a single PowerAuthSDK instance.
 */
public class PowerAuthConfiguration {

    private final @NonNull String instanceId;
    private final @NonNull String baseEndpointUrl;
    private final @NonNull String appKey;
    private final @NonNull String appSecret;
    private final @NonNull String masterServerPublicKey;
    private final @Nullable byte[] externalEncryptionKey;
    private final @NonNull IFetchKeysStrategy fetchKeysStrategy;
    private final boolean disableAutomaticProtocolUpgrade;

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
     * @return String with base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
     */
    public @NonNull String getBaseEndpointUrl() {
        return baseEndpointUrl;
    }

    /**
     * @return {@code APPLICATION_KEY} as defined in PowerAuth specification - a key identifying an application version.
     */
    public @NonNull String getAppKey() {
        return appKey;
    }

    /**
     * @return {@code APPLICATION_SECRET} as defined in PowerAuth specification - a secret associated with an application version.
     */
    public @NonNull String getAppSecret() {
        return appSecret;
    }

    /**
     * @return {@code KEY_SERVER_MASTER_PUBLIC} as defined in PowerAuth specification - a master server public key.
     */
    public @NonNull String getMasterServerPublicKey() {
        return masterServerPublicKey;
    }

    /**
     * @return Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
     */
    public @Nullable byte[] getExternalEncryptionKey() {
        return externalEncryptionKey;
    }

    /**
     * @return {@link IFetchKeysStrategy} interface for key providing strategy.
     */
    public @NonNull IFetchKeysStrategy getFetchKeysStrategy() {
        return fetchKeysStrategy;
    }

    /**
     * If set to true, then PowerAuthSDK will not automatically upgrade activation to a newer protocol version.
     * This option should be used only for the testing purposes.
     *
     * @return If set to {@code true}, then PowerAuthSDK will not automatically upgrade activation to a newer protocol version.
     */
    public boolean isAutomaticProtocolUpgradeDisabled() {
        return disableAutomaticProtocolUpgrade;
    }

    /**
     * Validate the configuration. Be aware that the method performs just a formal validation, so it cannot detect if you
     * provide a wrong cryptographic keys or secrets.
     *
     * @return {@code true} if configuration appears to be valid.
     */
    public boolean validateConfiguration() {
        if (externalEncryptionKey != null) {
            if (externalEncryptionKey.length != 16) {
                return false;
            }
        }
        return true;
    }

    /**
     * Private default constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
     * @param baseEndpointUrl Base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
     * @param appKey {@code APPLICATION_KEY} as defined in PowerAuth specification - a key identifying an application version.
     * @param appSecret {@code APPLICATION_SECRET} as defined in PowerAuth specification - a secret associated with an application version.
     * @param masterServerPublicKey {@code KEY_SERVER_MASTER_PUBLIC} as defined in PowerAuth specification - a master server public key.
     * @param externalEncryptionKey Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
     * @param fetchKeysStrategy {@link IFetchKeysStrategy} interface for key providing strategy.
     * @param disableAutomaticProtocolUpgrade If set to {@code true}, then PowerAuthSDK will not automatically upgrade activation to a newer protocol version.
     */
    private PowerAuthConfiguration(
            @NonNull String instanceId,
            @NonNull String baseEndpointUrl,
            @NonNull String appKey,
            @NonNull String appSecret,
            @NonNull String masterServerPublicKey,
            @Nullable byte[] externalEncryptionKey,
            @NonNull IFetchKeysStrategy fetchKeysStrategy,
            boolean disableAutomaticProtocolUpgrade) {
        this.instanceId = instanceId;
        this.baseEndpointUrl = baseEndpointUrl;
        this.appKey = appKey;
        this.appSecret = appSecret;
        this.masterServerPublicKey = masterServerPublicKey;
        this.externalEncryptionKey = externalEncryptionKey;
        this.fetchKeysStrategy = fetchKeysStrategy;
        this.disableAutomaticProtocolUpgrade = disableAutomaticProtocolUpgrade;
    }

    /**
     * A builder that collects arguments for {@link PowerAuthConfiguration}.
     */
    public static class Builder {
        // mandatory
        private final @NonNull String baseEndpointUrl;
        private final @NonNull String appKey;
        private final @NonNull String appSecret;
        private final @NonNull String masterServerPublicKey;
        // optional
        private String instanceId;
        private IFetchKeysStrategy fetchKeysStrategy = null;
        private byte[] externalEncryptionKey = null;
        private boolean disableAutomaticProtocolUpgrade = false;

        /**
         * Creates a builder for {@link PowerAuthConfiguration}.
         *
         * @param instanceId Identifier of the PowerAuthSDK instance, used as a 'key' to store session state. If {@code null}, then {@link #DEFAULT_INSTANCE_ID} is used.
         * @param baseEndpointUrl Base URL to the PowerAuth Standard REST API (the URL part before {@code "/pa/..."}).
         * @param appKey {@code APPLICATION_KEY} as defined in PowerAuth specification - a key identifying an application version.
         * @param appSecret {@code APPLICATION_SECRET} as defined in PowerAuth specification - a secret associated with an application version.
         * @param masterServerPublicKey {@code KEY_SERVER_MASTER_PUBLIC} as defined in PowerAuth specification - a master server public key.
         */
        public Builder(@Nullable String instanceId, @NonNull String baseEndpointUrl, @NonNull String appKey, @NonNull String appSecret, @NonNull String masterServerPublicKey) {
            this.instanceId = instanceId;
            this.appKey = appKey;
            this.appSecret = appSecret;
            this.masterServerPublicKey = masterServerPublicKey;
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
         * Set
         * @param fetchKeysStrategy {@link IFetchKeysStrategy} interface for key providing strategy.
         * @return {@link Builder}
         */
        public @NonNull Builder fetchKeysStrategy(@NonNull IFetchKeysStrategy fetchKeysStrategy) {
            this.fetchKeysStrategy = fetchKeysStrategy;
            return this;
        }

        /**
         * Set external encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
         * @param externalEncryptionKey Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
         * @return {@link Builder}
         */
        public @NonNull Builder externalEncryptionKey(@NonNull byte[] externalEncryptionKey) {
            this.externalEncryptionKey = externalEncryptionKey;
            return this;
        }

        /**
         * Disable automatic protocol upgrade. This option should be used only for the testing purposes.
         * @return {@link Builder}
         */
        public @NonNull Builder disableAutomaticProtocolUpgrade() {
            this.disableAutomaticProtocolUpgrade = true;
            return this;
        }

        /**
         * Build a final {@link PowerAuthConfiguration} instance.
         * @return New instance of {@link PowerAuthConfiguration}.
         */
        public @NonNull PowerAuthConfiguration build() {
            return new PowerAuthConfiguration(
                    instanceId != null ? instanceId : DEFAULT_INSTANCE_ID,
                    baseEndpointUrl,
                    appKey,
                    appSecret,
                    masterServerPublicKey,
                    externalEncryptionKey != null ? Arrays.copyOf(externalEncryptionKey, externalEncryptionKey.length) : null,
                    fetchKeysStrategy != null ? fetchKeysStrategy : new DefaultFetchKeysStrategy(),
                    disableAutomaticProtocolUpgrade);
        }
    }
}
