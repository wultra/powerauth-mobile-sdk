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

import io.getlime.security.powerauth.networking.response.IFetchKeysStrategy;
import io.getlime.security.powerauth.sdk.impl.DefaultFetchKeysStrategy;

/**
 * Class representing a configuration of a single PowerAuthSDK instance.
 *
 * @author miroslavmichalec
 */

public class PowerAuthConfiguration {

    /**
     * Identifier of the PowerAuthSDK instance, used as a 'key' to store session state.
     */
    private String instanceId;

    /**
     * Base URL to the PowerAuth Standard REST API (the URL part before "/pa/...").
     */
    private String baseEndpointUrl;

    /**
     * APPLICATION_KEY as defined in PowerAuth specification - a key identifying an application version.
     */
    private String appKey;

    /**
     * APPLICATION_SECRET as defined in PowerAuth specification - a secret associated with an application version.
     */
    private String appSecret;

    /**
     * KEY_SERVER_MASTER_PUBLIC as defined in PowerAuth specification - a master server public key.
     */
    private String masterServerPublicKey;

    /**
     * Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
     */
    private byte[] externalEncryptionKey;

    /**
     * Interface for key providing strategy
     */
    private IFetchKeysStrategy fetchKeysStrategy;

    /**
     * If set to true, then PowerAuthSDK will not automatically upgrade activation to a newer protocol version.
     * This option should be used only for the testing purposes.
     *
     * Default and recommended value is false.
     */
    private boolean disableAutomaticProtocolUpgrade;

    /**
     * Constant for default PowerAuthSDK instance identifier.
     */
    public static final String DEFAULT_INSTANCE_ID = "defaultPowerAuthInstance";

    public String getInstanceId() {
        if (instanceId != null) {
            return instanceId;
        }
        return DEFAULT_INSTANCE_ID;
    }

    public String getBaseEndpointUrl() {
        return baseEndpointUrl;
    }

    public String getAppKey() {
        return appKey;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public String getMasterServerPublicKey() {
        return masterServerPublicKey;
    }

    public byte[] getExternalEncryptionKey() {
        return externalEncryptionKey;
    }

    public IFetchKeysStrategy getFetchKeysStrategy() {
        return fetchKeysStrategy;
    }

    public boolean isAutomaticProtocolUpgradeDisabled() {
        return disableAutomaticProtocolUpgrade;
    }

    public boolean validateConfiguration() {
        boolean result = appKey != null;
        result = result && appSecret != null;
        result = result && masterServerPublicKey != null;
        result = result && baseEndpointUrl != null;
        return result;
    }

    public static class Builder {
        // mandatory
        private final String instanceId;
        private final String baseEndpointUrl;
        private String appKey;
        private String appSecret;
        private String masterServerPublicKey;
        private IFetchKeysStrategy fetchKeysStrategy;
        // optional
        private byte[] externalEncryptionKey = null;
        private boolean disableAutomaticProtocolUpgrade = false;

        public Builder(@Nullable String instanceId, @NonNull String baseEndpointUrl, @NonNull String appKey, @NonNull String appSecret, @NonNull String masterServerPublicKey) {
            this(instanceId, baseEndpointUrl, appKey, appSecret, masterServerPublicKey, new DefaultFetchKeysStrategy());
        }

        public Builder(@Nullable String instanceId, @NonNull String baseEndpointUrl, @NonNull String appKey, @NonNull String appSecret, @NonNull String masterServerPublicKey, @NonNull IFetchKeysStrategy fetchKeysStrategy) {
            this.instanceId = instanceId;
            this.appKey = appKey;
            this.appSecret = appSecret;
            this.masterServerPublicKey = masterServerPublicKey;
            this.fetchKeysStrategy = fetchKeysStrategy;
            if (baseEndpointUrl.endsWith("/")) { // make sure to remove trailing slash
                this.baseEndpointUrl = baseEndpointUrl.substring(0, baseEndpointUrl.length() - 1);
            } else {
                this.baseEndpointUrl = baseEndpointUrl;
            }
        }

        public Builder externalEncryptionKey(byte[] externalEncryptionKey) {
            this.externalEncryptionKey = externalEncryptionKey;
            return this;
        }

        public Builder disableAutomaticProtocolUpgrade() {
            this.disableAutomaticProtocolUpgrade = true;
            return this;
        }

        public PowerAuthConfiguration build() {
            final PowerAuthConfiguration powerAuthConfiguration = new PowerAuthConfiguration();
            powerAuthConfiguration.instanceId = instanceId;
            powerAuthConfiguration.baseEndpointUrl = baseEndpointUrl;
            powerAuthConfiguration.appKey = appKey;
            powerAuthConfiguration.appSecret = appSecret;
            powerAuthConfiguration.masterServerPublicKey = masterServerPublicKey;
            powerAuthConfiguration.externalEncryptionKey = externalEncryptionKey;
            powerAuthConfiguration.fetchKeysStrategy = fetchKeysStrategy;
            powerAuthConfiguration.disableAutomaticProtocolUpgrade = disableAutomaticProtocolUpgrade;

            return powerAuthConfiguration;
        }
    }
}
