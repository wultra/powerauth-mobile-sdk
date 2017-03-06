/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;

/**
 * Created by miroslavmichalec on 21/10/2016.
 */

/**
 * Class that is used to provide default (shared) RESTful API client configuration.
 */
public class PowerAuthClientConfiguration {

    private static final int DEF_CONNECTION_TIMEOUT = 20 * 1000; //ms
    private static final int DEF_READ_TIMEOUT = 20 * 1000; //ms

    /**
     * Property that specifies the default HTTP client connection timeout. The default value is 20.0 (seconds).
     */
    private int connectionTimeout = DEF_CONNECTION_TIMEOUT;

    /**
     * Property that specifies the default HTTP client read timeout. The default value is 20.0 (seconds).
     */
    private int readTimeout = DEF_READ_TIMEOUT;

    /**
     * Property that specifies the SSL validation strategy applied by the client.
     */
    private PA2ClientValidationStrategy clientValidationStrategy;

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public PA2ClientValidationStrategy getClientValidationStrategy() {
        return clientValidationStrategy;
    }

    public static class Builder {
        private int connectionTimeout = DEF_CONNECTION_TIMEOUT;
        private int readTimeout = DEF_READ_TIMEOUT;
        private PA2ClientValidationStrategy clientValidationStrategy;

        public Builder() {
        }

        public Builder timeouts(int connectionTimeout, int readTimeout) {
            this.connectionTimeout = connectionTimeout;
            this.readTimeout = readTimeout;
            return this;
        }

        public Builder clientValidationStrategy(PA2ClientValidationStrategy clientValidationStrategy) {
            this.clientValidationStrategy = clientValidationStrategy;
            return this;
        }

        public PowerAuthClientConfiguration build() {
            final PowerAuthClientConfiguration powerAuthClientConfiguration = new PowerAuthClientConfiguration();
            powerAuthClientConfiguration.connectionTimeout = connectionTimeout;
            powerAuthClientConfiguration.readTimeout = readTimeout;
            powerAuthClientConfiguration.clientValidationStrategy = clientValidationStrategy;
            return powerAuthClientConfiguration;
        }
    }
}
