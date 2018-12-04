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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * Created by miroslavmichalec on 21/10/2016.
 */

/**
 * Class that is used to provide default (shared) RESTful API client configuration.
 */
public class PowerAuthClientConfiguration {

    private static final int DEF_CONNECTION_TIMEOUT = 20 * 1000; //ms
    private static final int DEF_READ_TIMEOUT = 20 * 1000; //ms
    private static final boolean DEF_ALLOW_UNSECURED_CONNECTION = false;

    /**
     * Property that specifies the default HTTP client connection timeout. The default value is 20.0 (seconds).
     */
    private int connectionTimeout = DEF_CONNECTION_TIMEOUT;

    /**
     * Property that specifies the default HTTP client read timeout. The default value is 20.0 (seconds).
     */
    private int readTimeout = DEF_READ_TIMEOUT;

    /**
     * Property that specifies whether it's possible to connect to non-TLS endpoints.
     *
     * WARNING
     *
     * You should never allow unsecured connections to production-grade servers.
     */
    private boolean allowUnsecuredConnection = DEF_ALLOW_UNSECURED_CONNECTION;

    /**
     * Property that specifies the SSL validation strategy applied by the client.
     */
    private PA2ClientValidationStrategy clientValidationStrategy;

    /**
     * Property that specifies the list of request interceptors used by the client before the request is executed.
     */
    private List<HttpRequestInterceptor> requestInterceptors;

    /**
     * @return connection timeout in milliseconds
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * @return read timeout in milliseconds
     */
    public int getReadTimeout() {
        return readTimeout;
    }

    /**
     * @return true if unsecured connections are allowed
     */
    public boolean isUnsecuredConnectionAllowed() { return allowUnsecuredConnection; }

    /**
     * @return Validation strategy
     */
    public PA2ClientValidationStrategy getClientValidationStrategy() {
        return clientValidationStrategy;
    }

    /**
     * @return immutable list of request interceptors or null if there's no interceptor assigned.
     */
    public @Nullable List<HttpRequestInterceptor> getRequestInterceptors() {
        return requestInterceptors;
    }

    public static class Builder {
        private int connectionTimeout = DEF_CONNECTION_TIMEOUT;
        private int readTimeout = DEF_READ_TIMEOUT;
        private boolean allowUnsecuredConnection = DEF_ALLOW_UNSECURED_CONNECTION;
        private PA2ClientValidationStrategy clientValidationStrategy;
        private ArrayList<HttpRequestInterceptor> requestInterceptors;

        public Builder() {
        }

        /**
         * Sets timeouts to the future configuration.
         *
         * @param connectionTimeout connection timeout in milliseconds
         * @param readTimeout read timeout in milliseconds
         * @return The same {@link Builder} object instance
         */
        public Builder timeouts(int connectionTimeout, int readTimeout) {
            this.connectionTimeout = connectionTimeout;
            this.readTimeout = readTimeout;
            return this;
        }

        /**
         * Enables or disables connection to unsecured servers.
         *
         * @param allow true if unsecured connection should be allowed.
         * @return The same {@link Builder} object instance
         */
        public Builder allowUnsecuredConnection(boolean allow) {
            this.allowUnsecuredConnection = allow;
            if (allow) {
                 PA2Log.e("Unsecured connection is dangerous for production application.");
            }
            return this;
        }

        /**
         * Sets TLS client validation strategy to the future configuration.
         *
         * @param clientValidationStrategy strategy to be set
         * @return The same {@link Builder} object instance
         */
        public Builder clientValidationStrategy(PA2ClientValidationStrategy clientValidationStrategy) {
            this.clientValidationStrategy = clientValidationStrategy;
            return this;
        }

        /**
         * Adds request interceptor to the future configuration.
         *
         * @param interceptor interceptor to be added
         * @return The same {@link Builder} object instance
         */
        public Builder requestInterceptor(@NonNull HttpRequestInterceptor interceptor) {
            if (requestInterceptors == null) {
                requestInterceptors = new ArrayList<>();
            }
            requestInterceptors.add(interceptor);
            return this;
        }

        /**
         * Build a final configuration.
         *
         * @return Final {@link PowerAuthClientConfiguration} instance.
         */
        public PowerAuthClientConfiguration build() {
            final PowerAuthClientConfiguration powerAuthClientConfiguration = new PowerAuthClientConfiguration();
            powerAuthClientConfiguration.connectionTimeout = connectionTimeout;
            powerAuthClientConfiguration.readTimeout = readTimeout;
            powerAuthClientConfiguration.allowUnsecuredConnection = allowUnsecuredConnection;
            powerAuthClientConfiguration.clientValidationStrategy = clientValidationStrategy;
            if (requestInterceptors != null) {
                powerAuthClientConfiguration.requestInterceptors = Collections.unmodifiableList(requestInterceptors);
            }
            return powerAuthClientConfiguration;
        }
    }
}
