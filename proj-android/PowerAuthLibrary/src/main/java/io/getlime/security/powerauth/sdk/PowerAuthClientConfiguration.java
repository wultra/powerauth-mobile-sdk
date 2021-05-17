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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Class that is used to provide RESTful API client configuration.
 */
public class PowerAuthClientConfiguration {

    /**
     * Default value for connection timeout (in ms)
     */
    public static final int DEFAULT_CONNECTION_TIMEOUT = 20 * 1000;

    /**
     * Default value for read timeout (in ms)
     */
    public static final int DEFAULT_READ_TIMEOUT = 20 * 1000;

    /**
     * By default, unsecured connections are not allowed.
     */
    public static final boolean DEFAULT_ALLOW_UNSECURED_CONNECTION = false;

    /**
     * Property that specifies the default HTTP client connection timeout. The default value is 20.0 (seconds).
     */
    private final int connectionTimeout;

    /**
     * Property that specifies the default HTTP client read timeout. The default value is 20.0 (seconds).
     */
    private final int readTimeout;

    /**
     * Property that specifies whether it's possible to connect to non-TLS endpoints.
     * <p>
     * <b>WARNING:</b> You should never allow unsecured connections to production-grade servers.
     */
    private final boolean allowUnsecuredConnection;

    /**
     * Property that specifies the SSL validation strategy applied by the client.
     */
    private final HttpClientValidationStrategy clientValidationStrategy;

    /**
     * Property that specifies the list of request interceptors used by the client before the request is executed.
     */
    private final List<HttpRequestInterceptor> requestInterceptors;

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
     * @return {@code true} if unsecured connections are allowed
     */
    public boolean isUnsecuredConnectionAllowed() { return allowUnsecuredConnection; }

    /**
     * @return {@link HttpClientValidationStrategy} object that implements TLS validation strategy.
     */
    public HttpClientValidationStrategy getClientValidationStrategy() {
        return clientValidationStrategy;
    }

    /**
     * @return immutable list of request interceptors or null if there's no interceptor assigned.
     */
    public @Nullable List<HttpRequestInterceptor> getRequestInterceptors() {
        return requestInterceptors;
    }

    /**
     * Default private constructor. Use {@link Builder} to create a new instance of this class.
     *
     * @param connectionTimeout Connection timeout in ms.
     * @param readTimeout Read timeout in ms.
     * @param allowUnsecuredConnection Defines whether unsecured connection is allowed.
     * @param clientValidationStrategy {@link HttpClientValidationStrategy} object that implements TLS validation strategy.
     * @param requestInterceptors Array of {@link HttpRequestInterceptor} objects or {@code null} if there's none.
     */
    private PowerAuthClientConfiguration(
            int connectionTimeout,
            int readTimeout,
            boolean allowUnsecuredConnection,
            HttpClientValidationStrategy clientValidationStrategy,
            List<HttpRequestInterceptor> requestInterceptors) {
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
        this.allowUnsecuredConnection = allowUnsecuredConnection;
        this.clientValidationStrategy = clientValidationStrategy;
        this.requestInterceptors = requestInterceptors;
    }

    /**
     * A builder that collects arguments for {@link PowerAuthClientConfiguration}.
     */
    public static class Builder {
        private int connectionTimeout = DEFAULT_CONNECTION_TIMEOUT;
        private int readTimeout = DEFAULT_READ_TIMEOUT;
        private boolean allowUnsecuredConnection = DEFAULT_ALLOW_UNSECURED_CONNECTION;
        private HttpClientValidationStrategy clientValidationStrategy;
        private ArrayList<HttpRequestInterceptor> requestInterceptors;

        /**
         * Creates a builder for {@link PowerAuthClientConfiguration}.
         */
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
                 PowerAuthLog.e("Unsecured connection is dangerous for production application.");
            }
            return this;
        }

        /**
         * Sets TLS client validation strategy to the future configuration.
         *
         * @param clientValidationStrategy strategy to be set
         * @return The same {@link Builder} object instance
         */
        public Builder clientValidationStrategy(HttpClientValidationStrategy clientValidationStrategy) {
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
            return new PowerAuthClientConfiguration(
                    connectionTimeout,
                    readTimeout,
                    allowUnsecuredConnection,
                    clientValidationStrategy,
                    requestInterceptors != null ? Collections.unmodifiableList(requestInterceptors) : null);
        }
    }
}
