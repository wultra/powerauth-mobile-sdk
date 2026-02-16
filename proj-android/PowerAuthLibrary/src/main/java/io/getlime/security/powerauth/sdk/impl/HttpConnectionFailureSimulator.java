/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.getlime.security.powerauth.BuildConfig;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * Class to simulate HTTP connection failures for testing purpose.
 * This functionality is only available if {@link BuildConfig#DEBUG} is set to true.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public final class HttpConnectionFailureSimulator {

    /**
     * Wildcard value that matches any path.
     */
    public static final String WILDCARD = "*";

    private static final Map<String, Integer> responseFailure;
    private static final Map<String, Integer> onSendFailure;
    private static final Set<String> onReceiveFailure;

    static {
        responseFailure  = BuildConfig.DEBUG ? new HashMap<>() : null;
        onSendFailure    = BuildConfig.DEBUG ? new HashMap<>() : null;
        onReceiveFailure = BuildConfig.DEBUG ? new HashSet<>() : null;
    }

    /**
     * Indicates whether the HTTP failure simulator is available.
     * @return True if available, false otherwise.
     */
    public static boolean isRequestFailureSimulatorAvailable() {
        return BuildConfig.DEBUG;
    }

    /**
     * Configures the next HTTP response for the given path to fail with the provided status code.
     * @param relativePath Relative request path.
     * @param statusCode HTTP error status code.
     */
    public static void setNextResponseFailure(String relativePath, int statusCode) {
        if (BuildConfig.DEBUG) {
            if (statusCode < 400) {
                throw new IllegalArgumentException("Status code must represent an error");
            }

            synchronized (HttpConnectionFailureSimulator.class) {
                responseFailure.put(relativePath, statusCode);
                PowerAuthLog.d("!!! Next HTTP response will fail on %d: %s", statusCode, relativePath);
            }
        } else {
            throw new IllegalStateException("Failure simulator is not available in release build");
        }
    }

    /**
     * Configures network failures that occur during request send for the given path.
     * @param relativePath Relative request path.
     * @param repeatCount Number of times the send failure should occur.
     */
    public static void setNextRequestNetworkFailureOnSend(String relativePath, int repeatCount) {
        if (BuildConfig.DEBUG) {
            if (repeatCount < 1) {
                throw new IllegalArgumentException("Number of failure must be at least 1");
            }

            synchronized (HttpConnectionFailureSimulator.class) {
                onSendFailure.put(relativePath, repeatCount);
                PowerAuthLog.d("!!! Next %d HTTP request(s) will fail on send: %s", repeatCount, relativePath);
            }
        } else {
            throw new IllegalStateException("Failure simulator is not available in release build");
        }
    }

    /**
     * Configures a network failure that occurs during response receive for the given path.
     * @param relativePath Relative request path.
     */
    public static void setNextRequestNetworkFailureOnReceive(String relativePath) {
        if (BuildConfig.DEBUG) {
            synchronized (HttpConnectionFailureSimulator.class) {
                onReceiveFailure.add(relativePath);
                PowerAuthLog.d("!!! Next HTTP request will fail on receive: %s", relativePath);
            }
        } else {
            throw new IllegalStateException("Failure simulator is not available in release build");
        }
    }

    /**
     * Removes all configured failure hooks.
     */
    public static void clearAllFailureHooks() {
        if (BuildConfig.DEBUG) {
            synchronized (HttpConnectionFailureSimulator.class) {
                PowerAuthLog.d("!!! Removing all simulated HTTP failure hooks");
                responseFailure.clear();
                onSendFailure.clear();
                onReceiveFailure.clear();
            }
        } else {
            throw new IllegalStateException("Failure simulator is not available in release build");
        }
    }

    /**
     * Wraps the provided {@link HttpURLConnection} with fail-simulator wrapper.
     * @param delegate Underlying {@link HttpURLConnection}.
     * @param relativePath Relative request path.
     * @return Wrapped {@link HttpURLConnection} that injects configured failures.
     */
    public static HttpURLConnectionWrapper wrap(final HttpURLConnection delegate, final String relativePath) {
        if (BuildConfig.DEBUG) {
            synchronized (HttpConnectionFailureSimulator.class) {
                return new HttpURLConnectionWrapper(
                        delegate,
                        shouldFailWithResponseCode(relativePath),
                        shouldFailOnSend(relativePath),
                        shouldFailOnReceive(relativePath)
                );
            }
        } else {
            throw new IllegalStateException("Failure simulator is not available in release build");
        }
    }

    /**
     * {@link HttpURLConnection} wrapper that simulates network failures
     * based on configuration captured at creation time.
     */
    public static class HttpURLConnectionWrapper extends HttpURLConnection {

        private final HttpURLConnection delegate;

        private final Integer errorResponseCode;
        private final boolean failOnSend;
        private final boolean failOnReceive;

        private HttpURLConnectionWrapper(HttpURLConnection delegate, Integer errorResponseCode, boolean failOnSend, boolean failOnReceive) {
            super(delegate.getURL());
            this.delegate = delegate;
            this.errorResponseCode = errorResponseCode;
            this.failOnSend = failOnSend;
            this.failOnReceive = failOnReceive;
        }

        @Override
        public InputStream getErrorStream() {
            if (errorResponseCode != null) {
                // Override response body on simulated response error.
                final String message = "{\"status\": \"ERROR\",\"responseObject\":{\"code\": \"ERR_SIMULATED_FAILURE\",\"message\": \"This is fine 🐶\"}}";
                return new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
            }

            return delegate.getErrorStream();
        }

        @Override
        public int getResponseCode() throws IOException {
            if (failOnSend) {
                // Request is sent on getting response code.
                throw new IOException("Simulated error on data send: " + url);
            }

            final int actualResponseCode = delegate.getResponseCode();
            return errorResponseCode != null ? errorResponseCode : actualResponseCode;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            if (failOnReceive) {
                // Throw an error when trying to read a response body.
                throw new IOException("Simulated error on data receive: " + url);
            }

            return delegate.getInputStream();
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            return delegate.getOutputStream();
        }

        @Override
        public void disconnect() {
            delegate.disconnect();
        }

        @Override
        public boolean usingProxy() {
            return delegate.usingProxy();
        }

        @Override
        public void connect() throws IOException {
            delegate.connect();
        }
    }

    /**
     * Determines whether the next request should fail with an HTTP error response.
     * If a matching request path is found, it is removed so the failure is applied only once.
     * @param relativePath Relative request path.
     * @return HTTP error status code, or {@code null} if no failure is configured.
     */
    private static Integer shouldFailWithResponseCode(final String relativePath) {
        Integer errorResponseCode = responseFailure.remove(relativePath);
        if (errorResponseCode == null) {
            errorResponseCode = responseFailure.remove(WILDCARD);
        }

        return errorResponseCode;
    }

    /**
     * Determines whether the next request should fail during response receive.
     * If a matching request path is found, it is removed so the failure is applied only once.
     * @param relativePath Relative request path.
     * @return True if the response data receiving should fail, false otherwise.
     */
    private static boolean shouldFailOnReceive(final String relativePath) {
        boolean failOnReceive = onReceiveFailure.remove(relativePath);
        if (!failOnReceive) {
            failOnReceive = onReceiveFailure.remove(WILDCARD);
        }

        return failOnReceive;
    }

    /**
     * Determines whether the next request should fail during request send.
     * If a matching request path is found, its counter is decremented or removed so the failure
     * occurs only the configured number of times.
     * @param relativePath Relative request path.
     * @return True if the request send should fail, false otherwise.
     */
    private static boolean shouldFailOnSend(final String relativePath) {
        String pathToMatch = relativePath;
        Integer count = onSendFailure.get(pathToMatch);
        if (count == null) {
            pathToMatch = WILDCARD;
            count = onSendFailure.get(pathToMatch);
        }

        if (count == null || count < 1) {
            return false;
        }

        if (count > 1) {
            onSendFailure.replace(pathToMatch, count - 1);
        } else {
            onSendFailure.remove(pathToMatch);
        }

        return true;
    }

}
