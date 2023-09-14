/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.client;

import android.net.TrafficStats;
import android.os.AsyncTask;
import android.text.TextUtils;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;

import androidx.annotation.Nullable;
import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.exceptions.FailedApiException;
import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The {@code ClientTask} class implements an actual HTTP request & response processing, with using
 * {@link AsyncTask} infrastructure.
 */
class HttpClientTask<TRequest, TResponse> extends AsyncTask<TRequest, Void, TResponse> implements ICancelable {

    private static final int THREAD_STATS_TAG = 0x3456;

    private final HttpRequestHelper<TRequest, TResponse> httpRequestHelper;
    private final String baseUrl;
    private final IPrivateCryptoHelper cryptoHelper;
    private final INetworkResponseListener<TResponse> listener;
    private final PowerAuthClientConfiguration clientConfiguration;

    /**
     * If not null, then the task ended with an error.
     */
    private Throwable error;

    /**
     * @param httpRequestHelper request helper responsible for object serialization and deserialization
     * @param baseUrl base URL
     * @param clientConfiguration client configuration
     * @param cryptoHelper cryptographic helper
     * @param listener response listener
     */
    HttpClientTask(
            @NonNull HttpRequestHelper<TRequest, TResponse> httpRequestHelper,
            @NonNull String baseUrl,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @Nullable IPrivateCryptoHelper cryptoHelper,
            @NonNull INetworkResponseListener<TResponse> listener) {
        this.httpRequestHelper = httpRequestHelper;
        this.baseUrl = baseUrl;
        this.cryptoHelper = cryptoHelper;
        this.clientConfiguration = clientConfiguration;
        this.listener = listener;
    }

    /**
     * Reads all bytes from an input stream.
     *
     * @param is input stream whose content will be converted
     * @return String received from input stream
     */
    private byte[] loadBytesFromInputStream(InputStream is) throws IOException {
        if (is == null) {
            return null;
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
            if (isCancelled()) {
                return null;
            }
        }
        return result.toByteArray();
    }

    @SafeVarargs
    @Override
    protected final TResponse doInBackground(TRequest... tRequests) {
        setThreadStatsTag();

        InputStream inputStream = null;
        HttpURLConnection urlConnection = null;
        try {
            if (isCancelled()) {
                return null;
            }

            // Prepare request data
            HttpRequestHelper.RequestData requestData = httpRequestHelper.buildRequest(baseUrl, cryptoHelper);

            // Create an URL connection
            urlConnection = (HttpURLConnection) requestData.url.openConnection();
            final boolean securedUrlConnection = urlConnection instanceof HttpsURLConnection;

            // Setup the connection
            urlConnection.setRequestMethod(requestData.method);
            urlConnection.setDoOutput(true);
            urlConnection.setUseCaches(false);
            urlConnection.setConnectTimeout(clientConfiguration.getConnectionTimeout());
            urlConnection.setReadTimeout(clientConfiguration.getReadTimeout());
            for (Map.Entry<String, String> header : requestData.httpHeaders.entrySet()) {
                urlConnection.setRequestProperty(header.getKey(), header.getValue());
            }
            if (!TextUtils.isEmpty(clientConfiguration.getUserAgent())) {
                urlConnection.setRequestProperty("User-Agent", clientConfiguration.getUserAgent());
            }

            // ssl validation strategy
            if (securedUrlConnection) {
                final HttpClientValidationStrategy clientValidationStrategy = clientConfiguration.getClientValidationStrategy();
                if (clientValidationStrategy != null) {
                    final HttpsURLConnection sslConnection = (HttpsURLConnection) urlConnection;
                    final SSLSocketFactory sslSocketFactory = clientValidationStrategy.getSSLSocketFactory();
                    if (sslSocketFactory != null) {
                        sslConnection.setSSLSocketFactory(sslSocketFactory);
                    }
                    final HostnameVerifier hostnameVerifier = clientValidationStrategy.getHostnameVerifier();
                    if (hostnameVerifier != null) {
                        sslConnection.setHostnameVerifier(hostnameVerifier);
                    }
                }
            } else {
                if (!clientConfiguration.isUnsecuredConnectionAllowed()) {
                    throw new SSLException("Connection to non-TLS endpoint is not allowed.");
                }
            }

            // Apply request interceptors
            final List<HttpRequestInterceptor> requestInterceptors = clientConfiguration.getRequestInterceptors();
            if (requestInterceptors != null) {
                for (HttpRequestInterceptor interceptor : requestInterceptors) {
                    interceptor.processRequestConnection(urlConnection);
                }
            }
            // Log request
            logRequest(urlConnection, requestData.body);

            // Connect to endpoint
            if (requestData.body != null) {
                urlConnection.getOutputStream().write(requestData.body);
            }
            urlConnection.connect();

            if (isCancelled()) {
                return null;
            }

            // Get response code & try to get response body
            final int responseCode = urlConnection.getResponseCode();
            final boolean responseOk = (responseCode == 200);

            if (isCancelled()) {
                return null;
            }

            // Get response bytes from input stream
            inputStream = responseOk ? urlConnection.getInputStream() : urlConnection.getErrorStream();
            final byte[] responseData = loadBytesFromInputStream(inputStream);

            if (isCancelled()) {
                return null;
            }

            // Try to deserialize response
            TResponse result = httpRequestHelper.buildResponse(responseCode, responseData);
            // Log response
            logResponse(urlConnection, responseData, null);
            // Finally, return the result.
            return result;
        } catch (IOException e) {
            // Log response with error
            logResponse(urlConnection, null, e);
            // Create PowerAuthErrorException with NETWORK_ERROR code
            error = new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, e.getMessage(), e);

        } catch (Throwable e) {
            // Log response with error
            logResponse(urlConnection, null, e);
            // Keep an exception for later reporting.
            error = e;

        } finally {
            // Close input stream and disconnect the URL connection
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                }
            }
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
        return null;
    }

    @Override
    protected void onCancelled() {
        super.onCancelled();
        listener.onCancel();
    }

    @Override
    protected void onPostExecute(TResponse response) {
        super.onPostExecute(response);
        if (error == null) {
            listener.onNetworkResponse(response);
        } else {
            listener.onNetworkError(error);
        }
    }

    @Override
    public void cancel() {
        this.cancel(true);
    }

    /**
     * This method is here to mitigate
     * {@link android.os.StrictMode.VmPolicy.Builder#detectUntaggedSockets()}
     * detection problem.
     */
    private void setThreadStatsTag() {
        if (TrafficStats.getThreadStatsTag() == -1) {
            TrafficStats.setThreadStatsTag(THREAD_STATS_TAG);
        }
    }

    /**
     * Print information about HTTP request to {@link PowerAuthLog}.
     *
     * @param connection prepared connection object.
     * @param requestData (optional) byte array with request data.
     */
    private void logRequest(HttpURLConnection connection, byte[] requestData) {
        if (!PowerAuthLog.isEnabled()) {
            return;
        }
        // Endpoint
        final IEndpointDefinition<TResponse> endpoint = httpRequestHelper.getEndpoint();
        // URL, method
        final String url = connection.getURL().toString();
        final String method = endpoint.getHttpMethod();
        // Flags
        final boolean signature = endpoint.getAuthorizationUriId() != null;
        final boolean encrypted = endpoint.getEncryptorId() != EciesEncryptorId.NONE;
        final String signedEncrypted = (signature ? (encrypted ? " (sig+enc)" : " (sig)") : (encrypted ? " (enc)" : ""));
        if (!PowerAuthLog.isVerbose()) {
            // Not verbose -> put a simple log
            PowerAuthLog.d("HTTP %s request%s: -> %s", method, signedEncrypted, url);
        } else {
            // Verbose, put headers and body (if not encrypted) into the log.
            final Map<String,List<String>> prop = connection.getRequestProperties();
            final String propStr = prop == null ? "<empty>" : prop.toString();
            if (encrypted) {
                PowerAuthLog.d("HTTP %s request%s: %s\n- Headers: %s- Body: <encrypted>", method, signedEncrypted, url, propStr);
            } else {
                final String bodyStr = requestData == null ? "<empty>" : new String(requestData, Charset.defaultCharset());
                PowerAuthLog.d("HTTP %s request%s: %s\n- Headers: %s\n- Body: %s", method, signedEncrypted, url, propStr, bodyStr);
            }
        }
    }

    /**
     * Prints information about HTTP response to {@link PowerAuthLog}.
     *
     * @param connection connection object.
     * @param responseData (optional) data returned in HTTP request.
     * @param error (optional) error produced during the request.
     */
    private void logResponse(HttpURLConnection connection, byte[] responseData, Throwable error) {
        if (!PowerAuthLog.isEnabled()) {
            return;
        }
        // Endpoint
        final IEndpointDefinition<TResponse> endpoint = httpRequestHelper.getEndpoint();
        // URL, method
        final String url = connection.getURL().toString();
        final String method = endpoint.getHttpMethod();
        final String errorMessage;
        if (error != null) {
            if (error instanceof FailedApiException) {
                FailedApiException exception = (FailedApiException) error;
                if (responseData == null && exception.getResponseBody() != null) {
                    responseData = exception.getResponseBody().getBytes();
                }
            }
            errorMessage = error.getMessage() != null ? error.getMessage() : error.toString();
        } else {
            errorMessage = null;
        }
        // Response code
        int responseCode;
        try {
            responseCode = connection.getResponseCode();
        } catch (IOException e) {
            responseCode = 0;
        }
        if (!PowerAuthLog.isVerbose()) {
            // Not verbose -> put a simple log
            if (error == null) {
                PowerAuthLog.d("HTTP %s response %d: <- %s", method, responseCode, url);
            } else {
                PowerAuthLog.d("HTTP %s response %d: <- %s\n- Error: %s", method, responseCode, url, errorMessage);
            }
        } else {
            final boolean encrypted = endpoint.getEncryptorId() != EciesEncryptorId.NONE;
            // Response headers
            final String responseHeaders = connection.getHeaderFields().toString();
            // Response body
            final String responseBodyTmp = responseData == null ? "<empty>" : new String(responseData, Charset.defaultCharset());
            final String responseBody;
            if (!encrypted || error != null) {
                responseBody = responseBodyTmp;
            } else {
                responseBody = encrypted ? "<encrypted>" : responseBodyTmp;
            }
            if (error == null) {
                PowerAuthLog.d("HTTP %s response %d: <- %s\n- Headers: %s\n- Data: %s", method, responseCode, url, responseHeaders, responseBody);
            } else {
                PowerAuthLog.d("HTTP %s response %d: <- %s\n- Error: %s\n- Headers: %s\n- Data: %s", method, responseCode, url, errorMessage, responseHeaders, responseBody);
            }
        }
    }
}
