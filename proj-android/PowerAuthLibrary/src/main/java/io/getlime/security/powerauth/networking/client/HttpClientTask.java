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

import android.os.AsyncTask;
import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;

/**
 * The {@code ClientTask} class implements an actual HTTP request & response processing, with using
 * {@link AsyncTask} infrastructure.
 */
class HttpClientTask<TRequest, TResponse> extends AsyncTask<TRequest, Void, TResponse> implements ICancelable {

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
            @NonNull IPrivateCryptoHelper cryptoHelper,
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

    @Override
    protected TResponse doInBackground(TRequest... tRequests) {
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

            // ssl validation strategy
            if (securedUrlConnection) {
                final PA2ClientValidationStrategy clientValidationStrategy = clientConfiguration.getClientValidationStrategy();
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
                for (HttpRequestInterceptor interceptor: requestInterceptors) {
                    interceptor.processRequestConnection(urlConnection);
                }
            }

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
            return httpRequestHelper.buildResponse(responseCode, responseData);

        } catch (Throwable e) {
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
}
