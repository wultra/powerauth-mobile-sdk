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

import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.core.rest.model.base.entity.Error;
import io.getlime.security.powerauth.core.CoreEncryptorScope;
import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreHttpHeader;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.exceptions.FailedApiException;
import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The {@code CoreHttpTask} implements HTTP request execution. The request is specified in input
 * {@link CoreRequest} object.
 *
 * @param <TResult> Type of response. Use {@code Object} if response type is not relevant.
 */
public class CoreHttpRequest<TResult> implements ICancelable {

    /**
     * Interface for HTTP request completion.
     * @param <TResult> Result type.
     */
    public interface ICompletion<TResult> {
        /**
         * Called when task is complete with success result.
         * @param result Result to report.
         */
        void onSuccess(@Nullable TResult result);

        /**
         * Called when task is complete with failure.
         * @param failure Failure to report.
         */
        void onFailure(@NonNull Throwable failure);
    }

    @NonNull
    private final String baseUrl;
    @NonNull
    private final PowerAuthClientConfiguration clientConfiguration;
    @NonNull
    private final CoreRequest<TResult> coreRequest;
    @NonNull
    private final Runnable saveSessionState;
    @NonNull
    private final ICompletion<TResult> completion;
    private boolean canceled = false;
    private boolean done = false;

    /**
     * Create HTTP request with all required parameters.
     * @param baseUrl Base URL.
     * @param clientConfiguration HTTP client configuration.
     * @param coreRequest {@link CoreRequest} object.
     * @param saveSessionState Callback called when session state needs to be saved.
     * @param completion Completion callback.
     */
    public CoreHttpRequest(
            @NonNull String baseUrl,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull CoreRequest<TResult> coreRequest,
            @NonNull Runnable saveSessionState,
            @NonNull ICompletion<TResult> completion) {
        this.baseUrl = baseUrl;
        this.clientConfiguration = clientConfiguration;
        this.coreRequest = coreRequest;
        this.saveSessionState = saveSessionState;
        this.completion = completion;
    }

    @Override
    public synchronized void cancel() {
        if (!canceled) {
            canceled = true;
            coreRequest.cancel();
        }
    }

    @Override
    public synchronized boolean isCancelled() {
        return canceled || coreRequest.isCanceled();
    }

    /**
     * Execute request. THe method should be executed on a background thread, provided
     * by a task executor.
     */
    public void doInBackground() {
        InputStream inputStream = null;
        HttpURLConnection urlConnection = null;
        try {
            if (isCancelled()) {
                return;
            }
            // Prepare core request
            coreRequest.prepareRequest();

            // Save session's state after signature calculation
            if (coreRequest.isAuthenticated()) {
                saveSessionState.run();
            }

            final URL requestUrl = new URL(baseUrl + coreRequest.getRelativePath());
            final byte[] requestBody = coreRequest.getRequestBody();

            // Create an URL connection
            urlConnection = (HttpURLConnection) requestUrl.openConnection();
            final boolean securedUrlConnection = urlConnection instanceof HttpsURLConnection;

            // Setup the connection
            urlConnection.setRequestMethod(coreRequest.getHttpMethod());
            urlConnection.setDoOutput(true);
            urlConnection.setUseCaches(false);
            urlConnection.setConnectTimeout(clientConfiguration.getConnectionTimeout());
            urlConnection.setReadTimeout(clientConfiguration.getReadTimeout());
            for (CoreHttpHeader header : coreRequest.getRequestHeaders()) {
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
            logRequest(urlConnection, requestBody);

            // Connect to endpoint
            urlConnection.getOutputStream().write(requestBody);
            urlConnection.connect();

            if (isCancelled()) {
                return;
            }

            // Get response code & try to get response body
            final int responseCode = urlConnection.getResponseCode();
            final boolean responseOk = (responseCode == 200);

            if (isCancelled()) {
                return;
            }
            // Get response bytes from input stream
            inputStream = responseOk ? urlConnection.getInputStream() : urlConnection.getErrorStream();
            final byte[] responseData = loadBytesFromInputStream(inputStream);

            if (isCancelled()) {
                return;
            }

            if (responseOk) {
                // Process success response
                coreRequest.processResponse(responseData);
                // Log response
                logResponse(urlConnection, responseData, null);
                // Set request as completed
                setCompleted(coreRequest.getResponseObject());
            } else {
                // Failure response
                final Throwable failure = buildResponseException(responseCode, responseData);
                // Log response with error
                logResponse(urlConnection, responseData, failure);
                // Report failure
                setFailed(failure);
            }

        } catch (IOException e) {
            // Log response with error
            logResponse(urlConnection, null, e);
            // Create PowerAuthErrorException with NETWORK_ERROR code
            setFailed(new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, e.getMessage(), e));

        } catch (CoreException e) {
            // Log response with error
            logResponse(urlConnection, null, e);
            // Create PowerAuthErrorException with NETWORK_ERROR code
            setFailed(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, e));

        } catch (Throwable t) {
            // Log response with error
            logResponse(urlConnection, null, t);
            // Report failure
            setFailed(t);

        } finally {
            // Close input stream and disconnect the URL connection
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }

    /**
     * Constructs a {@link ErrorResponseApiException} or {@link FailedApiException} exceptions, depending
     * on data received from the server. The method is package-private.
     *
     * @param responseCode HTTP response code
     * @param responseData Response bytes
     * @return {@link Throwable} object with an appropriate exception.
     */
    @NonNull
    private Throwable buildResponseException(int responseCode, @Nullable byte[] responseData) {

        final JsonSerialization serialization = new JsonSerialization();

        // Convert bytes into String
        final String responseString;
        if (responseData != null) {
            responseString = new String(responseData, Charset.defaultCharset());
        } else {
            responseString = null;
        }

        Throwable exception = null;
        JsonObject jsonRoot = null;
        // Try to parse bytes into JSON representation
        try {
            jsonRoot = serialization.parseResponseObject(responseData);
        } catch (JsonParseException e) {
            exception = e;
        }
        if (jsonRoot != null) {
            try {
                // If JSON root is available, then try to deserialize Error object from the response
                final JsonElement responseObjectElement = jsonRoot.get("responseObject");
                if (responseObjectElement != null && responseObjectElement.isJsonObject()) {
                    final Error errorResponse = serialization.getGson().fromJson(responseObjectElement, TypeToken.get(Error.class).getType());
                    return new ErrorResponseApiException(errorResponse, responseCode, responseString, jsonRoot);
                }
            } catch (JsonParseException e) {
                exception = e;
            }
        }
        if (exception != null) {
            // If exception is known, then get the message and report FailedApiException
            return new FailedApiException(exception.getMessage(), responseCode, responseString, jsonRoot);
        }
        // Otherwise the FailedApiException will not contain the message.
        return new FailedApiException(responseCode, responseString, jsonRoot);
    }

    /**
     * Set request as completed with success result.
     * @param response Response object, if available.
     */
    private void setCompleted(TResult response) {
        // Report completion
        reportCompletion(response, null);
    }

    /**
     * Set request as failed,
     * @param t Reason of failure.
     */
    private void setFailed(@NonNull Throwable t) {
        // Mark core request as failed
        coreRequest.setFailed();
        // Report completion
        reportCompletion(null, t);
    }

    /**
     * Set request as completed.
     * @param result Result to report. Null is accepted in requests with no actual result.
     * @param failure Failure to report. Non-null means that request failed.
     */
    private void reportCompletion(@Nullable TResult result, @Nullable Throwable failure) {
        final boolean canceled;
        synchronized (this) {
            if (done) {
                return; // do nothing, result already presented
            }
            done = true;
            canceled = this.canceled;
        }
        if (!canceled) {
            if (failure != null) {
                completion.onFailure(failure);
            } else {
                completion.onSuccess(result);
            }
        }
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

    /**
     * Print information about HTTP request to {@link PowerAuthLog}.
     *
     * @param connection prepared connection object.
     * @param requestData (optional) byte array with request data.
     */
    private void logRequest(@Nullable HttpURLConnection connection, @Nullable byte[] requestData) {
        if (!PowerAuthLog.isEnabled()) {
            return;
        }
        // URL, method
        final boolean hasConnection = connection != null;
        final String url = hasConnection ? connection.getURL().toString() : "null";
        final String method = coreRequest.getHttpMethod();
        // Flags
        final boolean signature = coreRequest.isAuthenticated();
        final boolean encrypted = coreRequest.getEncryptorScope() != CoreEncryptorScope.NONE;
        final String signedEncrypted = (signature ? (encrypted ? " (sig+enc)" : " (sig)") : (encrypted ? " (enc)" : ""));
        if (!PowerAuthLog.isVerbose()) {
            // Not verbose -> put a simple log
            PowerAuthLog.d("HTTP %s request%s: -> %s", method, signedEncrypted, url);
        } else {
            // Verbose, put headers and body (if not encrypted) into the log.
            final Map<String,List<String>> prop = hasConnection ? connection.getRequestProperties() : null;
            final String propStr = prop == null ? "<empty>" : prop.toString();
            if (encrypted) {
                PowerAuthLog.d("HTTP %s request%s: -> %s\n- Headers: %s- Body: <encrypted>", method, signedEncrypted, url, propStr);
            } else {
                final String bodyStr = requestData == null ? "<empty>" : new String(requestData, Charset.defaultCharset());
                PowerAuthLog.d("HTTP %s request%s: -> %s\n- Headers: %s\n- Body: %s", method, signedEncrypted, url, propStr, bodyStr);
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
    private void logResponse(@Nullable HttpURLConnection connection, @Nullable byte[] responseData, @Nullable Throwable error) {
        if (!PowerAuthLog.isEnabled()) {
            return;
        }
        // URL, method
        final boolean hasConnection = connection != null;
        final String url = hasConnection ? connection.getURL().toString() : "null";
        final String method = coreRequest.getHttpMethod();
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
            responseCode = hasConnection ? connection.getResponseCode() : 0;
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
            final boolean encrypted = coreRequest.getEncryptorScope() != CoreEncryptorScope.NONE;
            // Response headers
            final String responseHeaders = hasConnection ? connection.getHeaderFields().toString() : "{}";
            // Response body
            final String responseBody = responseData == null ? "<empty>" : new String(responseData, Charset.defaultCharset());
            if (error == null) {
                PowerAuthLog.d("HTTP %s response %d: <- %s\n- Headers: %s\n- Data: %s", method, responseCode, url, responseHeaders, responseBody);
            } else {
                PowerAuthLog.d("HTTP %s response %d: <- %s\n- Error: %s\n- Headers: %s\n- Data: %s", method, responseCode, url, errorMessage, responseHeaders, responseBody);
            }
        }
    }
}
