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

package io.getlime.security.powerauth.networking.client;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Pair;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.core.rest.model.base.entity.Error;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.security.powerauth.networking.endpoints.PA2ActivationStatusEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2CreateActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2CreateTokenEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2NonPersonalizedEncryptedEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2RemoveActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2RemoveTokenEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2VaultUnlockEndpoint;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.exceptions.FailedApiException;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.request.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.system.PA2Log;

/**
 * Class responsible for simple communication with server.
 *
 * @author Miroslav Michalec, 10/10/2016.
 */
public class PA2Client {

    private final Gson mGson;
    private final Handler mHandler;
    private final PowerAuthConfiguration mConfiguration;
    private final PowerAuthClientConfiguration mClientConfiguration;

    public PA2Client(@NonNull PowerAuthConfiguration configuration, @NonNull PowerAuthClientConfiguration clientConfiguration) {
        mConfiguration = configuration;
        mClientConfiguration = clientConfiguration;
        mGson = new GsonBuilder().create();
        mHandler = new Handler(Looper.getMainLooper());
    }

    public @NonNull PowerAuthClientConfiguration getClientConfiguration() {
        return mClientConfiguration;
    }

    public @NonNull PowerAuthConfiguration getConfiguration() {
        return mConfiguration;
    }

    private class RestExecutor<TRequest, TResponse> extends AsyncTask<TRequest, Void, Void> {

        private static final String CONTENT_TYPE_JSON = "application/json";

        private IEndpointDefinition<TRequest> requestDefinition;
        private INetworkResponseListener<TResponse> responseListener;
        private @Nullable Map<String, String> headers;

        private RestExecutor(
                @Nullable Map<String, String> headers,
                @NonNull IEndpointDefinition<TRequest> requestDefinition,
                @NonNull INetworkResponseListener<TResponse> responseListener) {
            this.headers = headers;
            this.requestDefinition = requestDefinition;
            this.responseListener = responseListener;
        }

        @Override
        protected Void doInBackground(TRequest... params) {
            URL url;
            try {
                url = new URL(requestDefinition.getEndpoint());
            } catch (MalformedURLException e) {
                callOnErrorUi(e, responseListener);
                return null;
            }
            try {
                final Pair<byte[], String> postData = serializeRequestObject(params[0]);
                final HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                final boolean securedUrlConnection = urlConnection instanceof HttpsURLConnection;

                urlConnection.setRequestMethod("POST");
                urlConnection.setDoOutput(true);
                urlConnection.setUseCaches(false);
                urlConnection.setRequestProperty("Content-Type", CONTENT_TYPE_JSON);
                urlConnection.setRequestProperty("Accept", CONTENT_TYPE_JSON);
                if (headers != null) {
                    for (Map.Entry<String, String> header : headers.entrySet()) {
                        urlConnection.setRequestProperty(header.getKey(), header.getValue());
                    }
                }
                urlConnection.setConnectTimeout(mClientConfiguration.getConnectionTimeout());
                urlConnection.setReadTimeout(mClientConfiguration.getReadTimeout());

                // ssl validation strategy
                if (securedUrlConnection) {
                    final PA2ClientValidationStrategy clientValidationStrategy = mClientConfiguration.getClientValidationStrategy();
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
                    if (mClientConfiguration.isUnsecuredConnectionAllowed() == false) {
                        throw new SSLException("Connection to non-TLS endpoint is not allowed.");
                    }
                }

                if (PA2Log.isEnabled()) {
                    final String bodyStr = postData.second == null ? "<empty>" : postData.second;
                    final Map<String,List<String>> prop = urlConnection.getRequestProperties();
                    final String propStr = prop == null ? "<empty>" : prop.toString();
                    PA2Log.d("PA2Client %s request to URL: %s\n - Headers: %s\n - Body: %s",
                            urlConnection.getRequestMethod(), url.toString(), propStr, bodyStr);
                }

                // Connect to endpoint
                urlConnection.getOutputStream().write(postData.first);
                urlConnection.connect();

                // Get response code & try to get response body
                final int responseCode = urlConnection.getResponseCode();
                final boolean responseOk =  responseCode / 100 == 2;

                // Get response body from InputStream
                final InputStream inputStream = responseOk ? urlConnection.getInputStream() : urlConnection.getErrorStream();
                final String responseBody = loadStringFromInputStream(inputStream, urlConnection.getContentEncoding());

                if (PA2Log.isEnabled()) {
                    final String bodyStr = responseBody == null ? "<empty body>" : responseBody;
                    final Map<String,List<String>> prop = urlConnection.getHeaderFields();
                    final String propStr = prop == null ? "<empty>" : prop.toString();
                    PA2Log.d("PA2Client response from URL: %s\n - Status code: %d\n - Headers: %s\n - Body: %s",
                            url.toString(), responseCode, propStr, bodyStr);
                }

                // Always try to parse response as a JSON
                String exceptionMessage = null;
                JsonObject responseJson = null;

                try {
                    final JsonElement jsonRoot = new JsonParser().parse(responseBody);
                    responseJson = jsonRoot.isJsonObject() ? jsonRoot.getAsJsonObject() : null;
                    // Try to get "status" & "responseObject"
                    if (responseJson != null) {
                        final JsonElement statusElement = responseJson.get("status");
                        final JsonElement responseElement = responseJson.get("responseObject");
                        if (statusElement != null && statusElement.isJsonPrimitive()) {
                            // Check status & build corresponding response for UI
                            if (statusElement.getAsString().equalsIgnoreCase("OK")) {
                                // Status is "OK", try to create response object from objectElement.
                                if (requestDefinition.getResponseType() != null) {
                                    // Create a final response object
                                    final TResponse response = mGson.fromJson(responseElement, requestDefinition.getResponseType().getType());
                                    callOnResponseUi(response, responseListener);
                                } else {
                                    // No response object, just report null
                                    callOnResponseUi(null, responseListener);
                                }
                            } else {
                                // Status is not "OK", try to create ErrorModel object
                                final Error error = mGson.fromJson(responseElement, TypeToken.get(Error.class).getType());
                                callOnErrorUi(new ErrorResponseApiException(error, responseBody, responseJson), responseListener);
                            }
                            // Return now, because for all other cases, we will report an error...
                            return null;
                        }
                    }

                } catch (JsonParseException e) {
                    // Failed on JSON parser, we should keep json exception message
                    exceptionMessage = e.getMessage();
                }
                // For all other cases report an error constructed with response code, body and optional exception message.
                callOnErrorUi(new FailedApiException(exceptionMessage, responseCode, responseBody, responseJson), responseListener);

            } catch (IOException | JsonParseException e) {
                // All other cases report as produced exception.
                callOnErrorUi(e, responseListener);
            }
            return null;
        }
    }

    /**
     * Converts all bytes read an InputStream to string.
     *
     * @param is input stream whose content will be converted
     * @param encoding requested encoding. If null is provided, then "UTF-8" is used.
     * @return String received from input stream
     */
    private String loadStringFromInputStream(InputStream is, String encoding) throws IOException {
        if (is == null) {
            return null;
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        if (encoding == null) {
            encoding = "UTF-8";
        }
        return result.toString(encoding);
    }

    private <TResponse> void callOnResponseUi(final TResponse response, final INetworkResponseListener<TResponse> responseListener) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                responseListener.onNetworkResponse(response);
            }
        });
    }

    private <TResponse> void callOnErrorUi(final Throwable t, final INetworkResponseListener<TResponse> responseListener) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                responseListener.onNetworkError(t);
            }
        });
    }

    @SuppressWarnings("unchecked")
    private <TRequest, TResponse> AsyncTask execute(
            @NonNull IEndpointDefinition<TResponse> requestDefinition,
            @Nullable TRequest requestBody,
            @Nullable Map<String, String> headers,
            @NonNull INetworkResponseListener<TResponse> responseListener) {
        final RestExecutor restExecutor = new RestExecutor(headers, requestDefinition, responseListener);
        return restExecutor.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, requestBody, null, null);
    }

    private static final String EMPTY_OBJECT_STRING = "{}";
    private static final byte[] EMPTY_OBJECT_BYTES = { 0x7B, 0x7D };

    public <TRequest> Pair<byte[], String> serializeRequestObject(TRequest request) {
        if (request != null) {
            final ObjectRequest<TRequest> requestObject = new ObjectRequest<>(request);
            final String jsonString = mGson.toJson(requestObject);
            final byte[] jsonBytes = jsonString.getBytes(Charset.defaultCharset());
            return new Pair<>(jsonBytes, jsonString);
        } else {
            return new Pair<>(EMPTY_OBJECT_BYTES, EMPTY_OBJECT_STRING);
        }
    }

    public <TResponse> TResponse deserializePlainResponse(byte[] data, Class<TResponse> type) {
        try {
            final String jsonString = new String(data, Charset.defaultCharset());
            return mGson.fromJson(jsonString, type);
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    @CheckResult
    public AsyncTask sendNonPersonalizedEncryptedObjectToUrl(
            @NonNull NonPersonalizedEncryptedPayloadModel request,
            @NonNull String url,
            @NonNull Map<String, String> headers,
            @NonNull INetworkResponseListener<NonPersonalizedEncryptedPayloadModel> listener
            ) {
        return execute(new PA2NonPersonalizedEncryptedEndpoint(url), request, headers, listener);
    }

    @CheckResult
    public AsyncTask createActivation(
            @NonNull ActivationCreateRequest request,
            @NonNull INetworkResponseListener<ActivationCreateResponse> listener) {
        return execute(new PA2CreateActivationEndpoint(mConfiguration.getBaseEndpointUrl()), request, null, listener);
    }

    @CheckResult
    public AsyncTask getActivationStatus(
            @NonNull ActivationStatusRequest request,
            @NonNull INetworkResponseListener<ActivationStatusResponse> listener) {
        return execute(new PA2ActivationStatusEndpoint(mConfiguration.getBaseEndpointUrl()), request, null, listener);
    }

    @CheckResult
    public AsyncTask removeActivation(
            @NonNull Map<String, String> headers,
            @NonNull INetworkResponseListener<Void> listener) {
        return execute(new PA2RemoveActivationEndpoint(mConfiguration.getBaseEndpointUrl()), null, headers, listener);
    }

    @CheckResult
    public AsyncTask vaultUnlock(
            @NonNull Map<String, String> headers,
            @NonNull VaultUnlockRequest request,
            @NonNull INetworkResponseListener<VaultUnlockResponse> listener) {
        return execute(new PA2VaultUnlockEndpoint(mConfiguration.getBaseEndpointUrl()), request, headers, listener);
    }

    @CheckResult
    public AsyncTask createToken(
            @NonNull Map<String, String> headers,
            @NonNull TokenCreateRequest request,
            @NonNull INetworkResponseListener<TokenCreateResponse> listener) {
        return execute(new PA2CreateTokenEndpoint(mConfiguration.getBaseEndpointUrl()), request, headers, listener);
    }

    @CheckResult
    public AsyncTask removeToken(
            @NonNull Map<String, String> headers,
            @NonNull TokenRemoveRequest request,
            @NonNull INetworkResponseListener<TokenRemoveResponse> listener) {
        return execute(new PA2RemoveTokenEndpoint(mConfiguration.getBaseEndpointUrl()), request, headers, listener);
    }
}
