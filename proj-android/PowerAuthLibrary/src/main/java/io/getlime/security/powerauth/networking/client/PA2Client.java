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

package io.getlime.security.powerauth.networking.client;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.security.powerauth.networking.endpoints.PA2ActivationStatusEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2CreateActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2NonPersonalizedEncryptedEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2RemoveActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2VaultUnlockEndpoint;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.exceptions.FailedApiException;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.entity.ErrorModel;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;

/**
 * Class responsible for simple communication with server.
 *
 * @author Miroslav Michalec, 10/10/2016.
 */
public class PA2Client {

    private final Gson mGson;
    private final Handler mHandler;

    public PA2Client() {
        mGson = new GsonBuilder().create();
        mHandler = new Handler(Looper.getMainLooper());
    }

    private class RestExecutor<TRequest, TResponse> extends AsyncTask<TRequest, Void, Void> {

        private static final String CONTENT_TYPE_JSON = "application/json";

        private PowerAuthClientConfiguration clientConfiguration;
        private IEndpointDefinition<TRequest> requestDefinition;
        private INetworkResponseListener<TResponse> responseListener;
        private @Nullable Map<String, String> headers;

        private RestExecutor(
                @NonNull PowerAuthClientConfiguration clientConfiguration,
                @Nullable Map<String, String> headers,
                @NonNull IEndpointDefinition<TRequest> requestDefinition,
                @NonNull INetworkResponseListener<TResponse> responseListener) {
            this.clientConfiguration = clientConfiguration;
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
                final PowerAuthApiRequest<TRequest> requestObject = new PowerAuthApiRequest<>(params[0]);
                final String jsonRequestObject = mGson.toJson(requestObject);
                final byte[] postDataBytes = jsonRequestObject.getBytes("UTF-8");
                final boolean unsecuredConnection = clientConfiguration.isUnsecuredConnectionAllowed() && url.getProtocol().equals("http");

                final HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();

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
                urlConnection.setConnectTimeout(clientConfiguration.getConnectionTimeout());
                urlConnection.setReadTimeout(clientConfiguration.getReadTimeout());

                // ssl validation strategy
                final PA2ClientValidationStrategy clientValidationStrategy = clientConfiguration.getClientValidationStrategy();
                if (clientValidationStrategy != null && unsecuredConnection == false) {
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

                urlConnection.getOutputStream().write(postDataBytes);
                urlConnection.connect();

                final int responseCode = urlConnection.getResponseCode();
                switch (responseCode) {
                    case HttpsURLConnection.HTTP_OK:
                    case HttpsURLConnection.HTTP_BAD_REQUEST:
                    case HttpsURLConnection.HTTP_UNAUTHORIZED:
                        final InputStream inputStream = urlConnection.getInputStream();

                        final JsonReader jsonReader = new JsonReader(new InputStreamReader(inputStream));
                        final JsonObject jsonObject = new JsonParser().parse(jsonReader).getAsJsonObject();

                        final String status = jsonObject.get("status").getAsString();
                        final JsonElement responseObjectElement = jsonObject.get("responseObject");

                        if (status.equalsIgnoreCase("OK")) {
                            if (requestDefinition.getResponseType() != null) {
                                final TResponse response = mGson.fromJson(responseObjectElement, requestDefinition.getResponseType().getType());
                                callOnResponseUi(response, responseListener);
                            } else {
                                callOnResponseUi(null, responseListener);
                            }
                        } else {
                            final ErrorModel error = mGson.fromJson(responseObjectElement, TypeToken.get(ErrorModel.class).getType());
                            callOnErrorUi(new ErrorResponseApiException(error), responseListener);
                        }
                        jsonReader.close();
                        break;
                    default:
                        callOnErrorUi(new FailedApiException(responseCode), responseListener);
                        break;
                }
            } catch (IOException | JsonParseException e) {
                callOnErrorUi(e, responseListener);
            }

            return null;
        }
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
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull IEndpointDefinition<TResponse> requestDefinition,
            @Nullable TRequest requestBody,
            @Nullable Map<String, String> headers,
            @NonNull INetworkResponseListener<TResponse> responseListener) {
        final RestExecutor restExecutor = new RestExecutor(clientConfiguration, headers, requestDefinition, responseListener);
        return restExecutor.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, requestBody, null, null);
    }

    @CheckResult
    public AsyncTask sendNonPersonalizedEncryptedObjectToUrl(
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull NonPersonalizedEncryptedPayloadModel request,
            @NonNull String url,
            @NonNull Map<String, String> headers,
            @NonNull INetworkResponseListener<NonPersonalizedEncryptedPayloadModel> listener
            ) {
        return execute(configuration, clientConfiguration, new PA2NonPersonalizedEncryptedEndpoint(url), request, headers, listener);
    }

    @CheckResult
    public AsyncTask createActivation(
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull ActivationCreateRequest request,
            @NonNull INetworkResponseListener<ActivationCreateResponse> listener) {
        return execute(configuration, clientConfiguration, new PA2CreateActivationEndpoint(configuration.getBaseEndpointUrl()), request, null, listener);
    }

    @CheckResult
    public AsyncTask getActivationStatus(
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull ActivationStatusRequest request,
            @NonNull INetworkResponseListener<ActivationStatusResponse> listener) {
        return execute(configuration, clientConfiguration, new PA2ActivationStatusEndpoint(configuration.getBaseEndpointUrl()), request, null, listener);
    }

    @CheckResult
    public AsyncTask removeActivationSignatureHeader(
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull Map<String, String> headers,
            @NonNull INetworkResponseListener<Void> listener) {
        return execute(configuration, clientConfiguration, new PA2RemoveActivationEndpoint(configuration.getBaseEndpointUrl()), null, headers, listener);
    }

    @CheckResult
    public AsyncTask vaultUnlockSignatureHeader(
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthClientConfiguration clientConfiguration,
            @NonNull Map<String, String> headers,
            @NonNull INetworkResponseListener<VaultUnlockResponse> listener) {
        return execute(configuration, clientConfiguration, new PA2VaultUnlockEndpoint(configuration.getBaseEndpointUrl()), null, headers, listener);
    }

}
