/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.client;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;

import io.getlime.core.rest.model.base.entity.Error;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.integration.support.Logger;
import io.getlime.security.powerauth.integration.support.PowerAuthServerApiException;
import io.getlime.security.powerauth.integration.support.endpoints.EmptyRequestObject;
import io.getlime.security.powerauth.integration.support.endpoints.IServerApiEndpoint;

/**
 * The {@code RestClient} class implements HTTP communication with PowerAuth Server REST API.
 */
public class HttpRestClient {

    private final @NonNull String baseUrl;
    private final @NonNull Gson gson;
    private final @NonNull JsonParser jsonParser;

    public HttpRestClient(@NonNull String baseUrl) {
        // Make sure that baseUrl doesn't end with forward slash.
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.gson = new GsonBuilder().create();
        this.jsonParser = new JsonParser();
    }

    /**
     * Send request object to REST API endpoint.
     *
     * @param object object to be serialized into POST request. You can use {@code null} in case of empty request.
     * @param endpoint object defining REST API endpoint.
     * @param <TRequest> type of request object.
     * @param <TResponse> type of response object.
     * @return Response object.
     */
    public synchronized <TRequest, TResponse> TResponse send(@Nullable TRequest object, @NonNull IServerApiEndpoint<TResponse> endpoint) throws Exception {
        final RequestData requestData = new RequestData(
                baseUrl + endpoint.getRelativePath(),
                "POST",
                serializeRequestBytes(object)
        );
        final ResponseData responseData = sendAndReceiveData(requestData);
        return deserializeResponseBytes(responseData, endpoint.getResponseType());
    }

    /**
     * Internal class that wraps a whole information about request.
     */
    private static class RequestData {

        final @NonNull String url;
        final @NonNull String method;
        final @Nullable byte[] body;

        RequestData(@NonNull String url, @NonNull String method, @Nullable byte[] body) {
            this.url = url;
            this.method = method;
            this.body = body;
        }
    }

    /**
     * Internal class that wraps information about response.
     */
    private static class ResponseData {
        final int statusCode;
        final byte[] response;

        ResponseData(int statusCode, byte[] response) {
            this.statusCode = statusCode;
            this.response = response;
        }
    }

    /**
     * Send request data to the remote server.
     *
     * @param requestData Request data to be sent.
     * @return {@link ResponseData} object in case of communication did not fail.
     * @throws Exception If communication with the remote server fail.
     */
    private @NonNull ResponseData sendAndReceiveData(@NonNull RequestData requestData) throws Exception {

        Logger.d("Test HTTP Send " + requestData.method + " to: " + requestData.url);

        final URL url = new URL(requestData.url);
        final HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.setRequestMethod(requestData.method);
        urlConnection.setDoOutput(true);
        urlConnection.setUseCaches(false);
        urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        urlConnection.setRequestProperty("Accept", "application/json; charset=utf-8");
        if (requestData.body != null) {
            urlConnection.getOutputStream().write(requestData.body);
        }
        urlConnection.connect();

        final int responseCode = urlConnection.getResponseCode();
        InputStream inputStream = (responseCode == 200) ? urlConnection.getInputStream() : urlConnection.getErrorStream();
        final byte[] responseData = loadBytesFromInputStream(inputStream);

        Logger.d("Test HTTP Recv " + responseCode + " from: " + requestData.url);

        return new ResponseData(responseCode, responseData);
    }

    /**
     * Serialize request object into sequence of JSON encoded bytes.
     *
     * @param object Object to serialize.
     * @param <TRequest> Type of object to serialize.
     * @return JSON encoded sequence of bytes.
     */
    private <TRequest> byte[] serializeRequestBytes(@Nullable TRequest object) {
        final Object objectToSerialize;
        if (object == null) {
            final ObjectRequest<EmptyRequestObject> wrappedEmptyObject = new ObjectRequest<>();
            wrappedEmptyObject.setRequestObject(new EmptyRequestObject());
            objectToSerialize = wrappedEmptyObject;
        } else {
            final ObjectRequest<TRequest> wrappedObject = new ObjectRequest<>();
            wrappedObject.setRequestObject(object);
            objectToSerialize = wrappedObject;
        }
        return gson.toJson(objectToSerialize).getBytes(Charset.defaultCharset());
    }

    /**
     * Deserialize response bytes into response object.
     * @param responseData Received response data.
     * @param typeToken Type token contains type of response.
     * @param <TResponse> Type of response.
     * @return Response object in null, in case that response type is not defined.
     * @throws Exception In case of failure, or server returned non-200 response.
     */
    private <TResponse> TResponse deserializeResponseBytes(@NonNull ResponseData responseData, @Nullable TypeToken<TResponse> typeToken) throws Exception {
        if (responseData.statusCode != 200) {
            throw buildResponseException(responseData);
        }
        if (typeToken == null) {
            return null;
        }
        final TResponse response;
        try {
            final String responseString = new String(responseData.response, Charset.defaultCharset());
            final JsonElement jsonRoot = jsonParser.parse(responseString);
            if (!jsonRoot.isJsonObject()) {
                throw new PowerAuthServerApiException("JSON response doesn't contain a response object.");
            }
            final JsonElement jsonObject = jsonRoot.getAsJsonObject().get("responseObject");
            if (!jsonObject.isJsonObject()) {
                throw new PowerAuthServerApiException("JSON response doesn;t contain a response object.");
            }
            return gson.fromJson(jsonObject, typeToken.getType());
        } catch (JsonSyntaxException ex) {
            throw new PowerAuthServerApiException("Invalid JSON object received from the server.", ex, null, responseData.statusCode);
        }
    }

    /**
     * Build an exception from received error response.
     * @param responseData Response that should contain an error.
     * @return Exception constructed from received error response.
     */
    private Exception buildResponseException(@NonNull ResponseData responseData) {
        // Convert bytes into String
        if (responseData.response == null) {
            return new PowerAuthServerApiException("Empty response received from the server.", null, responseData.statusCode);
        }
        final ErrorResponse errorResponse;
        try {
            final String responseString = new String(responseData.response, Charset.defaultCharset());
            errorResponse = gson.fromJson(responseString, TypeToken.get(ErrorResponse.class).getType());
        } catch (JsonSyntaxException ex) {
            return new PowerAuthServerApiException("Invalid response error object received from the server.", null, responseData.statusCode);
        }
        final Error error = errorResponse.getResponseObject();
        if (error == null) {
            return new PowerAuthServerApiException("Empty Error object received from the server.", null, responseData.statusCode);
        }
        if (error.getMessage() != null) {
            return new PowerAuthServerApiException(error.getMessage(), error.getCode(), responseData.statusCode);
        }
        if (error.getCode() != null) {
            return new PowerAuthServerApiException("Request failed with error " + error.getCode(), error.getCode(), responseData.statusCode);
        }
        return new PowerAuthServerApiException("Request failed with status code " + responseData.statusCode, null, responseData.statusCode);
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
        }
        return result.toByteArray();
    }
}
