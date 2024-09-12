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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import io.getlime.core.rest.model.base.entity.Error;
import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.ecies.EciesMetadata;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.exceptions.FailedApiException;
import io.getlime.security.powerauth.networking.interfaces.ICustomEndpointOperation;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthAuthorizationHttpHeader;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;

/**
 * The {@code HttpRequestHelper} class implements request serialization and response deserialization.
 * The class is package-private.
 */
class HttpRequestHelper<TRequest, TResponse> {

    /**
     * Request object to be serialized to POST request. The object can be nil in case that
     * the endpoint doesn't define request type.
     */
    private final TRequest requestObject;

    /**
     * The endpoint definition.
     */
    private final IEndpointDefinition<TResponse> endpoint;

    /**
     * Authentication object. The property may be null for requests which doesn't need to be
     * signed with PowerAuth signature.
     */
    private final PowerAuthAuthentication authentication;

    /**
     * The serialization helper object.
     */
    private final JsonSerialization serialization;

    /**
     * ECIES encryptor. If null, then the response doesn't need to be decrypted.
     */
    private EciesEncryptor encryptor;

    /**
     * @param requestObject optional request object, to be sent in POST request
     * @param endpoint required endpoint definition
     * @param authentication optional authentication object, required for objects
     */
    HttpRequestHelper(
            @Nullable TRequest requestObject,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @Nullable PowerAuthAuthentication authentication) {
        this.requestObject = requestObject;
        this.endpoint = endpoint;
        this.authentication = authentication;
        this.serialization = new JsonSerialization();
    }


    /**
     * @return Endpoint definition set to this object.
     */
    IEndpointDefinition<TResponse> getEndpoint() {
        return endpoint;
    }

    // Request data object

    /**
     * The {@code RequestData} nested class contains all information required for HTTP request
     * execution.
     */
    static class RequestData {
        /**
         * Full URL
         */
        final @NonNull URL url;
        /**
         * HTTP method
         */
        final @NonNull String method;
        /**
         * Dictionary with all HTTP headers
         */
        final @NonNull Map<String, String> httpHeaders;
        /**
         * HTTP request body. May contain an empty array of bytes.
         */
        final @Nullable byte[] body;

        /**
         * @param url full URL
         * @param method HTTP method
         * @param httpHeaders HTTP headers
         * @param body HTTP request body
         */
        RequestData(
                @NonNull URL url,
                @NonNull String method,
                @NonNull Map<String, String> httpHeaders,
                @Nullable byte[] body) {
            this.url = url;
            this.method = method;
            this.httpHeaders = httpHeaders;
            this.body = body;
        }
    }


    /**
     * Build data for HTTP request. The method also updates {@link #encryptor} property when the ECIES encryption
     * is used. The encryptor can be later used for response decryption.
     *
     * @param baseUrl String with base URL
     * @param helper Private cryptographic helper
     * @return {@link RequestData} object with all information needed for request execution
     * @throws PowerAuthErrorException if encryption or signature calculation fails.
     * @throws MalformedURLException if cannot construct full request URL
     */
    @NonNull
    RequestData buildRequest(@NonNull String baseUrl, @Nullable IPrivateCryptoHelper helper) throws PowerAuthErrorException, MalformedURLException {

        // Sanity checks
        final boolean needsSignature = endpoint.getAuthorizationUriId() != null;
        final boolean needsEncryption = endpoint.getEncryptorId() != EciesEncryptorId.NONE;

        if (needsSignature && authentication == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Authentication object is missing");
        }
        if ((needsSignature || needsEncryption) && helper == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Cryptographic helper object is missing");
        }

        // Prepare data for a new RequestData object

        final URL requestUrl = new URL(baseUrl + endpoint.getRelativePath());
        final String requestMethod = endpoint.getHttpMethod();
        final HashMap<String, String> requestHeaders = new HashMap<>();
        final byte[] requestData;

        // Execute custom step before the request is serialized.
        ICustomEndpointOperation beforeRequestSerialization = endpoint.getBeforeRequestSerializationOperation();
        if (beforeRequestSerialization != null) {
            beforeRequestSerialization.customEndpointOperation(endpoint);
        }

        // Encrypt the request data if the endpoint has encryptor specified
        if (!needsEncryption) {
            // No data encryption
            encryptor = null;
            requestData = serialization.serializeRequestObject(requestObject);
        } else {
            // Acquire the encryptor from the helper and keep it locally.
            // We will use it later for the response decryption.
            encryptor = helper.getEciesEncryptor(endpoint.getEncryptorId());
            // Then encrypt the request object.
            requestData = serialization.encryptObject(requestObject, encryptor);

            // Set encryption HTTP header, only if this doesn't collide with the signature.
            // We don't send the encryption header together with the signature header. The reason
            // for that is fact, that signature header already contains values required for
            // decryption on the server.
            if (!needsSignature) {
                final EciesMetadata metadata = encryptor.getMetadata();
                requestHeaders.put(metadata.getHttpHeaderKey(), metadata.getHttpHeaderValue());
            }
        }

        // Sign data if requested
        if (needsSignature) {
            final boolean available = endpoint.isAvailableInProtocolUpgrade();
            final PowerAuthAuthorizationHttpHeader header = helper.getAuthorizationHeader(available, requestData, requestMethod, endpoint.getAuthorizationUriId(), authentication);
            if (header.getPowerAuthErrorCode() != PowerAuthErrorCodes.SUCCEED) {
                if (header.getPowerAuthErrorCode() == PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE) {
                    throw new PowerAuthErrorException(header.getPowerAuthErrorCode(), "Request is temporarily unavailable, due to pending protocol upgrade.");
                }
                throw new PowerAuthErrorException(header.getPowerAuthErrorCode());
            }
            // Keep authorization header
            requestHeaders.put(header.getKey(), header.getValue());
        }

        // Finalize headers
        requestHeaders.put("Content-Type", "application/json");
        requestHeaders.put("Accept", "application/json");

        // Return object with all information prepared for request processing.
        return new RequestData(requestUrl, requestMethod, requestHeaders, requestData);
    }


    /**
     * Build a response object from provided data. In case of error throws {@link FailedApiException},
     * {@link ErrorResponseApiException} or {@link PowerAuthErrorException} exceptions.
     *
     * @param responseCode HTTP response status code
     * @param responseData Response bytes
     * @return object created from response bytes
     * @throws Throwable if a deserialization, or decryption error occured.
     */
    @Nullable
    TResponse buildResponse(int responseCode, @Nullable byte[] responseData) throws Throwable {

        if (responseCode != 200) {
            // Non-200 response, throw an error
            throw buildResponseException(responseCode, responseData, null, null);
        }
        try {
            // 2xx response, try to build an object from response data
            return buildResponseObject(responseCode, responseData);

        } catch (FailedApiException | PowerAuthErrorException e) {
            // Known exceptions, just re-throw
            throw e;
        } catch (Throwable e) {
            // In case of generic exception re-throw that
            throw buildResponseException(responseCode, responseData, null, e);
        }
    }


    /**
     * Builds a response object from provided data. The function is used only for 2xx HTTP status codes,
     * to process a success response object.
     *
     * @param responseCode HTTP response status code
     * @param responseData Response bytes
     * @return Response object, or null if response object is not specified.
     * @throws Throwable if object cannot be constructed.
     */
    @Nullable
    private TResponse buildResponseObject(int responseCode, @Nullable byte[] responseData) throws Throwable {

        final byte[] objectData;
        final boolean unwrapResponse;

        if (encryptor != null) {
            // Encrypted response. The expected object is never wrapper in ObjectResponse<T>
            unwrapResponse = false;
            objectData = serialization.decryptData(responseData, encryptor);
        } else {
            // Regular response. It's always wrapped in ObjectResponse<T>
            unwrapResponse = true;
            objectData = responseData;
        }

        // So far so good, we can continue with an object deserialization.
        final TResponse result;

        if (unwrapResponse) {
            // Response object is wrapped in ObjectResponse<T> envelope.
            // At first, try to deserialize JSON
            final JsonObject jsonRoot = serialization.parseResponseObject(objectData);

            // Check "status" property in received JSON
            final JsonElement status = jsonRoot.get("status");
            if (status == null || !status.isJsonPrimitive() || !status.getAsString().equalsIgnoreCase("OK")) {
                throw buildResponseException(responseCode, responseData, jsonRoot, null);
            }
            if (endpoint.getResponseType() != null) {
                // Check "responseObject" property, but only if response type is specified
                final JsonElement responseObjectElement = jsonRoot.get("responseObject");
                if (responseObjectElement != null && responseObjectElement.isJsonObject()) {
                    // Now finally, try to deserialize the response object
                    result = serialization.getGson().fromJson(responseObjectElement, endpoint.getResponseType().getType());
                } else {
                    result = null;
                }
                // Check if object was created and if not, then throw an exception.
                if (result == null) {
                    throw new JsonParseException("Failed to deserialize response object.");
                }
            } else {
                // No action is needed. Response type is not specified, so the result can be null.
                result = null;
            }

        } else {
            // Response object is not wrapped in ObjectResponse<T>
            if (endpoint.getResponseType() != null) {
                // If response type is specified, then deserialize the object
                result = serialization.deserializeObject(objectData, endpoint.getResponseType());

            } else {
                // No action is needed. If response type is not specified, then the result can be null.
                result = null;
            }
        }

        return result;
    }


    /**
     * Constructs a {@link ErrorResponseApiException} or {@link FailedApiException} exceptions, depending
     * on data received from the server. The method is package-private.
     *
     * @param responseCode HTTP response code
     * @param responseData Response bytes
     * @param jsonRoot Optional JSON representation. If object is not available, then the function will try to parse
     * @param exception Optional exception. If provided, then its message will be used as a fallback.
     * @return {@link Throwable} object with an appropriate exception.
     */
    @NonNull
    private Throwable buildResponseException(int responseCode, @Nullable byte[] responseData, @Nullable JsonObject jsonRoot, @Nullable Throwable exception) {

        // Convert bytes into String
        final String responseString;
        if (responseData != null) {
            responseString = new String(responseData, Charset.defaultCharset());
        } else {
            responseString = null;
        }

        if (jsonRoot == null) {
            // Try to parse bytes into JSON representation
            try {
                jsonRoot = serialization.parseResponseObject(responseData);
            } catch (JsonParseException e) {
                exception = e;
            }
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
}
