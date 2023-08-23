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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import java.nio.charset.Charset;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.security.powerauth.core.EciesCryptogram;
import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.networking.model.response.EciesEncryptedResponse;

/**
 * The {@code JsonSerialization} class is helping with object to JSON serialization and
 * with JSON to object deserialization.
 */
public class JsonSerialization {

    /**
     * Private instance of {@link Gson} object.
     */
    private Gson gson;

    /**
     * Constant representing an empty object, serialized to JSON (e.g. empty curly brackets, {@code {}})
     */
    private static final byte[] EMPTY_OBJECT_BYTES = { 0x7B, 0x7D };


    public JsonSerialization() {
    }

    // Generic object

    /**
     * Serializes object as is, into sequence of bytes in JSON format. If object parameter is null,
     * then empty curly brackets are returned.
     *
     * @param object object to serialize
     * @param <TRequest> type of object, to serialize
     * @return JSON representation of object
     */
    @NonNull
    public <TRequest> byte[] serializeObject(@Nullable TRequest object) {
        if (object != null) {
            final String jsonString = getGson().toJson(object);
            return jsonString.getBytes(Charset.defaultCharset());
        }
        return EMPTY_OBJECT_BYTES;
    }


    /**
     * Deserialize object from from sequence of bytes in JSON format.
     *
     * @param data JSON data
     * @param type {@link TypeToken} for object to be deserialized.
     * @param <TResponse> type of object to be deserialized.
     * @return deserialized object
     */
    @NonNull
    public <TResponse> TResponse deserializeObject(@Nullable byte[] data, @NonNull TypeToken<TResponse> type) throws JsonParseException {
        if (data != null) {
            final String jsonString = new String(data, Charset.defaultCharset());
            final TResponse object = getGson().fromJson(jsonString, type.getType());
            if (object != null) {
                return object;
            }
        }
        final String message = (data == null) ? "Empty response received." : "Failed to deserialize object.";
        throw new JsonParseException(message);
    }


    // Request object

    /**
     * Serializes object into sequence of bytes in JSON format. Unlike {@link #serializeObject(Object)},
     * this method wraps the provided object into {@link ObjectRequest} request envelope,
     * before the serialization.
     *
     * If object parameter is null, then empty curly brackets are returned.
     *
     * @param object object to serialize
     * @param <TRequest> type of object, to serialize
     * @return JSON representation of object
     */
    @NonNull
    public <TRequest> byte[] serializeRequestObject(@Nullable TRequest object) {
        if (object != null) {
            ObjectRequest<TRequest> request = new ObjectRequest<>(object);
            final String jsonString = getGson().toJson(request);
            return jsonString.getBytes(Charset.defaultCharset());
        }
        return EMPTY_OBJECT_BYTES;
    }


    /**
     * Parse bytes in JSON format.
     *
     * @param data bytes to parse
     * @return {@link JsonObject} in case that provided JSON's root element is object.
     * @throws JsonParseException if JSON is invalid
     */
    @NonNull
    public JsonObject parseResponseObject(@Nullable byte[] data) throws JsonParseException {
        if (data == null || data.length == 0) {
            throw new JsonParseException("Empty response received.");
        }
        final String jsonString = new String(data, Charset.defaultCharset());
        final JsonElement jsonRoot = JsonParser.parseString(jsonString);
        if (!jsonRoot.isJsonObject()) {
            throw new JsonParseException("Unexpected type of JSON data.");
        }
        return jsonRoot.getAsJsonObject();
    }


    // ECIES encrypt & decrypt

    /**
     * Encrypt provided object into standard JSON formatted ECIES request.
     *
     * @param object object to encrypt and serialize
     * @param encryptor the ECIES encryptor
     * @param <TRequest> the type of the desired object
     * @return JSON formatted bytes with encrypted object
     * @throws PowerAuthErrorException if encryption fails
     */
    @NonNull
    public <TRequest> byte[] encryptObject(@Nullable TRequest object, @NonNull EciesEncryptor encryptor) throws PowerAuthErrorException {
        final EciesEncryptedRequest request = encryptObjectToRequest(object, encryptor);
        return serializeObject(request);
    }


    /**
     * Decrypt standard JSON formatted ECIES response into bytes.
     *
     * @param data data with JSON formatted ECIES response
     * @param decryptor the ECIES decryptor
     * @return decrypted sequence of bytes
     * @throws PowerAuthErrorException if decryption fails.
     */
    @NonNull
    public byte[] decryptData(@Nullable byte[] data, @NonNull EciesEncryptor decryptor) throws PowerAuthErrorException {
        // 1. Deserialize bytes into response object
        final EciesEncryptedResponse response = deserializeObject(data, TypeToken.get(EciesEncryptedResponse.class));
        // 2. Construct cryptogram with data & mac (response doesn't contain ephemeral key)
        final EciesCryptogram cryptogram = new EciesCryptogram(response.getEncryptedData(), response.getMac(), null, response.getNonce(), response.getTimestamp());
        // 3. Decrypt the response
        final byte[] plainData = decryptor.decryptResponse(cryptogram);
        if (plainData == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to decrypt object data.");
        }
        return plainData;
    }


    /**
     * Decrypt standard JSON formatted ECIES response into response object.
     *
     * @param data data with JSON formatted ECIES response
     * @param decryptor the ECIES decryptor
     * @param type {@link TypeToken} for object to be deserialized.
     * @param <TResponse> the type of the desired object
     * @return decrypted and deserialized response object
     * @throws PowerAuthErrorException in case of decryption error
     */
    @Nullable
    public <TResponse> TResponse decryptObject(@Nullable byte[] data, @NonNull EciesEncryptor decryptor, @Nullable TypeToken<TResponse> type) throws PowerAuthErrorException {
        // 1. Decrypt data
        final byte[] plainData = decryptData(data, decryptor);
        // 2. If type token is present, then deserialize JSON
        if (type == null) {
            return null;
        }
        return deserializeObject(plainData, type);
    }

    /**
     * Encrypt provided object into {@link EciesEncryptedRequest} object.
     *
     * @param object object to encrypt and serialize
     * @param encryptor the ECIES encryptor
     * @param <TRequest> the type of the desired object
     * @return {@link EciesEncryptedRequest} object with encrypted content
     * @throws PowerAuthErrorException if encryption fails
     */
    @NonNull
    public <TRequest> EciesEncryptedRequest encryptObjectToRequest(@Nullable TRequest object, @NonNull EciesEncryptor encryptor) throws PowerAuthErrorException {
        // 1. Serialize object into JSON
        final byte[] plainData = serializeObject(object);
        // 2. Encrypt serialized JSON data
        final EciesCryptogram cryptogram = encryptor.encryptRequest(plainData);
        if (cryptogram == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to encrypt object data.");
        }
        // 3. Construct final request object from the cryptogram
        final EciesEncryptedRequest request = new EciesEncryptedRequest();
        request.setEncryptedData(cryptogram.getBodyBase64());
        request.setEphemeralPublicKey(cryptogram.getKeyBase64());
        request.setMac(cryptogram.getMacBase64());
        request.setNonce(cryptogram.getNonceBase64());
        request.setTimestamp(cryptogram.timestamp);
        return request;
    }


    /**
     * Decrypts object from response.
     *
     * @param response encrypted response
     * @param decryptor the ECIES decryptor
     * @param type {@link TypeToken} for object to be deserialized.
     * @param <TResponse> the type of the desired object
     * @return decrypted and deserialized response object
     * @throws PowerAuthErrorException in case of decryption error
     */
    @NonNull
    public <TResponse> TResponse decryptObjectFromResponse(@Nullable EciesEncryptedResponse response, @NonNull EciesEncryptor decryptor, @NonNull TypeToken<TResponse> type) throws PowerAuthErrorException {
        // Sanity checks
        if (response == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Empty response cannot be decrypted.");
        }
        // 1. Convert response into cryptogram object
        final EciesCryptogram cryptogram = new EciesCryptogram(response.getEncryptedData(), response.getMac(), null, response.getNonce(), response.getTimestamp());
        // 2. Try to decrypt the response
        final byte[] plainData = decryptor.decryptResponse(cryptogram);
        if (plainData == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to decrypt object data.");
        }
        // 3. Deserialize the object
        return deserializeObject(plainData, type);
    }

    // Lazy initialized GSON & JsonParser

    /**
     * @return Lazy initialized instance of {@link Gson} object.
     */
    @NonNull
    public Gson getGson() {
        if (gson == null) {
            gson = new GsonBuilder().create();
        }
        return gson;
    }
}
