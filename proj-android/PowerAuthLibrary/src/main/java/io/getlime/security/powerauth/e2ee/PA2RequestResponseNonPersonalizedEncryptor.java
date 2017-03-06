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

package io.getlime.security.powerauth.e2ee;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.UnsupportedEncodingException;

import io.getlime.security.powerauth.core.EncryptedMessage;
import io.getlime.security.powerauth.core.Encryptor;
import io.getlime.security.powerauth.core.ErrorCode;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiRequest;
import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;

/**
 * Class representing a non-personalized encryptor instance.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PA2RequestResponseNonPersonalizedEncryptor implements PA2Encryptor {

    private Encryptor encryptor;
    private Gson objectMapper = new GsonBuilder().create();

    /**
     * Basic constructor that accepts a native encryptor instance.
     * @param encryptor Native encryptor.
     */
    public PA2RequestResponseNonPersonalizedEncryptor(Encryptor encryptor) {
        this.encryptor = encryptor;
    }

    /**
     * Allow changing the object mapper on the encryptor instance, in case JSON serialization requires customizations.
     *
     * @param objectMapper Provided object mapper.
     */
    public void setObjectMapper(Gson objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Encrypt request data using non-personalized encryption and return result object.
     *
     * @param originalData Bytes with request body payload.
     * @return Request object with encrypted payload.
     * @throws PA2EncryptionFailedException In case encryption fails.
     */
    @Override
    public PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> encryptRequestData(byte[] originalData) throws PA2EncryptionFailedException {
        EncryptedMessage encryptedMessage = encryptor.encrypt(originalData);
        if (encryptedMessage == null) {
            throw new PA2EncryptionFailedException();
        }
        NonPersonalizedEncryptedPayloadModel requestObject = new NonPersonalizedEncryptedPayloadModel();
        requestObject.setApplicationKey(encryptedMessage.applicationKey);
        requestObject.setSessionIndex(encryptedMessage.sessionIndex);
        requestObject.setAdHocIndex(encryptedMessage.adHocIndex);
        requestObject.setMacIndex(encryptedMessage.macIndex);
        requestObject.setNonce(encryptedMessage.nonce);
        requestObject.setEphemeralPublicKey(encryptedMessage.ephemeralPublicKey);
        requestObject.setMac(encryptedMessage.mac);
        requestObject.setEncryptedData(encryptedMessage.encryptedData);

        PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> request = new PowerAuthApiRequest<>(
                PowerAuthApiRequest.Encryption.NON_PERSONALIZED,
                requestObject
        );
        return request;
    }

    /**
     * Encrypt given object data using non-personalized (application key specific) or personalized (activation
     * specific) encryption and return ready to use request object.
     *
     * This method first converts object to JSON data using provided object mapper, then encrypts the bytes.
     *
     * @param requestObject Object to be encrypted.
     * @return Encrypted response.
     * @throws PA2EncryptionFailedException In case that encryption fails.
     */
    @Override
    public PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> encryptRequestData(Object requestObject) throws PA2EncryptionFailedException {
        try {
            byte[] bytes = objectMapper.toJson(requestObject).getBytes("UTF-8");
            return this.encryptRequestData(bytes);
        } catch (UnsupportedEncodingException e) {
            // ignore: UTF-8 not present
        }
        return null;
    }

    /**
     * Decrypt response data using non-personalized end-to-end encryption and retrieve original response bytes.
     *
     * @param response Instance of encrypted response.
     * @return Original decrypted bytes.
     * @throws PA2EncryptionFailedException In case invalid type of decryption mode is present in response, or in case decryption fails with error.
     */
    @Override
    public byte[] decryptResponse(PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> response) throws PA2EncryptionFailedException {
        if (response.getEncryption().equals(PowerAuthApiResponse.Encryption.NON_PERSONALIZED)) {

            NonPersonalizedEncryptedPayloadModel responseObject = response.getResponseObject();

            // Prepare the decrypted message payload
            EncryptedMessage encryptedMessage = new EncryptedMessage(
                    responseObject.getApplicationKey(),
                    null,
                    responseObject.getEncryptedData(),
                    responseObject.getMac(),
                    responseObject.getSessionIndex(),
                    responseObject.getAdHocIndex(),
                    responseObject.getMacIndex(),
                    responseObject.getNonce(),
                    responseObject.getEphemeralPublicKey()
            );

            // Return decrypted data
            byte[] originalData = encryptor.decrypt(encryptedMessage);

            if (encryptor.lastErrorCode != ErrorCode.OK) {
                throw new PA2EncryptionFailedException();
            }

            return originalData;
        }
        throw new PA2EncryptionFailedException();
    }

    /**
     * Decrypt encrypted response and return an instance of a provided class.
     *
     * This method first obtains bytes of the original JSON data and then attempts mapping the data to provided class instance.
     *
     * @param response Instance of encrypted response.
     * @param responseType Expected decrypted response type.
     * @param <T> Expected class of a response type.
     * @return Decrypted response in case decryption and mapping is successful, null otherwise.
     * @throws PA2EncryptionFailedException In case that encryption fails.
     */
    @Override
    public <T> T decryptResponse(PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> response, Class<T> responseType) throws PA2EncryptionFailedException {
        try {
            byte[] originalData = this.decryptResponse(response);
            return objectMapper.fromJson(new String(originalData, "UTF-8"), responseType);
        } catch (UnsupportedEncodingException e) {
            // ignore: UTF-8 not present
        }
        return null;
    }

}
