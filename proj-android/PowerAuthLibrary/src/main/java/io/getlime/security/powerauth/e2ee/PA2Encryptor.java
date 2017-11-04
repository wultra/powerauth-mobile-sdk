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

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public interface PA2Encryptor {

    /**
     * Encrypt data using non-personalized (application key specific) or personalized (activation
     * specific) encryption and return ready to use request object.
     *
     * @param originalData Bytes with request body payload.
     * @return New instance of a ready to use encrypted request, or nil if error occurs.
     * @throws PA2EncryptionFailedException In case that encryption fails.
     */
    ObjectRequest<NonPersonalizedEncryptedPayloadModel> encryptRequestData(byte[] originalData) throws PA2EncryptionFailedException;

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
    ObjectRequest<NonPersonalizedEncryptedPayloadModel> encryptRequestData(Object requestObject) throws PA2EncryptionFailedException;

    /**
     * Decrypt encrypted response and return plain decrypted response data.
     *
     * @param response Instance of encrypted response.
     * @return Decrypted response bytes, or nil if error occurs.
     * @throws PA2EncryptionFailedException In case that encryption fails.
     */
    byte[] decryptResponse(ObjectResponse<NonPersonalizedEncryptedPayloadModel> response) throws PA2EncryptionFailedException;

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
    <T> T decryptResponse(ObjectResponse<NonPersonalizedEncryptedPayloadModel> response, Class<T> responseType) throws PA2EncryptionFailedException;

}
