/*
 * Copyright 2019 Wultra s.r.o.
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

package io.getlime.security.powerauth.biometry.impl;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.FingerprintDialogResources;

/**
 * The {@code PrivateRequestData} class contains various temporary data required for the biometric
 * authentication request processing. The class is used internally by the SDK.
 */
public class PrivateRequestData {

    private final @NonNull BiometricAuthenticationRequest request;
    private final @NonNull BiometricResultDispatcher dispatcher;
    private final @NonNull FingerprintDialogResources resources;

    private @Nullable SecretKey secretKey;

    /**
     * Construct private reqeust data object.
     *
     * @param request Original, application provided request object.
     * @param dispatcher Dispatcher that holds completion callback and callback dispatcher.
     * @param resources Resources required for the legacy implementation.
     */
    public PrivateRequestData(@NonNull BiometricAuthenticationRequest request,
                              @NonNull BiometricResultDispatcher dispatcher,
                              @NonNull FingerprintDialogResources resources) {
        this.request = request;
        this.dispatcher = dispatcher;
        this.resources = resources;
    }

    /**
     * @return {@link BiometricAuthenticationRequest} associated with this private data object.
     */
    public @NonNull BiometricAuthenticationRequest getRequest() {
        return request;
    }

    /**
     * @return {@link BiometricResultDispatcher} associated with this private data object.
     */
    public @NonNull BiometricResultDispatcher getDispatcher() {
        return dispatcher;
    }

    /**
     * @return {@link FingerprintDialogResources} object with resources for
     */
    public @NonNull FingerprintDialogResources getResources() {
        return resources;
    }

    /**
     * Set secret key to the private request data object. The secret key has to be set before the
     * authentication is performed on the device implementation.
     * @param secretKey {@link SecretKey} object with the key protected by the biometry.
     */
    public void setSecretKey(@NonNull SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * @return {@link SecretKey} object with the key protected by the biometry. Method throws
     *         {@code IllegalStateException} in case that key was not set before.
     */
    public @NonNull SecretKey getSecretKey() {
        if (secretKey == null) {
            throw new IllegalStateException("SecretKey is null.");
        }
        return secretKey;
    }
}
