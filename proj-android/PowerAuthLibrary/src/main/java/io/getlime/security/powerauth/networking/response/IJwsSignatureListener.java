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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.MainThread;
import androidx.annotation.NonNull;

/**
 * Listener for calculating JWS or JWT signatures.
 */
public interface IJwsSignatureListener {
    /**
     * Called when JWS or JWT signature calculation succeeds.
     *
     * @param signedData the signature calculated from claims.
     * @param compactForm If {@code true}, the signed data is a compact JWT; otherwise, a full JWS
     *                    object is provided.
     */
    @MainThread
    void onJwsSignatureSucceed(@NonNull String signedData, boolean compactForm);

    /**
     * Called when data signature fails.
     *
     * @param throwable error that occurred during the data signature.
     */
    @MainThread
    void onJwsSignatureFailed(@NonNull Throwable throwable);
}
