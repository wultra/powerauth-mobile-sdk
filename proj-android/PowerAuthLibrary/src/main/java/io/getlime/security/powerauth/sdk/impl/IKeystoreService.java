/*
 * Copyright 2024 Wultra s.r.o.
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.core.EciesEncryptorScope;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

/**
 * The {@code IKeystoreService} is interface for getting temporary encryption keys for ECIES encryption from the server.
 * The key itself is stored in {@link io.getlime.security.powerauth.core.Session} instance and is available for further
 * encryption operations.
 */
public interface IKeystoreService {
    /**
     * Determine whether the service contains key for the requested encryption scope.
     * @param scope The scope of the key.
     * @return {@code true} if service contains a valid key for the requested encryption scope.
     */
    boolean containsKeyForEncryptor(@EciesEncryptorScope int scope);

    /**
     * Create a key for the requested encryptor scope. If the already exist and is valid, then does nothing.
     * @param scope The scope of the key.
     * @param cryptoHelper Implementation of {@link IPrivateCryptoHelper} interface.
     * @param listener The listener where the result of the operation will be notified.
     * @return Cancelable operation if communication with the server is required, or {@code null} if the result of
     *         the call has been determined immediately.
     */
    @Nullable
    ICancelable createKeyForEncryptor(@EciesEncryptorScope int scope, @NonNull IPrivateCryptoHelper cryptoHelper, @NonNull ICreateKeyListener listener);
}
