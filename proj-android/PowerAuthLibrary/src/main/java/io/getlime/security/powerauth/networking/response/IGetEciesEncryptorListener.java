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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.core.EciesEncryptor;

/**
 * Listener for getting ECIES encryptor for general application purposes.
 */
public interface IGetEciesEncryptorListener {
    /**
     * Called when encryptor has been successfully created.
     * @param encryptor {@link EciesEncryptor} object configured for the requested scope.
     */
    void onGetEciesEncryptorSuccess(@NonNull EciesEncryptor encryptor);

    /**
     * Called when operation fails.
     * @param t Error that occurred during the operation.
     */
    void onGetEciesEncryptorFailed(@NonNull Throwable t);
}
