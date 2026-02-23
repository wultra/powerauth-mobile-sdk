/*
 * Copyright 2025 Wultra s.r.o.
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

import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Listener for Creating PowerAuth signed CSR.
 *
 * @deprecated Deprecated in favor of {@link ICreateCertificateSigningRequestListener}.
 */
@Deprecated(since = "2.0.0")
public interface ICreateCSRListener {

    /**
     * When CSR is successfully created, this method is called with CSR string in PEM format.
     */
    @MainThread
    void onCSRCreateSucceed(@NonNull String csr);

    /**
     * Called when CSR creation fails.
     *
     * @param error Error that occurred during the CSR creation.
     */
    @MainThread
    void onCSRCreateFailed(@NonNull PowerAuthErrorException error);
}
