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

import io.getlime.security.powerauth.sdk.PowerAuthSecureVaultKey;

/**
 * Listener for secure vault key retrieval.
 */
public interface IFetchSecureVaultKeyListener {
    /**
     * Called when secure vault key key is successfully retrieved.
     *
     * @param vaultKey the retrieved secure vault key.
     */
    @MainThread
    void onFetchSecureVaultKeySucceed(@NonNull PowerAuthSecureVaultKey vaultKey);

    /**
     * Called when secure vault key key retrieval fails.
     *
     * @param throwable error that occurred during the encryption key retrieval.
     */
    @MainThread
    void onFetchSecureVaultKeyFailed(@NonNull Throwable throwable);
}
