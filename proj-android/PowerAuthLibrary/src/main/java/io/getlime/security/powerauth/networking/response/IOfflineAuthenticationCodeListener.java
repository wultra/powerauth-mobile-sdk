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
 * Listener for offline authentication code calculation.
 */
public interface IOfflineAuthenticationCodeListener {
    /**
     * Called when offline authentication code calculation succeeds.
     *
     * @param authenticationCode the calculated offline authentication code.
     */
    @MainThread
    void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode);

    /**
     * Called when offline authentication code calculation fails.
     *
     * @param error error that occurred during the authentication code calculation.
     */
    @MainThread
    void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error);
}
