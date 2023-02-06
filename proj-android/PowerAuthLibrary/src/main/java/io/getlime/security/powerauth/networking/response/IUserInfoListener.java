/*
 * Copyright 2023 Wultra s.r.o.
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
 * Listener for user information retrieval.
 */
public interface IUserInfoListener {
    /**
     * Called when activation status retrieval succeeds.
     *
     * @param userInfo retrieved information about user.
     */
    @MainThread
    void onUserInfoSucceed(@NonNull UserInfo userInfo);

    /**
     * Called when getting user information fails.
     *
     * @param t error that occurred during the user information retrieval.
     */
    @MainThread
    void onUserInfoFailed(@NonNull Throwable t);
}
