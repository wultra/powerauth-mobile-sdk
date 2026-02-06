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

import io.getlime.security.powerauth.sdk.impl.PowerAuthPasswordChangeData;

/**
 * Listener for the first step of password change.
 */
public interface IBeginPasswordChangeListener {

    /**
     * Called when the first step of the password change process completes successfully.
     *
     * @param passwordChangeData {@link PowerAuthPasswordChangeData} object received on successful
     *                           first step of password change process. The object is required for
     *                           the second step of the password change process.
     */
    @MainThread
    void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData);

    /**
     * Called when the first step of the password change process fails.
     *
     * @param throwable error that occurred during the first step of the password change process.
     */
    @MainThread
    void onBeginPasswordChangeFailed(@NonNull Throwable throwable);

}
