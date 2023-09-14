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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;

/**
 * Interface to be used to get status of the server from the server.
 */
public interface IServerStatusProvider {
    /**
     * Fetch status of the server from the server.
     * @param listener The callback called when operation succeeds or fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    @Nullable
    ICancelable getServerStatus(@NonNull IServerStatusListener listener);
}
