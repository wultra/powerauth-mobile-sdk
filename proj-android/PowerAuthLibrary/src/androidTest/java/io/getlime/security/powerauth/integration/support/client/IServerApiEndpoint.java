/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support.client;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.reflect.TypeToken;

/**
 * Interface defines endpoint for communicating with PowerAuth Server REST API.
 */
public interface IServerApiEndpoint<TResponse> {
    /**
     * @return String with relative path to construct full URL
     */
    @NonNull String getRelativePath();

    /**
     * @return Type of response object or {@code null} in case of empty response.
     */
    @Nullable TypeToken<TResponse> getResponseType();
}
