/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.interfaces;

/**
 * The {@code INetworkResponseListener} defines callback interface from HTTP client
 */
public interface INetworkResponseListener<TResponse> {
    /**
     * Called when HTTP request successfully ended and the response object is available.
     * @param response response object returned from the server
     */
    void onNetworkResponse(TResponse response);

    /**
     * Called when HTTP request failed with an error.
     * @param throwable exception with an error
     */
    void onNetworkError(Throwable throwable);

    /**
     * Called when HTTP request was cancelled.
     */
    void onCancel();
}
