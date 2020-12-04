/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.interceptors;

import androidx.annotation.NonNull;

import java.net.HttpURLConnection;

/**
 * The {@code CustomHeaderRequestInterceptor} class implements {@link HttpRequestInterceptor} interface
 * and allows you set an arbitrary HTTP header to requests, executed internally in PowerAuth SDK.
 */
public class CustomHeaderRequestInterceptor implements HttpRequestInterceptor {

    private final String headerKey;
    private final String headerValue;

    /**
     * @param headerKey String with HTTP header key.
     * @param headerValue String with corresponding header's value.
     */
    public CustomHeaderRequestInterceptor(@NonNull String headerKey, @NonNull String headerValue) {
        this.headerKey = headerKey;
        this.headerValue = headerValue;
    }

    /**
     * @return HTTP header's key provided in object initialization.
     */
    public @NonNull String getHeaderKey() {
        return headerKey;
    }

    /**
     * @return HTTP header's value provided in object initialization.
     */
    public @NonNull String getHeaderValue() {
        return headerValue;
    }

    @Override
    public void processRequestConnection(@NonNull HttpURLConnection connection) {
        connection.addRequestProperty(headerKey, headerValue);
    }
}
