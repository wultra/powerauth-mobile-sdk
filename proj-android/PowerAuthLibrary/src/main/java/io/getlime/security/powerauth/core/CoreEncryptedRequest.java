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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;

/**
 * The {@code CoreEncryptedRequest} represents encrypted request.
 */
public class CoreEncryptedRequest {
    private final byte[] requestBody;
    private final CoreHttpHeader[] requestHeaders;

    /**
     * Create encrypted request with body and headers. The constructor is typically used from JNI.
     * @param requestBody Request body.
     * @param requestHeaders Request headers.
     */
    public CoreEncryptedRequest(@NonNull byte[] requestBody, @NonNull CoreHttpHeader[] requestHeaders) {
        this.requestBody = requestBody;
        this.requestHeaders = requestHeaders;
    }

    /**
     * @return Request body.
     */
    @NonNull
    public byte[] getRequestBody() {
        return requestBody;
    }

    /**
     * @return Request headers.
     */
    @NonNull
    public CoreHttpHeader[] getRequestHeaders() {
        return requestHeaders;
    }
}
