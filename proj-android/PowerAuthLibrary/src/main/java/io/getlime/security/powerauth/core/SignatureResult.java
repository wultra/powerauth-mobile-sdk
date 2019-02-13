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

package io.getlime.security.powerauth.core;

import android.support.annotation.NonNull;

/**
 * Result from signature calculation.
 */
public class SignatureResult {

    /**
     * Error code returned from the C++ code. The value can be compared
     * to constants from {@link ErrorCode} class.
     */
    @ErrorCode
    public final int errorCode;

    /**
     * Contains a complete value for "X-PowerAuth-Authorization" HTTP header.
     */
    public final String authHeaderValue;

    /**
     * Calculated signature. Unlike `authHeaderValue`, this property contains just
     * a numeric authentication code.
     */
    public final String signatureCode;

    /**
     * Constructor used from JNI code.
     */
    public SignatureResult() {
        this.errorCode = 0;
        this.authHeaderValue = null;
        this.signatureCode = null;
    }


    /**
     * @return Always non-null authorization header value. If the error code is not Ok,
     *         then the empty string is returned.
     */
    public @NonNull String getAuthHeaderValue() {
        return authHeaderValue != null ? authHeaderValue : "";
    }

    /**
     * @return Always non-null signature code.  If the error code is not Ok,
     *         then the empty string is returned.
     */
    public @NonNull String getSignatureCode() {
        return signatureCode != null ? signatureCode : "";
    }
}