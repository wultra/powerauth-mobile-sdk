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

package io.getlime.security.powerauth.sdk;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;

public class PowerAuthAuthorizationHttpHeader {

    /**
     * Contains key for HTTP header or null in case of error.
     */
    public final String key;
    /**
     * Contains value for HTTP header or null in case of error.
     */
    public final String value;
    /**
     * Contains an error code from <code>PowerAuthErrorCodes</code> set of codes.
     */
    @PowerAuthErrorCodes
    public final int powerAuthErrorCode;

    /**
     * Constructs a new header object created for token based authorization header.
     *
     * @param value calculated value for token authentication
     * @return a new instance of header object created for token based authorization
     */
    public static @NonNull PowerAuthAuthorizationHttpHeader createAuthorizationHeader(@NonNull String value) {
        return new PowerAuthAuthorizationHttpHeader("X-PowerAuth-Authorization", value, PowerAuthErrorCodes.PA2Succeed);
    }

    /**
     * Constructs a new header object created for token based authorization header.
     *
     * @param value calculated value for token authentication
     * @return a new instance of header object created for token based authorization
     */
    public static @NonNull PowerAuthAuthorizationHttpHeader createTokenHeader(@NonNull String value) {
        return new PowerAuthAuthorizationHttpHeader("X-PowerAuth-Token", value, PowerAuthErrorCodes.PA2Succeed);
    }

    /**
     * Constructs an object with error response.
     *
     * @param powerAuthErrorCode error to report
     * @return a new instance of header object created with error
     */
    public static @NonNull PowerAuthAuthorizationHttpHeader createError(@PowerAuthErrorCodes int powerAuthErrorCode) {
        return new PowerAuthAuthorizationHttpHeader(null, null, powerAuthErrorCode);
    }

    /**
     * @return true if object contains a valid HTTP header.
     */
    public boolean isValid() {
        return powerAuthErrorCode == PowerAuthErrorCodes.PA2Succeed &&
                key != null &&
                value != null;
    }


    /**
     * A private constructor with all object properties.
     *
     * @param key key for HTTP header. May be null for error headers.
     * @param value value for HTTP header. May be null for error headers.
     * @param powerAuthErrorCode an error code from <code>PowerAuthErrorCodes</code> set of codes.
     */
    private PowerAuthAuthorizationHttpHeader(@Nullable String key, @Nullable String value, @PowerAuthErrorCodes int powerAuthErrorCode) {
        this.key = key;
        this.value = value;
        this.powerAuthErrorCode = powerAuthErrorCode;
    }

    //
    // Getters for code compatibility compatibility. In newer versions of library, you can use
    // final public properties to access the elements.
    //

    @PowerAuthErrorCodes
    public int getPowerAuthErrorCode() {
        return powerAuthErrorCode;
    }

    public @Nullable String getKey() {
        return key;
    }

    public @Nullable String getValue() {
        return value;
    }
}
