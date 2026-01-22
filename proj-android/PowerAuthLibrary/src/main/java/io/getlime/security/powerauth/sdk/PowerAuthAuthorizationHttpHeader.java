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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;

/**
 * Object representing a HTTP authentication header.
 *
 * This class is deprecated. Please migrate your code to use new API functions producing
 * {@link PowerAuthHttpHeader} at output.
 */
@Deprecated // 2.0.0
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
     * <p>
     * The property is deprecated and is only effective if header is calculated in deprecated methods from
     * {@link PowerAuthSDK} or {@link PowerAuthToken}.
     */
    @PowerAuthErrorCodes
    public final int powerAuthErrorCode;

    /**
     * Constructs an object with error response.
     * @param powerAuthErrorCode error to report
     */
    public PowerAuthAuthorizationHttpHeader(@PowerAuthErrorCodes int powerAuthErrorCode) {
        this.key = null;
        this.value = null;
        this.powerAuthErrorCode = PowerAuthErrorCodes.SUCCEED;
    }

    /**
     * Create instance of deprecated header object from {@link PowerAuthHttpHeader}.
     * @param header Source HTTP header.
     */
    public PowerAuthAuthorizationHttpHeader(@NonNull PowerAuthHttpHeader header) {
        this.key = header.getKey();
        this.value = header.getValue();
        this.powerAuthErrorCode = PowerAuthErrorCodes.SUCCEED;
    }

    /**
     * @return true if object contains a valid HTTP header.
     * @deprecated The new methods for calculating authentication headers throws an exception in case of failure, and
     *             therefore the returned header is always valid.
     */
    public boolean isValid() {
        return powerAuthErrorCode == PowerAuthErrorCodes.SUCCEED &&
                key != null &&
                value != null;
    }

    //
    // Getters for code compatibility reasons. In newer versions of library, you can use
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
