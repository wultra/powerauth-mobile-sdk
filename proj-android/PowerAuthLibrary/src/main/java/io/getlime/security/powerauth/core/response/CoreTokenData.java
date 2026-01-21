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

package io.getlime.security.powerauth.core.response;

import androidx.annotation.NonNull;

/**
 * The {@code CoreTokenData} object contains token data received from the server.
 */
public class CoreTokenData {

    private final int factorMask;
    @NonNull
    private final String tokenIdentifier;
    @NonNull
    private final byte[] tokenSecret;


    /**
     * Construct response object with given parameters. The constructor is used from JNI wrapper to
     * construct response received from the server.
     *
     * @param factorMask Integer representing factors used for the token construction.
     * @param tokenIdentifier Token's identifier.
     * @param tokenSecret Token's secret.
     */
    public CoreTokenData(int factorMask, @NonNull String tokenIdentifier, @NonNull byte[] tokenSecret) {
        this.factorMask = factorMask;
        this.tokenIdentifier = tokenIdentifier;
        this.tokenSecret = tokenSecret;
    }

    /**
     * Get factors involved in the token construction:
     * <ul>
     *     <li>For {@code POSSESSION}, value is {@code 1}</li>
     *     <li>For {@code POSSESSION_KNOWLEDGE}, value is {@code 1 + 2}</li>
     *     <li>For {@code POSSESSION_BIOMETRY}, value is {@code 1 + 4}</li>
     * </ul>
     * @return factors involved in the token construction.
     */
    public int getFactorMask() {
        return factorMask;
    }

    /**
     * @return Token's identifier.
     */
    @NonNull
    public String getTokenIdentifier() {
        return tokenIdentifier;
    }

    /**
     * @return Token's secret.
     */
    @NonNull
    public byte[] getTokenSecret() {
        return tokenSecret;
    }
}
