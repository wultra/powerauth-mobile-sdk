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

import io.getlime.security.powerauth.core.TokenCalculator;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.sdk.impl.PowerAuthPrivateTokenData;

/**
 * The <code>PowerAuthToken</code> class generates a token based authorization headers.
 * You have to use {@code PowerAuthTokenStore} to get an instance of this class.
 * <p>
 * The whole interface is thread safe.
 */
public class PowerAuthToken {

    /**
     * Reference to store which created this instance of token.
     */
    public final PowerAuthTokenStore tokenStore;
    /**
     * Token's private data
     */
    private final PowerAuthPrivateTokenData tokenData;

    /**
     * @param store {@link PowerAuthTokenStore} object who creates this token
     * @param tokenData private token data
     */
    public PowerAuthToken(@NonNull PowerAuthTokenStore store, @NonNull PowerAuthPrivateTokenData tokenData) {
        this.tokenStore = store;
        this.tokenData = tokenData;
    }

    /**
     * Return true if this token object contains a valid token data.
     * @return true if token has valid data.
     */
    public boolean isValid() {
        return tokenData.hasValidData();
    }


    /**
     * Compares this token to the specified object.
     *
     * @param anObject object to compare
     * @return true if objects are equal.
     */
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof PowerAuthToken) {
            PowerAuthToken anotherToken = (PowerAuthToken) anObject;
            if (anotherToken.isValid() && this.isValid()) {
                return tokenStore == anotherToken.tokenStore &&
                        tokenData.equals(anotherToken.tokenData);
            }
        }
        return false;
    }

    /**
     * @return symbolic name of token or null if token contains an invalid data.
     */
    public @Nullable String getTokenName() {
        return tokenData.name;
    }

    /**
     * Return token's unique identifier. You normally don't need this value, but it may help
     * with application's debugging. The value identifies this token on PowerAuth server.
     *
     * @return token's unique identifier or null if token contains an invalid data.
     */
    public @Nullable String getTokenIdentifier() {
        return tokenData.identifier;
    }


    /**
     * @return true if token can generate a new header
     */
    public boolean canGenerateHeader() {
        return tokenStore.canRequestForAccessToken();
    }

    /**
     * Generates a new HTTP header for token based authorization.
     *
     * @return calculated HTTP authorization header. The header object contains an information
     *         about error, so check its <code>isValid()</code> method afterwards.
     */
    public @NonNull PowerAuthAuthorizationHttpHeader generateHeader() {
        @PowerAuthErrorCodes int errorCode;
        if (this.isValid()) {
            if (tokenStore.canRequestForAccessToken()) {
                String headerValue = TokenCalculator.calculateTokenValue(tokenData);
                if (headerValue != null) {
                    return PowerAuthAuthorizationHttpHeader.createTokenHeader(headerValue);
                } else {
                    errorCode = PowerAuthErrorCodes.PA2ErrorCodeSignatureError;
                }
            } else {
                errorCode = PowerAuthErrorCodes.PA2ErrorCodeMissingActivation;
            }
        } else {
            errorCode = PowerAuthErrorCodes.PA2ErrorCodeInvalidToken;
        }
        // In case of error, create an object with error.
        return PowerAuthAuthorizationHttpHeader.createError(errorCode);
    }
}
