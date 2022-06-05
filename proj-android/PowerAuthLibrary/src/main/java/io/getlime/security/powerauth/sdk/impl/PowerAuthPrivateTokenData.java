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

package io.getlime.security.powerauth.sdk.impl;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


/**
 * The {@code PowerAuthPrivateTokenData} keeps all private data for access token.
 */
public class PowerAuthPrivateTokenData {

    /**
     * Token's symbolic name.
     */
    public final String name;
    /**
     * Token's identifier.
     */
    public final String identifier;
    /**
     * Token's secret.
     */
    public final byte[] secret;
    /**
     * Identifier of activation associated to this token.
     */
    public final String activationId;

    private static final int SECRET_LENGTH = 16;

    public PowerAuthPrivateTokenData(@NonNull String name, @NonNull String identifier, @NonNull byte[] secret, @Nullable String activationId) {
        this.name = name;
        this.identifier = identifier;
        this.secret = secret;
        this.activationId = activationId;
    }

    public boolean hasValidData() {
        return secret.length == SECRET_LENGTH &&
               !identifier.isEmpty() &&
               !name.isEmpty();
    }

    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof PowerAuthPrivateTokenData) {
            PowerAuthPrivateTokenData anotherToken = (PowerAuthPrivateTokenData) anObject;
            if (this.hasValidData() && anotherToken.hasValidData()) {
                boolean result = name.equals(anotherToken.name) &&
                        identifier.equals(anotherToken.identifier) &&
                        Arrays.equals(secret, anotherToken.secret);
                if (result) {
                    boolean hasActivationId = activationId != null;
                    boolean otherHasActivationId = anotherToken.activationId != null;
                    if (hasActivationId == otherHasActivationId) {
                        if (hasActivationId) {
                            // Both have activationId, so compare the strings.
                            result = activationId.equals(anotherToken.activationId);
                        }
                    } else {
                        // One object has AID but another one not.
                        result = false;
                    }
                }
                return result;
            }
        }
        return false;
    }

    public @Nullable byte[] getSerializedData() {

        if (!this.hasValidData()) {
            return null;
        }

        final String nameB64 = Base64.encodeToString(name.getBytes(), Base64.NO_WRAP);
        final String secretB64 = Base64.encodeToString(secret, Base64.NO_WRAP);

        final StringBuilder sb = new StringBuilder();
        sb.append(identifier);
        sb.append(',');
        sb.append(secretB64);
        sb.append(',');
        sb.append(nameB64);
        if (activationId != null) {
            sb.append(',');
            sb.append(activationId);
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    public static @Nullable PowerAuthPrivateTokenData deserializeWithData(@NonNull byte[] data) {

        String str = new String(data, StandardCharsets.US_ASCII);
        // Split into components
        final String[] components = str.split("\\,");
        if (components.length != 3 && components.length != 4) {
            return null;
        }
        final String identifier = components[0];
        final byte[] secret = Base64.decode(components[1], Base64.NO_WRAP);
        final String name = new String(Base64.decode(components[2], Base64.NO_WRAP));
        final String activationId;
        if (components.length == 4) {
            activationId = components[3];
        } else {
            activationId = null;
        }

        final PowerAuthPrivateTokenData tokenData = new PowerAuthPrivateTokenData(name, identifier, secret, activationId);
        return tokenData.hasValidData() ? tokenData : null;
    }
}
