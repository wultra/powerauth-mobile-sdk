/*
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.response;

import java.util.Map;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.sdk.impl.KVHelper;

/**
 * The `UserAddress` object contains address of end-user.
 */
public class UserAddress {

    private final KVHelper<String> claims;

    /**
     * Construct object with map with claims.
     * @param claims Map with all claims representing information about the user.
     */
    UserAddress(@Nullable Map<String, Object> claims) {
        this.claims = new KVHelper<>(claims);
    }

    /**
     * @return Full collection of claims received from the server.
     */
    public @NonNull Map<String, Object> getAllClaims() {
        return claims.map;
    }

    /**
     * @return The full mailing address, with multiple lines if necessary.
     */
    public @Nullable String getFormatted() {
        return claims.valueAsMultilineString("formatted");
    }

    /**
     * @return The street address component, which may include house number, street name, post office box,
     * and other multi-line information.
     */
    public @Nullable String getStreet() {
        return claims.valueAsMultilineString("street_address");
    }

    /**
     * @return City or locality component.
     */
    public @Nullable String getLocality() {
        return claims.valueAsString("locality");
    }

    /**
     * @return State, province, prefecture or region component.
     */
    public @Nullable String getRegion() {
        return claims.valueAsString("region");
    }

    /**
     * @return Zip code or postal code component.
     */
    public @Nullable String getPostalCode() {
        return claims.valueAsString("postal_code");
    }

    /**
     * @return Country name component.
     */
    public @Nullable String getCountry() {
        return claims.valueAsString("country");
    }
}
