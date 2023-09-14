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

import java.util.Date;
import java.util.Map;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.sdk.impl.KVHelper;

/**
 * The `UserInfo` object contains additional information about the end-user.
 */
public class UserInfo {

    private final @NonNull KVHelper<String> claims;
    private final @Nullable Date birthdate;
    private final @Nullable UserAddress address;

    /**
     * Construct object with map with claims.
     * @param claims Map with all claims representing information about the user.
     */
    public UserInfo(@Nullable Map<String, Object> claims) {
        this.claims = new KVHelper<>(claims);
        this.birthdate = this.claims.valueAsDate("birthdate", "yyyy-MM-dd");
        final Map<String, Object> addressObject = this.claims.valueAsMap("address");
        this.address = addressObject != null ? new UserAddress(addressObject) : null;
    }

    /**
     * @return Full collection of claims received from the server.
     */
    public @NonNull Map<String, Object> getAllClaims() {
        return claims.map;
    }

    /**
     * @return The subject (end-user) identifier. This is a mandatory identifier by OpenID
     * specification, but by default, not provided by PowerAuth based enrollment server.
     */
    public @Nullable String getSubject() {
        return claims.valueAsString("sub");
    }

    /**
     * @return The full name of the end-user.
     */
    public @Nullable String getName() {
        return claims.valueAsString("name");
    }

    /**
     * @return The given or first name of the end-user.
     */
    public @Nullable String getGivenName() {
        return claims.valueAsString("given_name");
    }

    /**
     * @return The surname(s) or last name(s) of the end-user.
     */
    public @Nullable String getFamilyName() {
        return claims.valueAsString("family_name");
    }

    /**
     * @return The middle name of the end-user.
     */
    public @Nullable String getMiddleName() {
        return claims.valueAsString("middle_name");
    }

    /**
     * @return The casual name of the end-user.
     */
    public @Nullable String getNickname() {
        return claims.valueAsString("nickname");
    }

    /**
     * @return The username by which the end-user wants to be referred to at the client application.
     */
    public @Nullable String getPreferredUsername() {
        return claims.valueAsString("preferred_username");
    }

    /**
     * @return The URL of the profile page for the end-user.
     */
    public @Nullable String getProfileUrl() {
        return claims.valueAsString("profile");
    }

    /**
     * @return The URL of the profile picture for the end-user.
     */
    public @Nullable String getPictureUrl() {
        return claims.valueAsString("picture");
    }

    /**
     * @return The URL of the end-user's web page or blog.
     */
    public @Nullable String getWebsiteUrl() {
        return claims.valueAsString("website");
    }

    /**
     * @return The end-user's preferred email address.
     */
    public @Nullable String getEmail() {
        return claims.valueAsString("email");
    }

    /**
     * @return `true` if the end-user's email address has been verified, else `false`.
     * Note that the value is false also when claim is not present in `claims` dictionary.
     */
    public boolean isEmailVerified() {
        return claims.valueAsBool("email_verified");
    }

    /**
     * @return The end-user's preferred telephone number, typically in E.164 format, for example
     * `+1 (425) 555-1212` or `+56 (2) 687 2400`.
     */
    public @Nullable String getPhoneNumber() {
        return claims.valueAsString("phone_number");
    }

    /**
     * @return `true` if the end-user's telephone number has been verified, else `false`. Note that
     * value is false also when claim is not present in `claims` dictionary.
     */
    public boolean isPhoneNumberVerified() {
        return claims.valueAsBool("phone_number_verified");
    }

    /**
     * @return The end-user's gender.
     */
    public @Nullable String getGender() {
        return claims.valueAsString("gender");
    }

    /**
     * @return The end-user's birthday.
     */
    public @Nullable Date getBirthdate() {
        return birthdate;
    }

    /**
     * @return The end-user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles`.
     */
    public @Nullable String getZoneInfo() {
        return claims.valueAsString("zoneinfo");
    }

    /**
     * @return The end-user's locale, represented as a BCP47 language tag. This is typically
     * an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code
     * in uppercase, separated by a dash. For example, `en-US` or `fr-CA`.
     */
    public @Nullable String getLocale() {
        return claims.valueAsString("locale");
    }

    /**
     * @return An object describing the end-user's preferred postal address.
     */
    public @Nullable UserAddress getAddress() {
        return address;
    }

    /**
     * @return Time the end-user's information was last updated.
     */
    public @Nullable Date getUpdatedAt() {
        return claims.valueAsTimestamp("updated_at");
    }
}
