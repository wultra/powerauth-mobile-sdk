/*
 * Copyright 2019 Wultra s.r.o.
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

package io.getlime.security.powerauth.biometry;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.StringRes;

import java.util.Arrays;

/**
 * The {@code BiometricAuthenticationRequest} class contains information required for biometric authentication.
 */
public class BiometricAuthenticationRequest {

    private final @NonNull CharSequence title;
    private final @Nullable CharSequence subtitle;
    private final @NonNull CharSequence description;
    private final boolean forceGenerateNewKey;
    private final boolean invalidateByBiometricEnrollment;
    private final @NonNull byte[] keyToProtect;

    private BiometricAuthenticationRequest(
            @NonNull CharSequence title,
            @Nullable CharSequence subtitle,
            @NonNull CharSequence description,
            boolean forceGenerateNewKey,
            boolean invalidateByBiometricEnrollment,
            @NonNull byte[] keyToProtect) {
        this.title = title;
        this.subtitle = subtitle;
        this.description = description;
        this.forceGenerateNewKey = forceGenerateNewKey;
        this.invalidateByBiometricEnrollment = invalidateByBiometricEnrollment;
        this.keyToProtect = Arrays.copyOf(keyToProtect, keyToProtect.length);
    }

    /**
     * @return String with the title of the biometric authentication dialog.
     */
    public @NonNull CharSequence getTitle() {
        return title;
    }

    /**
     * @return String with the subtitle for the biometric authentication dialog.
     */
    public @Nullable CharSequence getSubtitle() {
        return subtitle;
    }

    /**
     * @return String with the description for the biometric authentication dialog.
     */
    public @NonNull CharSequence getDescription() {
        return description;
    }

    /**
     * @return true whether the new biometric key has to be generated as a part of the operation.
     */
    public boolean isForceGenerateNewKey() {
        return forceGenerateNewKey;
    }

    /**
     * @return Whether the new key should be invalidated on biometric enrollment.
     */
    public boolean isInvalidateByBiometricEnrollment() {
        return invalidateByBiometricEnrollment;
    }

    /**
     * @return Application provided key which will be protected by the biometric key.
     */
    public @NonNull byte[] getKeyToProtect() {
        return keyToProtect;
    }

    /**
     * A builder class that collects arguments required for the biometric dialog.
     */
    public static class Builder {

        private final @NonNull Context context;

        private CharSequence title;
        private CharSequence subtitle;
        private CharSequence description;

        private boolean forceGenerateNewKey;
        private boolean invalidateByBiometricEnrollment = true;
        private byte[] keyToProtect;

        /**
         * Creates a builder for a biometric dialog.
         *
         * @param context Android {@link Context} object
         */
        public Builder(@NonNull Context context) {
            this.context = context;
        }

        /**
         * Creates a {@link BiometricAuthenticationRequest} which can be used for the biometric
         * authentication.
         *
         * @return Instance of {@link BiometricAuthenticationRequest} object.
         */
        public BiometricAuthenticationRequest build() {
            if (title == null || description == null) {
                throw new IllegalArgumentException("Title and description is required.");
            }
            if (keyToProtect == null) {
                throw new IllegalArgumentException("KeyToProtect is required.");
            }
            if (keyToProtect.length < 16) {
                throw new IllegalArgumentException("KeyToProtect length is insufficient.");
            }
            return new BiometricAuthenticationRequest(
                    title,
                    subtitle,
                    description,
                    forceGenerateNewKey,
                    invalidateByBiometricEnrollment,
                    keyToProtect);
        }

        /**
         * Required: Set the title to display.
         *
         * @param title Title string to display
         * @return This value will never be {@code null}.
         */
        public Builder setTitle(@NonNull CharSequence title) {
            this.title = title;
            return this;
        }
        /**
         * Required: Set the title to display.
         *
         * @param titleId String resource identifier containing the title to display.
         * @return This value will never be {@code null}.
         */
        public Builder setTitle(@StringRes int titleId) {
            return setTitle(context.getText(titleId));
        }

        /**
         * Optional: Set the subtitle to display.
         *
         * @param subtitle Subtitle string to display
         * @return This value will never be {@code null}.
         */
        public Builder setSubtitle(@NonNull CharSequence subtitle) {
            this.subtitle = subtitle;
            return this;
        }

        /**
         * Optional: Set the subtitle to display.
         *
         * @param subtitleId String resource identifier containing the subtitle to display.
         * @return This value will never be {@code null}.
         */
        public Builder setSubtitle(@StringRes int subtitleId) {
            return setSubtitle(context.getText(subtitleId));
        }

        /**
         * Optional: Set the description to display.
         *
         * @param description Description string to display
         * @return This value will never be {@code null}.
         */
        public Builder setDescription(@NonNull CharSequence description) {
            this.description = description;
            return this;
        }

        /**
         * Optional: Set the subtitle to display.
         *
         * @param descriptionId String resource identifier containing the description to display.
         * @return This value will never be {@code null}.
         */
        public Builder setDescription(@StringRes int descriptionId) {
            return setDescription(context.getText(descriptionId));
        }

        /**
         * @param forceGenerateNewKey If true then the new biometric key will be generated as a
         *                            part of the process.
         * @param invalidateByBiometricEnrollment Sets whether the new key should be invalidated on
         *                                       biometric enrollment.
         * @return This value will never be {@code null}.
         */
        public Builder setForceGenerateNewKey(boolean forceGenerateNewKey, boolean invalidateByBiometricEnrollment) {
            this.forceGenerateNewKey = forceGenerateNewKey;
            this.invalidateByBiometricEnrollment = invalidateByBiometricEnrollment;
            return this;
        }

        /**
         * Required: Sets sequence of bytes as key, which will be encrypted by the biometry.
         *
         * @param keyBytes Array of bytes containing a key, which will be encrypted by the biometric key.
         * @return This value will never be {@code null}.
         */
        public Builder setKeyToProtect(@NonNull byte[] keyBytes) {
            this.keyToProtect = keyBytes;
            return this;
        }
    }
}
