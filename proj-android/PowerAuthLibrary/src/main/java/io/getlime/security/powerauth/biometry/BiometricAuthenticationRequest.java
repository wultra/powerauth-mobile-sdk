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
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import android.text.TextUtils;

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
    private final boolean userConfirmationRequired;
    private final boolean useSymmetricCipher;
    private final @NonNull byte[] rawKeyData;
    private final @NonNull IBiometricKeyEncryptor biometricKeyEncryptor;

    private BiometricAuthenticationRequest(
            @NonNull CharSequence title,
            @Nullable CharSequence subtitle,
            @NonNull CharSequence description,
            boolean forceGenerateNewKey,
            boolean invalidateByBiometricEnrollment,
            boolean userConfirmationRequired,
            boolean useSymmetricCipher,
            @NonNull byte[] rawKeyData,
            @NonNull IBiometricKeyEncryptor biometricKeyEncryptor) {
        this.title = title;
        this.subtitle = subtitle;
        this.description = description;
        this.forceGenerateNewKey = forceGenerateNewKey;
        this.invalidateByBiometricEnrollment = invalidateByBiometricEnrollment;
        this.userConfirmationRequired = userConfirmationRequired;
        this.useSymmetricCipher = useSymmetricCipher;
        this.rawKeyData = Arrays.copyOf(rawKeyData, rawKeyData.length);
        this.biometricKeyEncryptor = biometricKeyEncryptor;
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
     * @return {@code true} in case that user's confirmation is required.
     */
    public boolean isUserConfirmationRequired() {
        return userConfirmationRequired;
    }

    /**
     * @return {@code true} in case that symmetric cipher should be used for biometric key protection.
     */
    public boolean isUseSymmetricCipher() {
        return useSymmetricCipher;
    }

    /**
     * @return Application provided key which will be protected by the biometric key. The content
     * depends on whether the key is being encrypted (for key setup procedure) or decrypted (for
     * a signature calculation).
     */
    public @NonNull byte[] getRawKeyData() {
        return rawKeyData;
    }

    /**
     * @return Object that encrypt or decrypt raw key data.
     */
    public @NonNull IBiometricKeyEncryptor getBiometricKeyEncryptor() {
        return biometricKeyEncryptor;
    }

    /**
     * A builder class that collects arguments required for the biometric dialog.
     */
    public static class Builder {

        private final @NonNull Context context;

        private CharSequence title;
        private CharSequence subtitle;
        private CharSequence description;

        private boolean forceGenerateNewKey = false;
        private boolean invalidateByBiometricEnrollment = true;
        private boolean userConfirmationRequired = false;
        private boolean useSymmetricCipher = true;
        private byte[] rawKeyData;
        private IBiometricKeyEncryptor biometricKeyEncryptor;

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
            if (TextUtils.isEmpty(title) || TextUtils.isEmpty(description)) {
                throw new IllegalArgumentException("Title and description is required.");
            }
            if (rawKeyData == null) {
                throw new IllegalArgumentException("RawKeyData is required.");
            }
            if (rawKeyData.length < 16) {
                throw new IllegalArgumentException("RawKeyData length is insufficient.");
            }
            if (biometricKeyEncryptor == null) {
                throw new IllegalArgumentException("BiometricKeyEncryptor is required.");
            }
            return new BiometricAuthenticationRequest(
                    title,
                    subtitle,
                    description,
                    forceGenerateNewKey,
                    invalidateByBiometricEnrollment,
                    userConfirmationRequired,
                    useSymmetricCipher,
                    rawKeyData,
                    biometricKeyEncryptor);
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
         * @param forceGenerateNewKey             If true then the new biometric key will be generated as a
         *                                        part of the process.
         * @param invalidateByBiometricEnrollment Sets whether the new key should be invalidated on
         *                                        biometric enrollment.
         * @param useSymmetricCipher              If true then symmetric cipher will be used to biometric
         *                                        factor key protection.
         * @return This value will never be {@code null}.
         */
        public Builder setForceGenerateNewKey(boolean forceGenerateNewKey, boolean invalidateByBiometricEnrollment, boolean useSymmetricCipher) {
            this.forceGenerateNewKey = forceGenerateNewKey;
            this.invalidateByBiometricEnrollment = invalidateByBiometricEnrollment;
            this.useSymmetricCipher = useSymmetricCipher;
            return this;
        }

        /**
         * Optional: A hint to the system to require user confirmation after a biometric has been
         * authenticated. For example, implicit modalities like Face and Iris authentication are
         * passive, meaning they don't require an explicit user action to complete. When set to
         * {@code false}, the user action (e.g. pressing a button) will not be required. {@code BiometricPrompt}
         * will require confirmation by default.
         *
         * @param userConfirmationRequired Whether user's confirmation should be required in the biometric prompt.
         * @return This value will never be {@code null}.
         */
        public Builder setUserConfirmationRequired(boolean userConfirmationRequired) {
            this.userConfirmationRequired = userConfirmationRequired;
            return this;
        }

        /**
         * Required: Sets sequence of bytes that will be encrypted or decrypted with using biometric authentication.
         *
         * @param keyData Array of bytes containing a key, which will be encrypted by the biometric key.
         * @param biometricKeyEncryptor Object that perform biometric key encryption and decryption.
         * @return This value will never be {@code null}.
         */
        public Builder setRawKeyData(@NonNull byte[] keyData, @NonNull IBiometricKeyEncryptor biometricKeyEncryptor) {
            this.rawKeyData = keyData;
            this.biometricKeyEncryptor = biometricKeyEncryptor;
            return this;
        }
    }
}
