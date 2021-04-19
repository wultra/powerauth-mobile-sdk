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

import androidx.annotation.ColorRes;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.StringRes;

import io.getlime.security.powerauth.R;

/**
 * The {@code BiometricDialogResources} contains resource identifier of layout, strings, drawables
 * and other information, required for the display of error dialog after failed biometric authentication.
 *
 * You can construct your own set of resources and use it in {@link BiometricAuthentication#setBiometricDialogResources(BiometricDialogResources)}
 * method, to affect all future biometric authentication requests.
 */
public class BiometricDialogResources {

    /**
     * Contains object with strings, required for an error handling.
     */
    public final @NonNull Strings strings;

    /**
     * Contains object with icons, displayed in the fingerprint dialog.
     */
    public final @NonNull Drawables drawables;

    private BiometricDialogResources(
            @NonNull Strings strings,
            @NonNull Drawables drawables) {
        this.strings = strings;
        this.drawables = drawables;
    }

    /**
     * A builder that collects resources required for the fallback fingerprint dialog.
     */
    public static class Builder {

        private Strings strings;
        private Drawables drawables;

        public Builder() {
        }

        /**
         * Creates {@link BiometricDialogResources} object.
         * @return Instance of {@link BiometricDialogResources}.
         */
        public BiometricDialogResources build() {
            return new BiometricDialogResources(
                    strings != null ? strings : Strings.getDefaultStrings(),
                    drawables != null ? drawables : Drawables.getDefaultDrawables());
        }

        /**
         * @param strings Object with string resources required for the future dialog.
         * @return This value will never be null.
         */
        public Builder setStrings(@NonNull final Strings strings) {
            this.strings = strings;
            return this;
        }

        /**
         * @param drawables Object with drawable resources required for the future dialog.
         * @return This value will never be null.
         */
        public Builder setDrawables(@NonNull final Drawables drawables) {
            this.drawables = drawables;
            return this;
        }
    }


    /**
     * The nested {@code Strings} class contains all strings resources used by the SDK.
     */
    public static class Strings {
        /**
         * "OK" button.
         */
        public final @StringRes int ok;

        /**
         * "Close" button.
         */
        public final @StringRes int close;

        /**
         * Title that informs that user needs to enroll at least one fingerprint image.
         */
        public final @StringRes int errorEnrollFingerprintTitle;
        /**
         * Message that informs that user needs to enroll at least one fingerprint image.
         */
        public final @StringRes int errorEnrollFingerprintDescription;

        /**
         * Title that informs that device has no biometric hardware available.
         */
        public final @StringRes int errorNoFingerprintScannerTitle;
        /**
         * Message that informs that device has no biometric hardware available.
         */
        public final @StringRes int errorNoFingerprintScannerDescription;

        /**
         * Title that informs that biometric support has been disabled on the device, or is not available.
         */
        public final @StringRes int errorFingerprintDisabledTitle;
        /**
         * Message that informs that biometric support has been disabled on the device, or is not available.
         */
        public final @StringRes int errorFingerprintDisabledDescription;

        /**
         * String for error code that instructs user that biometric authentication has been locked out.
         */
        public final @StringRes int errorCodeLockout;
        /**
         * String for all other error codes, reported from biometric API.
         */
        public final @StringRes int errorCodeGeneric;

        /**
         * Deprecated in version 1.6.0. Please review your resources and use new constructor
         * with reduced number of strings.
         *
         * @param ok Resource string still in use.
         * @param close Resource string still in use.
         * @param errorEnrollFingerprintTitle Resource string still in use.
         * @param errorEnrollFingerprintDescription Resource string still in use.
         * @param errorNoFingerprintScannerTitle Resource string still in use.
         * @param errorNoFingerprintScannerDescription Resource string still in use.
         * @param errorFingerprintDisabledTitle Resource string still in use.
         * @param errorFingerprintDisabledDescription Resource string still in use.
         * @param statusTouchSensor Resource is now deprecated.
         * @param statusFingerprintNotRecognized Resource is now deprecated.
         * @param statusSuccess Resource is now deprecated.
         * @param errorCodeLockout Resource string still in use.
         * @param errorCodeGeneric Resource string still in use.
         * @param accessibilityFingerprintIcon Resource is now deprecated.
         * @param accessibilitySuccessIcon Resource is now deprecated.
         * @param accessibilityFailureIcon Resource is now deprecated.
         * @param accessibilityTryAgainAnnouncement Resource is now deprecated.
         * @param accessibilitySuccessAnnouncement Resource is now deprecated.
         */
        @Deprecated
        public Strings(@StringRes int ok,
                       @StringRes int close,
                       @StringRes int errorEnrollFingerprintTitle,
                       @StringRes int errorEnrollFingerprintDescription,
                       @StringRes int errorNoFingerprintScannerTitle,
                       @StringRes int errorNoFingerprintScannerDescription,
                       @StringRes int errorFingerprintDisabledTitle,
                       @StringRes int errorFingerprintDisabledDescription,
                       @StringRes int statusTouchSensor,
                       @StringRes int statusFingerprintNotRecognized,
                       @StringRes int statusSuccess,
                       @StringRes int errorCodeLockout,
                       @StringRes int errorCodeGeneric,
                       @StringRes int accessibilityFingerprintIcon,
                       @StringRes int accessibilitySuccessIcon,
                       @StringRes int accessibilityFailureIcon,
                       @StringRes int accessibilityTryAgainAnnouncement,
                       @StringRes int accessibilitySuccessAnnouncement) {
            this(ok, close,
                 errorEnrollFingerprintTitle, errorEnrollFingerprintDescription,
                 errorNoFingerprintScannerTitle, errorNoFingerprintScannerDescription,
                 errorFingerprintDisabledTitle, errorFingerprintDisabledDescription,
                 errorCodeLockout, errorCodeGeneric);
        }

        public Strings(@StringRes int ok,
                       @StringRes int close,
                       @StringRes int errorEnrollFingerprintTitle,
                       @StringRes int errorEnrollFingerprintDescription,
                       @StringRes int errorNoFingerprintScannerTitle,
                       @StringRes int errorNoFingerprintScannerDescription,
                       @StringRes int errorFingerprintDisabledTitle,
                       @StringRes int errorFingerprintDisabledDescription,
                       @StringRes int errorCodeLockout,
                       @StringRes int errorCodeGeneric) {
            this.ok = ok;
            this.close = close;
            this.errorEnrollFingerprintTitle = errorEnrollFingerprintTitle;
            this.errorEnrollFingerprintDescription = errorEnrollFingerprintDescription;
            this.errorNoFingerprintScannerTitle = errorNoFingerprintScannerTitle;
            this.errorNoFingerprintScannerDescription = errorNoFingerprintScannerDescription;
            this.errorFingerprintDisabledTitle = errorFingerprintDisabledTitle;
            this.errorFingerprintDisabledDescription = errorFingerprintDisabledDescription;
            this.errorCodeLockout = errorCodeLockout;
            this.errorCodeGeneric = errorCodeGeneric;
        }

        /**
         * @return Default localized strings provided by the SDK.
         */
        public static @NonNull Strings getDefaultStrings() {
            return new Strings(
                    R.string.ok,
                    R.string.close,
                    R.string.fingerprint_dialog_title_new_fingerprint,
                    R.string.fingerprint_dialog_description_new_fingerprint,
                    R.string.fingerprint_dialog_title_no_scanner,
                    R.string.fingerprint_dialog_description_no_scanner,
                    R.string.fingerprint_dialog_title_invalidated,
                    R.string.fingerprint_dialog_description_invalidated,
                    R.string.fallback_error_code_lockout,
                    R.string.fallback_error_code_generic
            );
        }
    }

    /**
     * The nested {@link Drawables} class contains all resource identifiers for drawable images
     * used by the SDK.
     */
    public static class Drawables {
        /**
         * Error icon.
         */
        public final @DrawableRes int errorIcon;

        /**
         * Deprecated in version 1.6.0. Please review your resources and use new constructor
         * with reduced number of strings.
         * @param fingerprintIcon Resource is now deprecated.
         * @param errorIcon Resource ID for error icon.
         * @param successIcon Resource is now deprecated.
         */
        @Deprecated
        public Drawables(
                @DrawableRes int fingerprintIcon,
                @DrawableRes int errorIcon,
                @DrawableRes int successIcon) {
            this(errorIcon);
        }

        public Drawables(
                @DrawableRes int errorIcon) {
            this.errorIcon = errorIcon;
        }

        /**
         * @return Default drawable resources provided by the SDK.
         */
        public static @NonNull Drawables getDefaultDrawables() {
            return new Drawables(
                    R.drawable.ic_fingerprint_error);
        }
    }
}
