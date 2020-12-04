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
import androidx.annotation.IdRes;
import androidx.annotation.LayoutRes;
import androidx.annotation.NonNull;
import androidx.annotation.StringRes;

import io.getlime.security.powerauth.R;

/**
 * The {@code BiometricDialogResources} contains resource identifier of layout, strings, drawables
 * and other information, required for the display of fallback fingerprint dialog. Such dialog is
 * currently needed on the systems API level less than 28 (Android.P).
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

    /**
     * Contains object witch colors, required for the fingerprint dialog.
     */
    public final @NonNull Colors colors;

    /**
     * Contains object with dialog layout and constants identifying views inside the layout.
     */
    public final @NonNull Layout layout;


    private BiometricDialogResources(
            @NonNull Strings strings,
            @NonNull Drawables drawables,
            @NonNull Colors colors,
            @NonNull Layout layout) {
        this.layout = layout;
        this.strings = strings;
        this.colors = colors;
        this.drawables = drawables;
    }

    /**
     * A builder that collects resources required for the fallback fingerprint dialog.
     */
    public static class Builder {

        private Strings strings;
        private Drawables drawables;
        private Colors colors;
        private Layout layout;

        public Builder() {
        }

        /**
         * Creates {@link BiometricDialogResources} object.
         * @return Instance of {@link BiometricDialogResources}.
         */
        public BiometricDialogResources build() {
            return new BiometricDialogResources(
                    strings != null ? strings : Strings.getDefaultStrings(),
                    drawables != null ? drawables : Drawables.getDefaultDrawables(),
                    colors != null ? colors : Colors.getDefaultColors(),
                    layout != null ? layout : Layout.getDefaultLayout());
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

        /**
         * @param colors Object with color resources required for the future dialog.
         * @return This value will never be null.
         */
        public Builder setColors(@NonNull final Colors colors) {
            this.colors = colors;
            return this;
        }

        /**
         * @param layout Layout definition for the future dialog.
         * @return This value will never be null.
         */
        public Builder setLayout(@NonNull Layout layout) {
            this.layout = layout;
            return this;
        }
    }


    /**
     * The nested {@code Strings} class contains all strings resources used by the SDK.
     */
    public static class Strings {

        static final int RESOURCES_COUNT = 18;

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
         * Status text that informs user that he has to use the sensor to authenticate.
         */
        public final @StringRes int statusTouchSensor;
        /**
         * Status text that informs user that image has not been recognized.
         */
        public final @StringRes int statusFingerprintNotRecognized;
        /**
         * Status text that informs user that authentication did succeed.
         */
        public final @StringRes int statusSuccess;

        /**
         * String for error code that instructs user that biometric authentication has been locked out.
         */
        public final @StringRes int errorCodeLockout;
        /**
         * String for all other error codes, reported from biometric API.
         */
        public final @StringRes int errorCodeGeneric;

        /**
         * Accessibility description for fingerprint icon.
         */
        public final @StringRes int accessibilityFingerprintIcon;
        /**
         * Accessibility description for success icon.
         */
        public final @StringRes int accessibilitySuccessIcon;
        /**
         * Accessibility description for failure icon.
         */
        public final @StringRes int accessibilityFailureIcon;
        /**
         * Accessibility announcement text instructing user to try again with the biometric authentication.
         */
        public final @StringRes int accessibilityTryAgainAnnouncement;
        /**
         * Accessibility announcement text for the biometric authentication success.
         */
        public final @StringRes int accessibilitySuccessAnnouncement;

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
            this.ok = ok;
            this.close = close;
            this.errorEnrollFingerprintTitle = errorEnrollFingerprintTitle;
            this.errorEnrollFingerprintDescription = errorEnrollFingerprintDescription;
            this.errorNoFingerprintScannerTitle = errorNoFingerprintScannerTitle;
            this.errorNoFingerprintScannerDescription = errorNoFingerprintScannerDescription;
            this.errorFingerprintDisabledTitle = errorFingerprintDisabledTitle;
            this.errorFingerprintDisabledDescription = errorFingerprintDisabledDescription;
            this.statusTouchSensor = statusTouchSensor;
            this.statusFingerprintNotRecognized = statusFingerprintNotRecognized;
            this.statusSuccess = statusSuccess;
            this.errorCodeLockout = errorCodeLockout;
            this.errorCodeGeneric = errorCodeGeneric;
            this.accessibilityFingerprintIcon = accessibilityFingerprintIcon;
            this.accessibilitySuccessIcon = accessibilitySuccessIcon;
            this.accessibilityFailureIcon = accessibilityFailureIcon;
            this.accessibilityTryAgainAnnouncement = accessibilityTryAgainAnnouncement;
            this.accessibilitySuccessAnnouncement = accessibilitySuccessAnnouncement;
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
                    R.string.fingerprint_dialog_touch_sensor,
                    R.string.fingerprint_dialog_not_recognized,
                    R.string.fingerprint_dialog_success,
                    R.string.fallback_error_code_lockout,
                    R.string.fallback_error_code_generic,
                    R.string.accessibility_icon_fingerprint,
                    R.string.accessibility_icon_success,
                    R.string.accessibility_icon_failure,
                    R.string.accessibility_announcement_try_again,
                    R.string.accessibility_announcement_success
            );
        }

        /**
         * Internal method that pack string resources into array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array to store the resources.
         */
        void packTo(@NonNull int[] array, int offset) {
            array[offset]       = this.ok;
            array[offset + 1]   = this.close;
            array[offset + 2]   = this.errorEnrollFingerprintTitle;
            array[offset + 3]   = this.errorEnrollFingerprintDescription;
            array[offset + 4]   = this.errorNoFingerprintScannerTitle;
            array[offset + 5]   = this.errorNoFingerprintScannerDescription;
            array[offset + 6]   = this.errorFingerprintDisabledTitle;
            array[offset + 7]   = this.errorFingerprintDisabledDescription;
            array[offset + 8]   = this.statusTouchSensor;
            array[offset + 9]   = this.statusFingerprintNotRecognized;
            array[offset + 10]  = this.statusSuccess;
            array[offset + 11]  = this.errorCodeLockout;
            array[offset + 12]  = this.errorCodeGeneric;
            array[offset + 13]  = this.accessibilityFingerprintIcon;
            array[offset + 14]  = this.accessibilitySuccessIcon;
            array[offset + 15]  = this.accessibilityFailureIcon;
            array[offset + 16]  = this.accessibilityTryAgainAnnouncement;
            array[offset + 17]  = this.accessibilitySuccessAnnouncement;
        }

        /**
         * Internal method that unpacks resources from the provided array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array where resources are located.
         * @return Unpacked {@link Strings} object.
         */
        static @NonNull Strings unpackFrom(@NonNull int[] array, int offset) {
            return new Strings(
                    array[offset],
                    array[offset + 1],
                    array[offset + 2],
                    array[offset + 3],
                    array[offset + 4],
                    array[offset + 5],
                    array[offset + 6],
                    array[offset + 7],
                    array[offset + 8],
                    array[offset + 9],
                    array[offset + 10],
                    array[offset + 11],
                    array[offset + 12],
                    array[offset + 13],
                    array[offset + 14],
                    array[offset + 15],
                    array[offset + 16],
                    array[offset + 17]);
        }
    }

    /**
     * The nested {@link Drawables} class contains all resource identifiers for drawable images
     * used by the SDK.
     */
    public static class Drawables {

        static final int RESOURCES_COUNT = 3;

        /**
         * Fingerprint icon.
         */
        public final @DrawableRes int fingerprintIcon;

        /**
         * Error icon.
         */
        public final @DrawableRes int errorIcon;

        /**
         * Success icon.
         */
        public final @DrawableRes int successIcon;

        public Drawables(
                @DrawableRes int fingerprintIcon,
                @DrawableRes int errorIcon,
                @DrawableRes int successIcon) {
            this.fingerprintIcon = fingerprintIcon;
            this.errorIcon = errorIcon;
            this.successIcon = successIcon;
        }

        /**
         * @return Default drawable resources provided by the SDK.
         */
        public static @NonNull Drawables getDefaultDrawables() {
            return new Drawables(
                    R.drawable.ic_fingerprint_default,
                    R.drawable.ic_fingerprint_error,
                    R.drawable.ic_fingerprint_success);
        }

        /**
         * Internal method that pack drawable resources into array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array to store the resources.
         */
        void packTo(@NonNull int[] array, int offset) {
            array[offset]       = this.fingerprintIcon;
            array[offset + 1]   = this.errorIcon;
            array[offset + 2]   = this.successIcon;
        }

        /**
         * Internal method that unpacks resources from the provided array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array where resources are located.
         * @return Unpacked {@link Drawables} object.
         */
        static @NonNull Drawables unpackFrom(@NonNull int[] array, int offset) {
            return new Drawables(
                    array[offset],
                    array[offset + 1],
                    array[offset + 2]);
        }
    }

    /**
     * The nested {@code Colors} class contains colors used in the fingerprint dialog and error
     * dialogs, created by SDK.
     */
    public static class Colors {

        static final int RESOURCES_COUNT = 6;

        /**
         * Fingerprint dialog's background color.
         */
        public final @ColorRes int background;
        /**
         * Primary text color.
         */
        public final @ColorRes int primaryText;
        /**
         * Secondary text color.
         */
        public final @ColorRes int secondaryText;
        /**
         * Success text color.
         */
        public final @ColorRes int successText;
        /**
         * Failure text color.
         */
        public final @ColorRes int failureText;
        /**
         * Close or cancel button text color.
         */
        public final @ColorRes int closeButtonText;

        public Colors(
                @ColorRes int background,
                @ColorRes int primaryText,
                @ColorRes int secondaryText,
                @ColorRes int successText,
                @ColorRes int failureText,
                @ColorRes int closeButtonText) {
            this.background = background;
            this.primaryText = primaryText;
            this.secondaryText = secondaryText;
            this.successText = successText;
            this.failureText = failureText;
            this.closeButtonText = closeButtonText;
        }

        /**
         * @return Default color resources provided by the SDK.
         */
        public static @NonNull Colors getDefaultColors() {
            return new Colors(
                    R.color.color_fingerprint_dialog_background,
                    R.color.color_fingerprint_text_primary,
                    R.color.color_fingerprint_text_secondary,
                    R.color.color_fingerprint_success_text,
                    R.color.color_fingerprint_failure_text,
                    R.color.color_fingerprint_close_button);
        }

        /**
         * Internal method that pack drawable resources into array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array to store the resources.
         */
        void packTo(@NonNull int[] array, int offset) {
            array[offset]       = background;
            array[offset + 1]   = primaryText;
            array[offset + 2]   = secondaryText;
            array[offset + 3]   = successText;
            array[offset + 4]   = failureText;
            array[offset + 5]   = closeButtonText;
        }

        /**
         * Internal method that unpacks resources from the provided array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array where resources are located.
         * @return Unpacked {@link Colors} object.
         */
        static @NonNull Colors unpackFrom(@NonNull int[] array, int offset) {
            return new Colors(
                    array[offset],
                    array[offset + 1],
                    array[offset + 2],
                    array[offset + 3],
                    array[offset + 4],
                    array[offset + 5]);
        }
    }

    /**
     * The nested {@code Layout} class defines layout for fingerprint dialog. The class also contains
     * view identifiers which must be valid inside of the layout.
     */
    public static class Layout {

        static final int RESOURCES_COUNT = 4;

        /**
         * Dialog's layout.
         */
        public final @LayoutRes int dialogLayout;
        /**
         * Identifier for status icon.
         */
        public final @IdRes int statusImageView;
        /**
         * Identifier for status TextView.
         */
        public final @IdRes int statusTextView;
        /**
         * Identifier for description TextView.
         */
        public final @IdRes int descriptionTextView;

        public Layout(
                @LayoutRes int dialogLayout,
                @IdRes int statusImageView,
                @IdRes int statusTextView,
                @IdRes int descriptionTextView) {
            this.dialogLayout = dialogLayout;
            this.statusImageView = statusImageView;
            this.statusTextView = statusTextView;
            this.descriptionTextView = descriptionTextView;
        }

        /**
         * @return Default layout resources provided by the SDK.
         */
        public static @NonNull Layout getDefaultLayout() {
            return new Layout(
                    R.layout.dialog_fingerprint_login,
                    R.id.fingerprint_icon,
                    R.id.fingerprint_status,
                    R.id.fingerprint_description);
        }

        /**
         * Internal method that pack drawable resources into array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array to store the resources.
         */
        void packTo(@NonNull int[] array, int offset) {
            array[offset]       = this.dialogLayout;
            array[offset + 1]   = this.statusImageView;
            array[offset + 2]   = this.statusTextView;
            array[offset + 3]   = this.descriptionTextView;
        }

        /**
         * Internal method that unpacks resources from the provided array of integers.
         * @param array Array to hold the resources.
         * @param offset Offset in the array where resources are located.
         * @return Unpacked {@link Layout} object.
         */
        static @NonNull Layout unpackFrom(@NonNull int[] array, int offset) {
            return new Layout(
                    array[offset],
                    array[offset + 1],
                    array[offset + 2],
                    array[offset + 3]);
        }
    }

    // Offsets for resources serialization.

    private static final int PACK_STRINGS_OFFSET = 0;
    private static final int PACK_DRAWABLES_OFFSET = PACK_STRINGS_OFFSET + Strings.RESOURCES_COUNT;
    private static final int PACK_COLORS_OFFSET = PACK_DRAWABLES_OFFSET + Drawables.RESOURCES_COUNT;
    private static final int PACK_LAYOUT_OFFSET = PACK_COLORS_OFFSET + Colors.RESOURCES_COUNT;
    private static final int PACK_DATA_COUNT = PACK_LAYOUT_OFFSET + Layout.RESOURCES_COUNT;

    /**
     * Method packs {@link BiometricDialogResources} into contiguous array of integers.
     * @return Array of integers with packed resources.
     */
    public @NonNull int[] packResources() {
        final int[] array = new int[PACK_DATA_COUNT];
        strings.packTo(array, PACK_STRINGS_OFFSET);
        drawables.packTo(array, PACK_DRAWABLES_OFFSET);
        colors.packTo(array, PACK_COLORS_OFFSET);
        layout.packTo(array, PACK_LAYOUT_OFFSET);
        return array;
    }

    /**
     * Method unpacks {@link BiometricDialogResources} from provided array of integers. The method
     * throws an exception if array is null or has unexpected size.
     *
     * @param array Array with the packed resources.
     * @return Unpacked {@link BiometricDialogResources} object.
     */
    public static @NonNull BiometricDialogResources unpackResources(int[] array) {
        if (array == null) {
            throw new IllegalArgumentException("array must not be null");
        }
        if (array.length != PACK_DATA_COUNT) {
            throw new IllegalArgumentException("array has unexpected size.");
        }
        return new BiometricDialogResources(
                Strings.unpackFrom(array, PACK_STRINGS_OFFSET),
                Drawables.unpackFrom(array, PACK_DRAWABLES_OFFSET),
                Colors.unpackFrom(array, PACK_COLORS_OFFSET),
                Layout.unpackFrom(array, PACK_LAYOUT_OFFSET));
    }
}
