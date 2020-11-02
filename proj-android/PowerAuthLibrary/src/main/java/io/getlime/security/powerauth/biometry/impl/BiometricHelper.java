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

package io.getlime.security.powerauth.biometry.impl;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.StringRes;
import android.util.Pair;

import io.getlime.security.powerauth.R;
import io.getlime.security.powerauth.biometry.BiometricDialogResources;
import io.getlime.security.powerauth.biometry.BiometricStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code BiometricHelper} class provides helper methods for PowerAuth Mobile SDK. The class
 * is supposed to be used only by the SDK itself.
 */
public class BiometricHelper {
    /**
     * Translate {@link BiometricStatus} into appropriate {@link PowerAuthErrorException}.
     *
     * @param status Status to be translated to the exception.
     * @return Exception created for the error status. If status is {@link BiometricStatus#OK},
     *         then {@code IllegalArgumentException} is produced.
     */
    public static @NonNull PowerAuthErrorException getExceptionForBiometricStatus(@BiometricStatus int status) {
        switch (status) {
            case BiometricStatus.NOT_ENROLLED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Biometric data is not enrolled on the device.");
            case BiometricStatus.NOT_SUPPORTED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported, "Biometry is not supported on the device.");
            case BiometricStatus.NOT_AVAILABLE:
                return new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable, "Biometry is not available. Try again later.");
            case BiometricStatus.OK:
                throw new IllegalArgumentException("Cannot get exception for success status.");
            default:
                throw new IllegalArgumentException("Unknown status.");
        }
    }

    /**
     * Translate {@link BiometricStatus} into pair of string resources, representing title and description for error dialog.
     *
     * @param status Status to be translated to error dialog resources.
     * @param resources {@link BiometricDialogResources} object with resource identifiers.
     * @return Pair of string resource identifiers, with appropriate title and description.
     */
    public static @NonNull Pair<Integer, Integer> getErrorDialogStringsForBiometricStatus(@BiometricStatus int status, @NonNull BiometricDialogResources resources) {
        final @StringRes int errorTitle;
        final @StringRes int errorDescription;
        if (status == BiometricStatus.NOT_ENROLLED) {
            // User must enroll at least one fingerprint
            errorTitle       = resources.strings.errorEnrollFingerprintTitle;
            errorDescription = resources.strings.errorEnrollFingerprintDescription;
        } else if (status == BiometricStatus.NOT_SUPPORTED) {
            // Fingerprint scanner is not supported on the authenticator
            errorTitle       = resources.strings.errorNoFingerprintScannerTitle;
            errorDescription = resources.strings.errorNoFingerprintScannerDescription;
        } else if (status == BiometricStatus.NOT_AVAILABLE) {
            // Fingerprint scanner is disabled in the system, or permission was not granted.
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        } else {
            // Fallback...
            errorTitle       = resources.strings.errorFingerprintDisabledTitle;
            errorDescription = resources.strings.errorFingerprintDisabledDescription;
        }
        return Pair.create(errorTitle, errorDescription);
    }

    /**
     * Determine if the current device should explicitly fallback to {@code FingerprintManager} based
     * authentication. This may happen on devices that incorrectly provide a weak biometric authenticator
     * that doesn't support crypto-based authentication. The function checks the following conditions:
     * <ul>
     *     <li>Device has API level 28 (Android "P"). Other Android versions doesn't require this workaround.</li>
     *     <li>Device's manufacturer is on the list of problematic vendors (see {@code R.array.crypto_fingerprint_fallback_vendors}).</li>
     *     <li>Model is on the list of problematic devices (see {@code R.array.crypto_fingerprint_fallback_prefixes}).</li>
     * </ul>
     * The {@code devices.xml} resource file contains both lists.
     *
     * @param context Android context object.
     * @return {@code true} in case that fallback to {@code FingerprintManager} is required.
     */
    public static boolean shouldFallbackToFingerprintManager(@NonNull Context context) {
        if (Build.VERSION.SDK_INT != Build.VERSION_CODES.P) {
            return false;
        }
        if (!isVendorInFallbackList(context)) {
            return false;
        }
        return isModelInPrefixList(context.getResources().getStringArray(R.array.crypto_fingerprint_fallback_prefixes));
    }

    /**
     * Determine if the current device should hide a fingerprint dialog immediately. This is intended
     * to improve the experience on devices for which this dialog is needed as a workaround but which
     * display a custom UI, such as an overlay, when {@code FingerprintManager} is invoked. The function
     * checks the following conditions:
     * <ul>
     *     <li>Device has API level 28 (Android "P"). Other Android versions doesn't require this workaround.</li>
     *     <li>Device's manufacturer is on the list of problematic vendors (see {@code R.array.crypto_fingerprint_fallback_vendors}).</li>
     *     <li>Model is on the list of devices that should not display fingerprint dialog (see {@code R.array.hide_fingerprint_instantly_prefixes}).</li>
     * </ul>
     * The {@code devices.xml} resource file contains both lists.
     *
     * @param context Android context object.
     * @return {@code true} in case that the fingerprint dialog should be dismissed immediately.
     */
    public static boolean shouldHideFingerprintDialog(@NonNull Context context) {
        if (Build.VERSION.SDK_INT != Build.VERSION_CODES.P) {
            return false;
        }
        if (!isVendorInFallbackList(context)) {
            return false;
        }
        return isModelInPrefixList(context.getResources().getStringArray(R.array.hide_fingerprint_instantly_prefixes));
    }

    /**
     * Determine whether device manufacturer is in the list of problematic vendors and potentially
     * require some workaround for the biometric authentication. The function simply looks whether
     * {@code Build.MANUFACTURER} is mentioned in the {@code R.array.crypto_fingerprint_fallback_vendors}
     * list.
     *
     * @param context Android context object.
     * @return {@code true} in case that vendor of the current device is problematic and needs.
     */
    private static boolean isVendorInFallbackList(@NonNull Context context) {
        final String[] vendorNames = context.getResources().getStringArray(R.array.crypto_fingerprint_fallback_vendors);
        final String vendor = Build.MANUFACTURER;
        if (vendor == null) {
            return false;
        }
        for (String vendorName : vendorNames) {
            if (vendor.equalsIgnoreCase(vendorName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether {@code Build.MODEL} matches one in the given string array.
     * <p>
     * Note that the string array should contain the model prefixes rather than exact model identifiers.
     * For example, if device's model is "Android SDK built for x86", then the prefix list should
     * contain only "Android SDK", to match more simulator variants.
     *
     * @param modelPrefixes String array with model prefixes.
     * @return {@code true} if the model matches one in the given string array, or {@code false} otherwise.
     */
    private static boolean isModelInPrefixList(String[] modelPrefixes) {
        final String model = Build.MODEL;
        if (model == null) {
            return false;
        }
        for (String modelPrefix : modelPrefixes) {
            if (model.startsWith(modelPrefix)) {
                return true;
            }
        }
        return false;
    }
}
