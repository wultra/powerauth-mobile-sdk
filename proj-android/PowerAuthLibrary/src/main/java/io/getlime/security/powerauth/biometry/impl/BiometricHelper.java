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

import androidx.annotation.NonNull;
import androidx.annotation.StringRes;
import android.util.Pair;

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
                return new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED, "Biometric data is not enrolled on the device.");
            case BiometricStatus.NOT_SUPPORTED:
                return new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED, "Biometry is not supported on the device.");
            case BiometricStatus.NOT_AVAILABLE:
                return new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Biometry is not available. Try again later.");
            case BiometricStatus.OK:
                throw new IllegalArgumentException("Cannot get exception for success status.");
            default:
                throw new IllegalArgumentException("Unknown status.");
        }
    }

    /**
     * Translate {@link BiometricStatus} into a pair of string resources, representing title and description for error dialog.
     *
     * @param status Status to be translated to error dialog resources.
     * @param strings {@link BiometricDialogResources.Strings} object with resource identifiers.
     * @return Pair of string resource identifiers, with appropriate title and description.
     */
    public static @NonNull Pair<Integer, Integer> getErrorDialogStringsForBiometricStatus(@BiometricStatus int status, @NonNull BiometricDialogResources.Strings strings) {
        final @StringRes int errorTitle;
        final @StringRes int errorDescription;
        if (status == BiometricStatus.NOT_ENROLLED) {
            // User must enroll at least one fingerprint
            errorTitle       = strings.errorEnrollFingerprintTitle;
            errorDescription = strings.errorEnrollFingerprintDescription;
        } else if (status == BiometricStatus.NOT_SUPPORTED) {
            // Fingerprint scanner is not supported on the authenticator
            errorTitle       = strings.errorNoFingerprintScannerTitle;
            errorDescription = strings.errorNoFingerprintScannerDescription;
        } else if (status == BiometricStatus.NOT_AVAILABLE) {
            // Fingerprint scanner is disabled in the system, or permission was not granted.
            errorTitle       = strings.errorFingerprintDisabledTitle;
            errorDescription = strings.errorFingerprintDisabledDescription;
        } else {
            // Fallback...
            errorTitle       = strings.errorFingerprintDisabledTitle;
            errorDescription = strings.errorFingerprintDisabledDescription;
        }
        return Pair.create(errorTitle, errorDescription);
    }

    /**
     * Translate {@link PowerAuthErrorCodes} into the string resource identifier with the reason of biometric authentication failure.
     * @param errorCode Error code to be translated.
     * @param strings {@link BiometricDialogResources.Strings} object with resource identifiers.
     * @return String resource identifier.
     */
    public static @StringRes int getErrorDialogStringForBiometricErrorCode(@PowerAuthErrorCodes int errorCode, @NonNull BiometricDialogResources.Strings strings) {
        switch (errorCode) {
            case PowerAuthErrorCodes.BIOMETRY_LOCKOUT:
                return strings.errorCodeLockout;
            case PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED:
                return strings.errorEnrollFingerprintDescription;
            case PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED:
                return strings.errorNoFingerprintScannerDescription;
            case PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE:
                return strings.errorFingerprintDisabledDescription;
            case PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED:
                // NOT-RECOGNIZED may be reported only during biometric setup.
                return strings.errorCodeLockout;
            default:
                return strings.errorCodeGeneric;
        }
    }
}
