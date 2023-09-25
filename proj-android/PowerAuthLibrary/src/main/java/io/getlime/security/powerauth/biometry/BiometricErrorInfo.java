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

package io.getlime.security.powerauth.biometry;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.biometry.impl.BiometricHelper;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code BiometricErrorInfo} class contains an information associated with {@link PowerAuthErrorException}.
 * The class is available only if the exception's error code is one of:
 * <ul>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_LOCKOUT}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_AVAILABLE}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_RECOGNIZED}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_SUPPORTED}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_ENROLLED}</li>
 * </ul>
 * The information is typically available in {@link PowerAuthErrorException#getAdditionalInformation()}.
 */
public class BiometricErrorInfo {
    /**
     * Error code that will be used to determine the localized message.
     */
    private final @PowerAuthErrorCodes int errorCode;
    /**
     * Information whether application should present error to the user.
     */
    private final boolean errorPresentationIsRequired;
    /**
     * Optional error message.
     */
    private final @Nullable String errorMessage;

    /**
     * @return Contains {@code true} if the reason of biometric authentication failure was not properly communicated
     * to the user in the authentication dialog.
     */
    public boolean isErrorPresentationRequired() {
        return errorPresentationIsRequired;
    }

    /**
     * @return Contains optional error message retrieved from {@link androidx.biometric.BiometricPrompt.AuthenticationCallback}.
     * The error message may not be available in case when the operation failed before the biometric prompt was created.
     */
    @Nullable
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Return localized error message. If {@link #getErrorMessage()} contains valid string, then returns this string, otherwise
     * the strings from provided dialog resources are used.
     * @param context Android context.
     * @param dialogResources {@link BiometricDialogResources} class with strings. If {@code null} is provided, then the
     *                        string resources used by {@link BiometricAuthentication} is used.
     * @return Localized error message.
     */
    @NonNull
    public String getLocalizedErrorMessage(@NonNull Context context, @Nullable BiometricDialogResources.Strings dialogResources) {
        if (errorMessage != null) {
            return errorMessage;
        }
        if (dialogResources == null) {
            dialogResources = BiometricAuthentication.getBiometricDialogResources().strings;
        }
        return context.getString(BiometricHelper.getErrorDialogStringForBiometricErrorCode(errorCode, dialogResources));
    }

    // Object construction

    /**
     * Construct biometric error info object with error code, hint to application and optional localized message.
     * @param errorCode Biometric error code.
     * @param errorPresentationIsRequired Hint to application, whether error should be presented to the user.
     * @param errorMessage Optional localized error message from {@code BiometricPrompt}.
     */
    public BiometricErrorInfo(
            @PowerAuthErrorCodes int errorCode,
            boolean errorPresentationIsRequired,
            @Nullable CharSequence errorMessage) {
        this.errorCode = errorCode;
        this.errorPresentationIsRequired = errorPresentationIsRequired;
        this.errorMessage = errorMessage != null ? errorMessage.toString() : null;
    }

    /**
     * Construct biometric error info object with error code and hint to application.
     * @param errorCode Biometric error code.
     * @param errorPresentationIsRequired Hint to application, whether error should be presented to the user.
     */
    public BiometricErrorInfo(
            @PowerAuthErrorCodes int errorCode,
            boolean errorPresentationIsRequired) {
        this.errorCode = errorCode;
        this.errorPresentationIsRequired = errorPresentationIsRequired;
        this.errorMessage = null;
    }

    /**
     * If the provided exception is biometry-related, then create a new instance of {@link PowerAuthErrorException}
     * with the same error code, message and cause and use {@code BiometricErrorInfo} class as a source of additional information.
     * The additional information can be later retrieved with {@link PowerAuthErrorException#getAdditionalInformation()}.
     * @param exception Exception to enhance.
     * @param errorPresentationIsRequired {@code true} if reason of failure was not communicated to the user in the authentication dialog.
     * @param errorMessage Optional message, available only if the biometric authentication was performed and then failed.
     * @return new exception enhanced with additional information or the original exception if it's not biometry-related.
     */
    @NonNull
    public static PowerAuthErrorException addToException(@NonNull PowerAuthErrorException exception, boolean errorPresentationIsRequired, @Nullable CharSequence errorMessage) {
        final int errorCode = exception.getPowerAuthErrorCode();
        if (errorCode == PowerAuthErrorCodes.BIOMETRY_LOCKOUT ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED) {
            final BiometricErrorInfo info = new BiometricErrorInfo(errorCode, errorPresentationIsRequired, errorMessage);
            return new PowerAuthErrorException(errorCode, exception.getMessage(), exception.getCause(), info);
        }
        return exception;
    }

    /**
     * If the provided exception is biometry-related, then create a new instance of {@link PowerAuthErrorException}
     * with the same error code, message and cause and use {@code BiometricErrorInfo} class as a source of additional information.
     * The additional information can be later retrieved with {@link PowerAuthErrorException#getAdditionalInformation()}.
     * @param exception Exception to enhance.
     * @param errorPresentationIsRequired {@code true} if reason of failure was not communicated to the user in the authentication dialog.
     * @return new exception enhanced with additional information or the original exception if it's not biometry-related.
     */
    public static PowerAuthErrorException addToException(@NonNull PowerAuthErrorException exception, boolean errorPresentationIsRequired) {
        return addToException(exception, errorPresentationIsRequired, null);
    }
}
