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

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * The {@code BiometricErrorInfo} enumeration contains an information associated with {@link PowerAuthErrorException}.
 * The enumeration is available only if the exception's error code is one of:
 * <ul>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_LOCKOUT}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_AVAILABLE}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_RECOGNIZED}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_SUPPORTED}</li>
 *     <li>{@link PowerAuthErrorCodes#BIOMETRY_NOT_ENROLLED}</li>
 * </ul>
 */
public enum BiometricErrorInfo {
    /**
     * The biometric authentication failed and the reason of failure was already displayed in the authentication dialog.
     */
    BIOMETRICS_FAILED_WITH_VISIBLE_REASON,
    /**
     * The biometric authentication failed and the reason of failure was not displayed in the authentication dialog.
     * In this case, application should properly investigate the reason of the failure and display an appropriate
     * error information.
     */
    BIOMETRICS_FAILED_WITH_NO_VISIBLE_REASON
    ;

    /**
     * If the provided exception is biometry-related, then create a new instance of {@link PowerAuthErrorException}
     * with the same error code, message and cause and use this enumeration as a source of additional information.
     * THe additional information can be later retrieved with {@link PowerAuthErrorException#getAdditionalInformation()}.
     * @param exception Exception to enhance.
     * @return new exception enhanced with additional information or the original exception if it's not biometry-related.
     */
    @NonNull
    public PowerAuthErrorException addToException(@NonNull PowerAuthErrorException exception) {
        final int errorCode = exception.getPowerAuthErrorCode();
        if (errorCode == PowerAuthErrorCodes.BIOMETRY_LOCKOUT ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED ||
                errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED) {
            return new PowerAuthErrorException(errorCode, exception.getMessage(), exception.getCause(), this);
        }
        return exception;
    }
}
