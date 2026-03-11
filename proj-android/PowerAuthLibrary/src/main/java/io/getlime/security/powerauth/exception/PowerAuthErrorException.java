/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.exception;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.core.CoreErrorCode;
import io.getlime.security.powerauth.core.CoreException;

/**
 * Will be thrown, or will be returned to listener, in case that requested operation fails
 * on an error.
 */
public class PowerAuthErrorException extends Exception {

    /**
     * Integer constant from {@link PowerAuthErrorCodes} class.
     */
    @PowerAuthErrorCodes
    private final int powerAuthErrorCode;
    /**
     * Additional information associated with the failure reason. The m
     */
    private final Object additionalInformation;

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode) {
        this.powerAuthErrorCode = powerAuthErrorCode;
        this.additionalInformation = null;
    }

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     * @param message String with detailed error description.
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode, String message) {
        super(message);
        this.powerAuthErrorCode = powerAuthErrorCode;
        this.additionalInformation = null;
    }

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     * @param message String with detailed error description.
     * @param cause Original cause of failure.
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode, String message, Throwable cause) {
        super(message, cause);
        this.powerAuthErrorCode = powerAuthErrorCode;
        this.additionalInformation = null;
    }

    /**
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}
     * @param message String with detailed error description.
     * @param cause Original cause of failure.
     * @param additionalInformation Additional information.
     */
    public PowerAuthErrorException(@PowerAuthErrorCodes int powerAuthErrorCode, String message, Throwable cause, Object additionalInformation) {
        super(message, cause);
        this.powerAuthErrorCode = powerAuthErrorCode;
        this.additionalInformation = additionalInformation;
    }

    /**
     * @return Integer constant from {@link PowerAuthErrorCodes}, describing the reason of failure.
     */
    @PowerAuthErrorCodes
    public int getPowerAuthErrorCode() {
        return powerAuthErrorCode;
    }

    /**
     * Get additional information that may help with the error processing. If the error is biometry-related, then
     * you can obtain {@link io.getlime.security.powerauth.biometry.BiometricErrorInfo} enumeration in this property.
     * @return Additional information that help with error processing.
     */
    @Nullable
    public Object getAdditionalInformation() {
        return additionalInformation;
    }

    /**
     * Wrap {@link Throwable} cause of failure into {@link PowerAuthErrorException} with provided
     * error code and message. In case that original exception is already {@link PowerAuthErrorException},
     * then return that object.
     *
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}.
     * @param message String with detailed error description.
     * @param exception Original cause of failure.
     *
     * @return Original exception if it's already instance of {@link PowerAuthErrorException} or
     *         new instance of {@link PowerAuthErrorException}.
     */
    public static @NonNull PowerAuthErrorException wrapException(@PowerAuthErrorCodes int powerAuthErrorCode, String message, Throwable exception) {
        if (exception instanceof PowerAuthErrorException) {
            return (PowerAuthErrorException)exception;
        }
        if (exception instanceof CoreException) {
            return wrapCoreException((CoreException) exception, powerAuthErrorCode);
        }
        return new PowerAuthErrorException(powerAuthErrorCode, message, exception);
    }

    /**
     * Wrap {@link Throwable} cause of failure into {@link PowerAuthErrorException} with provided
     * error code. In case that original exception is already {@link PowerAuthErrorException},
     * then return that object.
     *
     * @param powerAuthErrorCode Integer constant from {@link PowerAuthErrorCodes}.
     * @param exception Original cause of failure.
     *
     * @return Original exception if it's already instance of {@link PowerAuthErrorException} or
     *         new instance of {@link PowerAuthErrorException}.
     */
    public static @NonNull PowerAuthErrorException wrapException(@PowerAuthErrorCodes int powerAuthErrorCode, Throwable exception) {
        return wrapException(powerAuthErrorCode, exception != null ? exception.getMessage() : null, exception);
    }

    public static PowerAuthErrorException wrapException(@NonNull Throwable throwable) {
        if (throwable instanceof PowerAuthErrorException) {
            return (PowerAuthErrorException) throwable;
        }
        if (throwable instanceof CoreException) {
            return wrapCoreException((CoreException) throwable, PowerAuthErrorCodes.OTHER);
        }
        return new PowerAuthErrorException(PowerAuthErrorCodes.OTHER, throwable.getMessage(), throwable);
    }

    /**
     * Wrap {@link CoreException} cause of failure into {@link PowerAuthErrorException}. If the core
     * error code is too generic, then, then the suggested error code is used in the final exception.
     *
     * @param exception Exception to wrap.
     * @param suggestedErrorCode Error code applied in case the core error code is generic.
     * @return New instance of {@link PowerAuthErrorException}.
     */
    public static PowerAuthErrorException wrapCoreException(@NonNull CoreException exception, @PowerAuthErrorCodes int suggestedErrorCode) {
        final @PowerAuthErrorCodes int errorCode;
        switch (exception.getErrorCode()) {
            case CoreErrorCode.MISSING_ACTIVATION:
                errorCode = PowerAuthErrorCodes.MISSING_ACTIVATION;
                break;
            case CoreErrorCode.WRONG_ACTIVATION_STATE:
                errorCode = PowerAuthErrorCodes.INVALID_ACTIVATION_STATE;
                break;
            case CoreErrorCode.WRONG_PARAMETER:
                errorCode = PowerAuthErrorCodes.WRONG_PARAMETER;
                break;
            case CoreErrorCode.BIOMETRY_NOT_ALLOWED:
                errorCode = PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE;
                break;
            case CoreErrorCode.WRONG_SIGNATURE:
                errorCode = PowerAuthErrorCodes.WRONG_SIGNATURE;
                break;
            case CoreErrorCode.CANCELED:
                errorCode = PowerAuthErrorCodes.OPERATION_CANCELED;
                break;
            case CoreErrorCode.TIME_NOT_SYNCHRONIZED:
                errorCode = PowerAuthErrorCodes.TIME_SYNCHRONIZATION;
                break;
            case CoreErrorCode.PENDING_PROTOCOL_UPGRADE:
                errorCode = PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE;
                break;
            case CoreErrorCode.INVALID_ACTIVATION_DATA:
                errorCode = PowerAuthErrorCodes.INVALID_ACTIVATION_DATA;
                break;
            case CoreErrorCode.UPGRADE_SDK:
                errorCode = PowerAuthErrorCodes.UPGRADE_SDK;
                break;
            default:
                errorCode = suggestedErrorCode;
                break;
        }
        return new PowerAuthErrorException(errorCode, exception.getMessage(), exception);
    }
}
