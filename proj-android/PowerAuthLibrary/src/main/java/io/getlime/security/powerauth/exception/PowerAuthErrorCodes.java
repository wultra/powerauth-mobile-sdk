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

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;

import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PENDING_ACTIVATION;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.BIOMETRY_LOCKOUT;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.BIOMETRY_CANCEL;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.ENCRYPTION_ERROR;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.INSUFFICIENT_KEYCHAIN_PROTECTION;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.INVALID_ACTIVATION_CODE;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.INVALID_ACTIVATION_DATA;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.INVALID_ACTIVATION_STATE;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.INVALID_TOKEN;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.MISSING_ACTIVATION;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.NETWORK_ERROR;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.OPERATION_CANCELED;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PROTOCOL_UPGRADE;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.SIGNATURE_ERROR;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.WRONG_PARAMETER;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.SUCCEED;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * The {@code PowerAuthErrorCodes} interface defines various error constants reported from PowerAuth SDK.
 *
 */
@Retention(SOURCE)
@IntDef({SUCCEED, NETWORK_ERROR, SIGNATURE_ERROR, INVALID_ACTIVATION_STATE,
        INVALID_ACTIVATION_DATA, MISSING_ACTIVATION, PENDING_ACTIVATION,
        BIOMETRY_CANCEL, OPERATION_CANCELED, INVALID_ACTIVATION_CODE,
        INVALID_TOKEN, ENCRYPTION_ERROR, WRONG_PARAMETER,
        PROTOCOL_UPGRADE, PENDING_PROTOCOL_UPGRADE,
        BIOMETRY_NOT_SUPPORTED, BIOMETRY_NOT_AVAILABLE, BIOMETRY_NOT_RECOGNIZED,
        INSUFFICIENT_KEYCHAIN_PROTECTION, BIOMETRY_LOCKOUT})
public @interface PowerAuthErrorCodes {

    /**
     * Code returned, or reported, when operation succeeds.
     */
    int SUCCEED = 0;

    /**
     * Error code for error with network connectivity or download.
     */
    int NETWORK_ERROR = 1;

    /**
     * Error code for error in signature calculation.
     */
    int SIGNATURE_ERROR = 2;

    /**
     * Error code for error that occurs when activation state is invalid.
     */
    int INVALID_ACTIVATION_STATE = 3;

    /**
     * Error code for error that occurs when activation data is invalid.
     */
    int INVALID_ACTIVATION_DATA = 4;

    /**
     * Error code for error that occurs when activation is required but missing.
     */
    int MISSING_ACTIVATION = 5;

    /**
     * Error code for error that occurs when pending activation is present and work with completed
     * activation is required.
     */
    int PENDING_ACTIVATION = 7;

    /**
     * Error code for situation when biometric prompt is canceled by the user.
     */
    int BIOMETRY_CANCEL = 10;

    /**
     * Error code for canceled operation. This kind of error may occur in situations, when SDK
     * needs to cancel an asynchronous operation, but the cancel is not initiated by the application
     * itself. For example, if you reset the state of {@code PowerAuthSDK} during the pending
     * fetch for activation status, then the application gets an exception, with this error code.
     */
    int OPERATION_CANCELED = 11;

    /**
     * Error code for error that occurs when invalid activation code is provided.
     */
    int INVALID_ACTIVATION_CODE = 12;

    /**
     * Error code for accessing an unknown token.
     */
    int INVALID_TOKEN = 13;

    /**
     * Error code for errors related to end-to-end encryption.
     */
    int ENCRYPTION_ERROR = 14;

    /**
     * Error code for a general API misuse.
     */
    int WRONG_PARAMETER = 15;

    /**
     * Error code for protocol upgrade failure.
     * The recommended action is to retry the status fetch operation, or locally remove the activation.
     */
    int PROTOCOL_UPGRADE = 16;

    /**
     * The requested function is not available during the protocol upgrade. You can retry the operation,
     * after the upgrade is finished.
     */
    int PENDING_PROTOCOL_UPGRADE = 17;

    /**
     * The biometric authentication cannot be processed due to lack of required hardware or due to
     * a missing support from the operating system.
     */
    int BIOMETRY_NOT_SUPPORTED = 18;

    /**
     * The biometric authentication is temporarily unavailable.
     * <p>
     * There might be multiple reasons why this error is reported, such as missing biometric
     * enrollment, internal biometric sensor failure, or other unspecified error.
     */
    int BIOMETRY_NOT_AVAILABLE = 19;

    /**
     * The biometric authentication did not recognize the biometric image (fingerprint, face, etc...)
     * <p>
     * Be aware that this error code is reported only during the biometric factor setup, but is never
     * reported when PowerAuth signature with biometric factor is requested. This is because the
     * PowerAuth SDK swallows this error code internally and generates a random biometric signature
     * and pretends that everything is OK. The result is that a counter of failed attempts on the server
     * is increased, so the attacker has a limited ability to fool the biometric sensor.
     */
    int BIOMETRY_NOT_RECOGNIZED = 20;

    /**
     * The keychain protection is not sufficient. The exception is thrown in case that device doesn't
     * support the minimum required level of the keychain protection.
     */
    int INSUFFICIENT_KEYCHAIN_PROTECTION = 21;

    /**
     * The biometric authentication is locked out due to too many failed attempts.
     * <p>
     * The error is reported for the temporary and also for the permanent lockout. The temporary
     * lockout typically occurs after 5 failed attempts, and lasts for 30 seconds. In case of permanent
     * lockout the biometric authentication is disabled until the user unlocks the device with strong
     * authentication (PIN, password, pattern).
     */
    int BIOMETRY_LOCKOUT = 22;

    // Old and deprecated constants

    /**
     * {@code PA2Succeed} is now deprecated, please use {@link #SUCCEED} constant as a replacement.
     */
    @Deprecated int PA2Succeed = SUCCEED;
    /**
     * {@code PA2ErrorCodeNetworkError} is now deprecated, please use {@link #NETWORK_ERROR} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeNetworkError = NETWORK_ERROR;
    /**
     * {@code PA2ErrorCodeSignatureError} is now deprecated, please use {@link #SIGNATURE_ERROR} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeSignatureError = SIGNATURE_ERROR;
    /**
     * {@code PA2ErrorCodeInvalidActivationState} is now deprecated, please use {@link #INVALID_ACTIVATION_STATE} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeInvalidActivationState = INVALID_ACTIVATION_STATE;
    /**
     * {@code PA2ErrorCodeInvalidActivationData} is now deprecated, please use {@link #INVALID_ACTIVATION_DATA} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeInvalidActivationData = INVALID_ACTIVATION_DATA;
    /**
     * {@code PA2ErrorCodeMissingActivation} is now deprecated, please use {@link #MISSING_ACTIVATION} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeMissingActivation = MISSING_ACTIVATION;
    /**
     * {@code PA2ErrorCodeActivationPending} is now deprecated, please use {@link #PENDING_ACTIVATION} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeActivationPending = PENDING_ACTIVATION;
    /**
     * {@code PA2ErrorCodeBiometryCancel} is now deprecated, please use {@link #BIOMETRY_CANCEL} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeBiometryCancel = BIOMETRY_CANCEL;
    /**
     * {@code PA2ErrorCodeOperationCancelled} is now deprecated, please use {@link #OPERATION_CANCELED} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeOperationCancelled = OPERATION_CANCELED;
    /**
     * {@code PA2ErrorCodeInvalidActivationCode} is now deprecated, please use {@link #INVALID_ACTIVATION_CODE} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeInvalidActivationCode = INVALID_ACTIVATION_CODE;
    /**
     * {@code PA2ErrorCodeInvalidToken} is now deprecated, please use {@link #INVALID_TOKEN} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeInvalidToken = INVALID_TOKEN;
    /**
     * {@code PA2ErrorCodeEncryptionError} is now deprecated, please use {@link #ENCRYPTION_ERROR} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeEncryptionError = ENCRYPTION_ERROR;
    /**
     * {@code PA2ErrorCodeWrongParameter} is now deprecated, please use {@link #WRONG_PARAMETER} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeWrongParameter = WRONG_PARAMETER;
    /**
     * {@code PA2ErrorCodeProtocolUpgrade} is now deprecated, please use {@link #PROTOCOL_UPGRADE} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeProtocolUpgrade = PROTOCOL_UPGRADE;
    /**
     * {@code PA2ErrorCodePendingProtocolUpgrade} is now deprecated, please use {@link #PENDING_PROTOCOL_UPGRADE} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodePendingProtocolUpgrade = PENDING_PROTOCOL_UPGRADE;
    /**
     * {@code PA2ErrorCodeBiometryNotSupported} is now deprecated, please use {@link #BIOMETRY_NOT_SUPPORTED} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeBiometryNotSupported = BIOMETRY_NOT_SUPPORTED;
    /**
     * {@code PA2ErrorCodeBiometryNotAvailable} is now deprecated, please use {@link #BIOMETRY_NOT_AVAILABLE} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeBiometryNotAvailable = BIOMETRY_NOT_AVAILABLE;
    /**
     * {@code PA2ErrorCodeBiometryNotRecognized} is now deprecated, please use {@link #BIOMETRY_NOT_RECOGNIZED} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeBiometryNotRecognized = BIOMETRY_NOT_RECOGNIZED;
    /**
     * {@code PA2ErrorCodeInsufficientKeychainProtection} is now deprecated, please use {@link #INSUFFICIENT_KEYCHAIN_PROTECTION} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeInsufficientKeychainProtection = INSUFFICIENT_KEYCHAIN_PROTECTION;
    /**
     * {@code PA2ErrorCodeBiometryLockout} is now deprecated, please use {@link #BIOMETRY_LOCKOUT} constant as a replacement.
     */
    @Deprecated int PA2ErrorCodeBiometryLockout = BIOMETRY_LOCKOUT;
}
