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

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;

import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeActivationPending;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeBiometryLockout;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeBiometryNotRecognized;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeBiometryCancel;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeBiometryNotAvailable;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeBiometryNotSupported;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeEncryptionError;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeInsufficientKeychainProtection;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationCode;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeInvalidToken;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeMissingActivation;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeNetworkError;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeOperationCancelled;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodePendingProtocolUpgrade;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeProtocolUpgrade;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeSignatureError;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2ErrorCodeWrongParameter;
import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.PA2Succeed;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * The {@code PowerAuthErrorCodes} interface defines various error constants reported from PowerAuth SDK.
 *
 */
@Retention(SOURCE)
@IntDef({PA2Succeed, PA2ErrorCodeNetworkError, PA2ErrorCodeSignatureError, PA2ErrorCodeInvalidActivationState,
        PA2ErrorCodeInvalidActivationData, PA2ErrorCodeMissingActivation, PA2ErrorCodeActivationPending,
        PA2ErrorCodeBiometryCancel, PA2ErrorCodeOperationCancelled, PA2ErrorCodeInvalidActivationCode,
        PA2ErrorCodeInvalidToken, PA2ErrorCodeEncryptionError, PA2ErrorCodeWrongParameter,
        PA2ErrorCodeProtocolUpgrade, PA2ErrorCodePendingProtocolUpgrade,
        PA2ErrorCodeBiometryNotSupported, PA2ErrorCodeBiometryNotAvailable, PA2ErrorCodeBiometryNotRecognized,
        PA2ErrorCodeInsufficientKeychainProtection, PA2ErrorCodeBiometryLockout})
public @interface PowerAuthErrorCodes {

    /**
     * Code returned, or reported, when operation succeeds.
     */
    int PA2Succeed = 0;

    /**
     * Error code for error with network connectivity or download.
     */
    int PA2ErrorCodeNetworkError = 1;

    /**
     * Error code for error in signature calculation.
     */
    int PA2ErrorCodeSignatureError = 2;

    /**
     * Error code for error that occurs when activation state is invalid.
     */
    int PA2ErrorCodeInvalidActivationState = 3;

    /**
     * Error code for error that occurs when activation data is invalid.
     */
    int PA2ErrorCodeInvalidActivationData = 4;

    /**
     * Error code for error that occurs when activation is required but missing.
     */
    int PA2ErrorCodeMissingActivation = 5;

    /**
     * Error code for error that occurs when pending activation is present and work with completed
     * activation is required.
     */
    int PA2ErrorCodeActivationPending = 7;

    /**
     * Error code for situation when biometric prompt is canceled by the user.
     */
    int PA2ErrorCodeBiometryCancel = 10;

    /**
     * Error code for canceled operation. This kind of error may occur in situations, when SDK
     * needs to cancel an asynchronous operation, but the cancel is not initiated by the application
     * itself. For example, if you reset the state of {@code PowerAuthSDK} during the pending
     * fetch for activation status, then the application gets an exception, with this error code.
     */
    int PA2ErrorCodeOperationCancelled = 11;

    /**
     * Error code for error that occurs when invalid activation code is provided.
     */
    int PA2ErrorCodeInvalidActivationCode = 12;

    /**
     * Error code for accessing an unknown token.
     */
    int PA2ErrorCodeInvalidToken = 13;

    /**
     * Error code for errors related to end-to-end encryption.
     */
    int PA2ErrorCodeEncryptionError = 14;

    /**
     * Error code for a general API misuse.
     */
    int PA2ErrorCodeWrongParameter = 15;

    /**
     * Error code for protocol upgrade failure.
     * The recommended action is to retry the status fetch operation, or locally remove the activation.
     */
    int PA2ErrorCodeProtocolUpgrade = 16;

    /**
     * The requested function is not available during the protocol upgrade. You can retry the operation,
     * after the upgrade is finished.
     */
    int PA2ErrorCodePendingProtocolUpgrade = 17;

    /**
     * The biometric authentication cannot be processed due to lack of required hardware or due to
     * a missing support from the operating system.
     */
    int PA2ErrorCodeBiometryNotSupported = 18;

    /**
     * The biometric authentication is temporarily unavailable.
     * <p>
     * There might be multiple reasons why this error is reported, such as missing biometric
     * enrollment, internal biometric sensor failure, or other unspecified error.
     */
    int PA2ErrorCodeBiometryNotAvailable = 19;

    /**
     * The biometric authentication did not recognize the biometric image (fingerprint, face, etc...)
     * <p>
     * Be aware that this error code is reported only during the biometric factor setup, but is never
     * reported when PowerAuth signature with biometric factor is requested. This is because the
     * PowerAuth SDK swallows this error code internally and generates a random biometric signature
     * and pretends that everything is OK. The result is that a counter of failed attempts on the server
     * is increased, so the attacker has a limited ability to fool the biometric sensor.
     */
    int PA2ErrorCodeBiometryNotRecognized = 20;

    /**
     * The keychain protection is not sufficient. The exception is thrown in case that device doesn't
     * support the minimum required level of the keychain protection.
     */
    int PA2ErrorCodeInsufficientKeychainProtection = 21;

    /**
     * The biometric authentication is locked out due to too many failed attempts.
     * <p>
     * The error is reported for the temporary and also for the permanent lockout. The temporary
     * lockout typically occurs after 5 failed attempts, and lasts for 30 seconds. In case of permanent
     * lockout the biometric authentication is disabled until the user unlocks the device with strong
     * authentication (PIN, password, pattern).
     */
    int PA2ErrorCodeBiometryLockout = 22;
}
