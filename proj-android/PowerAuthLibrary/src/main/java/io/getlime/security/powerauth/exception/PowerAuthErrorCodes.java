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

import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.*;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * The {@code PowerAuthErrorCodes} interface defines various error constants reported from PowerAuth SDK.
 */
@Retention(SOURCE)
@IntDef({SUCCEED, NETWORK_ERROR, SIGNATURE_ERROR, INVALID_ACTIVATION_STATE,
        INVALID_ACTIVATION_DATA, MISSING_ACTIVATION, PENDING_ACTIVATION,
        BIOMETRY_CANCEL, OPERATION_CANCELED, INVALID_ACTIVATION_CODE,
        INVALID_TOKEN, ENCRYPTION_ERROR, WRONG_PARAMETER,
        PROTOCOL_UPGRADE, PENDING_PROTOCOL_UPGRADE,
        BIOMETRY_NOT_SUPPORTED, BIOMETRY_NOT_AVAILABLE, BIOMETRY_NOT_RECOGNIZED,
        INSUFFICIENT_KEYCHAIN_PROTECTION, BIOMETRY_LOCKOUT, TIME_SYNCHRONIZATION})
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
     * Error code for error that occurs when invalid activation or invalid recovery code is provided.
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

    /**
     * Failed to synchronize time with the server.
     */
    int TIME_SYNCHRONIZATION = 23;
}
