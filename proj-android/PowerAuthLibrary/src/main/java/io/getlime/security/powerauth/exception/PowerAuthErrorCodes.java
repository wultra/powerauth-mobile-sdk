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

import static io.getlime.security.powerauth.exception.PowerAuthErrorCodes.*;
import static java.lang.annotation.RetentionPolicy.SOURCE;

/**
 * Created by miroslavmichalec on 20/10/2016.
 */
@Retention(SOURCE)
@IntDef({PA2Succeed, PA2ErrorCodeNetworkError, PA2ErrorCodeSignatureError, PA2ErrorCodeInvalidActivationState,
        PA2ErrorCodeInvalidActivationData, PA2ErrorCodeMissingActivation, PA2ErrorCodeAuthenticationFailed,
        PA2ErrorCodeActivationPending, PA2ErrorCodeKeychain, PA2ErrorCodeTouchIDNotAvailable, PA2ErrorCodeTouchIDCancel,
        PA2ErrorCodeOperationCancelled, PA2ErrorCodeInvalidActivationCode, PA2ErrorCodeInvalidToken,
        PA2ErrorCodeEncryptionError, PA2ErrorCodeWrongParameter, PA2ErrorCodeProtocolUpgrade,
        PA2ErrorCodePendingProtocolUpgrade})
public @interface PowerAuthErrorCodes {

    /**
     * Error code for error with network connectivity or download
     */
    int PA2Succeed = 0;
    int PA2ErrorCodeNetworkError = 1;
    int PA2ErrorCodeSignatureError = 2;
    int PA2ErrorCodeInvalidActivationState = 3;
    int PA2ErrorCodeInvalidActivationData = 4;
    int PA2ErrorCodeMissingActivation = 5;
    int PA2ErrorCodeAuthenticationFailed = 6;
    int PA2ErrorCodeActivationPending = 7;
    int PA2ErrorCodeKeychain = 8;
    int PA2ErrorCodeTouchIDNotAvailable = 9;
    int PA2ErrorCodeTouchIDCancel = 10;
    int PA2ErrorCodeOperationCancelled = 11;
    int PA2ErrorCodeInvalidActivationCode = 12;
    int PA2ErrorCodeInvalidToken = 13;
    int PA2ErrorCodeEncryptionError = 14;
    int PA2ErrorCodeWrongParameter = 15;

    /**
     * Error code for protocol upgrade failure.
     * The recommended action is to retry the status fetch operation, or remove the activation.
     */
    int PA2ErrorCodeProtocolUpgrade = 16;

    /**
     * The requested function is not available during the protocol upgrade. You can retry the operation,
     * after the upgrade is finished.
     */
    int PA2ErrorCodePendingProtocolUpgrade = 17;
}
