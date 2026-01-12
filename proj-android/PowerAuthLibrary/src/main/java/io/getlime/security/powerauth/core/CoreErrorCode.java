/*
 * Copyright 2025 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import static java.lang.annotation.RetentionPolicy.SOURCE;
import static io.getlime.security.powerauth.core.CoreErrorCode.*;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;

@Retention(SOURCE)
@IntDef({MISSING_ACTIVATION, WRONG_ACTIVATION_STATE, WRONG_PARAMETER, BIOMETRY_NOT_ALLOWED, NOT_ALLOWED,
        TIME_NOT_SYNCHRONIZED, INVALID_DATA, INVALID_RESPONSE, WRONG_SIGNATURE, INTERNAL_ERROR,
        CRYPTOGRAPHY, CANCELED, PENDING_PROTOCOL_UPGRADE, OTHER})
public @interface CoreErrorCode {
    /**
     * Session has no activation but activation is required for the operation.
     */
    int MISSING_ACTIVATION = 1;
    /**
     * Activation is in wrong state for the requested operation.
     */
    int WRONG_ACTIVATION_STATE = 2;
    /**
     * Wrong input parameter provided.
     */
    int WRONG_PARAMETER = 3;
    /**
     * Biometry factor is not configured.
     */
    int BIOMETRY_NOT_ALLOWED = 4;
    /**
     * Operation is not allowed in the current object's state. For example, if you try to already used encryptor object.
     */
    int NOT_ALLOWED = 5;
    /**
     * Operation require synchronized time.
     */
    int TIME_NOT_SYNCHRONIZED = 6;
    /**
     * Invalid data. Error is reported in situations, when configuration or serialized data format is not valid.
     */
    int INVALID_DATA = 7;
    /**
     * Invalid response received from the server.
     */
    int INVALID_RESPONSE = 8;
    /**
     * Digital or JWS signature is not valid.
     */
    int WRONG_SIGNATURE = 9;
    /**
     * Internal library error.
     */
    int INTERNAL_ERROR = 10;
    /**
     * Operation failed in the cryptographic provider.
     */
    int CRYPTOGRAPHY = 11;
    /**
     * Operation was canceled from elsewhere.
     */
    int CANCELED = 12;
    /**
     * Operation is not allowed due to pending protocol upgrade. Try again later.
     */
    int PENDING_PROTOCOL_UPGRADE = 13;
    /**
     * Other, unspecified type of error.
     */
    int OTHER = 14;
}
