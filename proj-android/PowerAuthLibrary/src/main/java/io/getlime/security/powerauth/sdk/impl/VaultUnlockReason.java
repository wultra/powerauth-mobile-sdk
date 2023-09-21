/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk.impl;


import androidx.annotation.StringDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.sdk.impl.VaultUnlockReason.*;

/**
 * Constants for Vault Unlock reasons.
 */
@Retention(RetentionPolicy.SOURCE)
@StringDef({ADD_BIOMETRY, FETCH_ENCRYPTION_KEY, SIGN_WITH_DEVICE_PRIVATE_KEY, RECOVERY_CODE})
public @interface VaultUnlockReason {

    /**
     * Add biometry factor is the reason for vault unlock.
     */
    String ADD_BIOMETRY = "ADD_BIOMETRY";
    /**
     * Fetch encryption key is the reason for vault unlock.
     */
    String FETCH_ENCRYPTION_KEY = "FETCH_ENCRYPTION_KEY";
    /**
     * Sign with device private key is the reason for vault unlock.
     */
    String SIGN_WITH_DEVICE_PRIVATE_KEY = "SIGN_WITH_DEVICE_PRIVATE_KEY";
    /**
     * Get recovery code is the reason for vault unlock.
     */
    String RECOVERY_CODE = "RECOVERY_CODE";
}
