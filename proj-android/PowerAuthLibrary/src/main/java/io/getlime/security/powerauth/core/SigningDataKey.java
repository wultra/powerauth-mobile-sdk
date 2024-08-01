/*
 * Copyright 2024 Wultra s.r.o.
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

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.SigningDataKey.ECDSA_MASTER_SERVER_KEY;
import static io.getlime.security.powerauth.core.SigningDataKey.ECDSA_PERSONALIZED_KEY;
import static io.getlime.security.powerauth.core.SigningDataKey.HMAC_APPLICATION;
import static io.getlime.security.powerauth.core.SigningDataKey.HMAC_ACTIVATION;

/**
 * The <code>SigningDataKey</code> defines key type for signature validation or calculation.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({ECDSA_MASTER_SERVER_KEY, ECDSA_PERSONALIZED_KEY, HMAC_APPLICATION, HMAC_ACTIVATION})
public @interface SigningDataKey {
    /**
     * {@code KEY_SERVER_MASTER_PRIVATE} key was used for signature calculation.
     */
    int ECDSA_MASTER_SERVER_KEY = 0;
    /**
     * {@code KEY_SERVER_PRIVATE} key was used for signature calculation.
     */
    int ECDSA_PERSONALIZED_KEY = 1;
    /**
     * {@code APP_SECRET} key is used for HMAC-SHA256 signature calculation.
     */
    int HMAC_APPLICATION = 2;
    /**
     * {@code KEY_TRANSPORT} key is used for HMAC-SHA256 signature calculation.
     */
    int HMAC_ACTIVATION = 3;
}
