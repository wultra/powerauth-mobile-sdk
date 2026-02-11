/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import io.getlime.security.powerauth.core.CoreSecureVaultKeyId;

import static io.getlime.security.powerauth.sdk.PowerAuthSecureVaultKeyId.*;

/**
 * The {@code PowerAuthSecureVaultKeyId} enumeration defines the types of vault keys
 * supported in the PowerAuth Mobile SDK.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({KNOWLEDGE_OR_BIOMETRY, KNOWLEDGE})
public @interface PowerAuthSecureVaultKeyId {
    /**
     * This type of vault key can be provided after successful 2FA authentication on the server.
     */
    int KNOWLEDGE_OR_BIOMETRY = CoreSecureVaultKeyId.ANY_2FA;
    /**
     * This type of vault key can be provided after authentication with the user's password.
     */
    int KNOWLEDGE = CoreSecureVaultKeyId.KNOWLEDGE;
}
