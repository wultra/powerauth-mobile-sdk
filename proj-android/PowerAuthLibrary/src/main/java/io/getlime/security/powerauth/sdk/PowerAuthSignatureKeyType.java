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

package io.getlime.security.powerauth.sdk;

import static java.lang.annotation.RetentionPolicy.SOURCE;
import static io.getlime.security.powerauth.sdk.PowerAuthSignatureKeyType.*;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;

import io.getlime.security.powerauth.core.CoreSignatureKeyType;

/**
 * The {@code PowerAuthSignatureKeyType} enumeration defines the types of keys used for signing
 * or verifying operations.
 */
@Retention(SOURCE)
@IntDef({EC, ML_DSA})
public @interface PowerAuthSignatureKeyType {
    /**
     * Elliptic Curve–based key.
     */
    int EC = CoreSignatureKeyType.EC;
    /**
     * ML-DSA–based key.
     */
    int ML_DSA = CoreSignatureKeyType.ML_DSA;
}
