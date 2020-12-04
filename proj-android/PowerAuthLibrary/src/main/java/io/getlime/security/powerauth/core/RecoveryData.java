/*
 * Copyright 2019 Wultra s.r.o.
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

import androidx.annotation.NonNull;

/**
 * The {@code RecoveryData} contains information about recovery code and PUK, created
 * during the activation process.
 */
public class RecoveryData {

    /**
     * Contains recovery code.
     */
    public final String recoveryCode;

    /**
     * Contains PUK, valid with recovery code.
     */
    public final String puk;

    /**
     * @param recoveryCode String with recovery code
     * @param puk String with PUK (10 digits long string)
     */
    public RecoveryData(@NonNull String recoveryCode, @NonNull String puk) {
        this.recoveryCode = recoveryCode;
        this.puk = puk;
    }

    /**
     * Constructor used from JNI code.
     */
    public RecoveryData() {
        this.recoveryCode = null;
        this.puk = null;
    }
}
