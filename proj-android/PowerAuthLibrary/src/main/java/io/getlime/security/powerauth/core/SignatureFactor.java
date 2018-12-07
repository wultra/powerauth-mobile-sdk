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

package io.getlime.security.powerauth.core;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.SignatureFactor.Biometry;
import static io.getlime.security.powerauth.core.SignatureFactor.Knowledge;
import static io.getlime.security.powerauth.core.SignatureFactor.Possession;

/**
 * The SignatureFactor constants defines factors involved in the signature
 * computation. The factor types are tightly coupled with SignatureUnlockKeys
 * class.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef(flag = true,
        value = {Possession, Knowledge, Biometry})
public @interface SignatureFactor {
    /**
     * The possession factor, you have to provide possessionUnlocKey.
     */
    int Possession = 0x0001;
    /**
     * The knowledge factor, you have to provide userPassword
     */
    int Knowledge = 0x0010;
    /**
     * The biometry factor, you have to provide biometryUnlockKey.
     */
    int Biometry = 0x0100;

    /**
     * 2FA, with using possession and knowledge factors.
     */
    int Possession_Knowledge = 0x0011;
    /**
     * 2FA, with using possession and biometric factors.
     */
    int Possession_Biometry = 0x0101;
    /**
     * 3FA, with using all supported factors.
     */
    int Possession_Knowledge_Biometry = 0x0111;
}