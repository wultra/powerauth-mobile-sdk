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

package io.getlime.security.powerauth.core;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static io.getlime.security.powerauth.core.EciesEncryptorScope.ACTIVATION;
import static io.getlime.security.powerauth.core.EciesEncryptorScope.APPLICATION;

/**
 * The <code>EciesEncryptorScope</code> defines how {@link EciesEncryptor} encryptor
 * is configured in {@link Session#getEciesEncryptor(int, SignatureUnlockKeys, byte[]) Session.getEciesEncryptor} method.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({APPLICATION, ACTIVATION})
public @interface EciesEncryptorScope {

    /**
     * An application scope means that encryptor can be constructed also when
     * the session has no valid activation.
     */
    int APPLICATION = 0;

    /**
     * An activation scope means that the encryptor can be constructed only when
     * the session has a valid activation.
     */
    int ACTIVATION = 1;
}
