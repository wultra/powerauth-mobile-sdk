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

/**
 * The <code>ECIESEncryptorScope</code> enumeration defines how {@link ECIESEncryptor} encryptor
 * is configured in {@link Session#getEciesEncryptor(ECIESEncryptorScope, SignatureUnlockKeys, byte[]) Session.getEciesEncryptor} method.
 */
public enum ECIESEncryptorScope {
    /**
     * An application scope means that encryptor can be constructed also when
     * the session has no valid activation.
     */
    Application(0),

    /**
     * An activation scope means that the encryptor can be constructed only when
     * the session has a valid activation.
     */
    Activation(1);

    /**
     * The value associated to the enumeration.
     */
    public final int numericValue;

    ECIESEncryptorScope(int numericValue) {
        this.numericValue = numericValue;
    }
}
