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

/**
 * The SignatureUnlockKeys class keeps all keys required for data signature
 * computation. Typically, you have to provide all  keys involved into selected
 * combination of factors.
 */
public class SignatureUnlockKeys {
    
    /**
     * The key required for signatures with "possession" factor.
     * You have to provide a key based on the unique properties of the device.
     * For example, WI-FI MAC address or UDID are a good sources for this
     * key. You can use Session::normalizeSignatureUnlockKeyFromData method
     * to convert arbitrary data into normalized key.
     * You cannot use vector of zeroes as a key. That's a protection against
     * lazy developers.
     */
    public final byte[] possessionUnlockKey;
    /**
     * The key required for signatures with "biometry" factor. You should not
     * use this key and factor, if device has no biometric engine available.
     * You cannot use vector of zeroes as a key. That's a protection against
     * lazy developers.
     */
    public final byte[] biometryUnlockKey;
    /**
     * The password required for signatures with "knowledge" factor. The complexity
     * of the password depends on the rules, defined by the applicaiton.
     * The Session validates only the minimum lenght of the passphrase.
     */
    public final Password userPassword;

    /**
     * @param possessionUnlockKey key for lock or unlock the signature key for possession factor
     * @param biometryUnlockKey key for lock or unlock the signature key for biometry factor
     * @param userPassword password for lock or unlock the signature key for knowledge factor
     */
    public SignatureUnlockKeys(byte[] possessionUnlockKey, byte[] biometryUnlockKey, Password userPassword) {
        this.possessionUnlockKey = possessionUnlockKey;
        this.biometryUnlockKey = biometryUnlockKey;
        this.userPassword = userPassword;
    }
}