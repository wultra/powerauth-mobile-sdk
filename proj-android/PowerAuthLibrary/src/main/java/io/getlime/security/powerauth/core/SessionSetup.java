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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The SessionSetup class defines unique constants required during the lifetime
 * of the Session object.
 */
public class SessionSetup {

    static {
        System.loadLibrary(Session.NATIVE_LIB);
    }

    /**
     * Contains string with simplified configuration.
     */
    public final @NonNull String configuration;

    /**
     * Optional external encryption key. If the byte array's size is equal to 16 bytes,
     * then the key is considered as valid and will be used during the cryptographic operations.
     * <p>
     * The additional encryption key is useful in  multibanking applications, where it allows the
     * application to create chain of trusted PA2 activations. If the key is set, then the session will
     * perform additional encryption / decryption operations when the signature keys are being used.
     * <p>
     * The session implements a couple of simple protections against misuse of this feature and therefore
     * once the session is activated with the EEK, then you have to use that EEK for all future cryptographic
     * operations. The key is NOT serialized in the session's state and thus it's up to the application,
     * how it manages the chain of multiple PA2 sessions.
     */
    public final @Nullable byte[] externalEncryptionKey;

    /**
     * Construct object with new simplified configuration.
     *
     * @param configuration Simplified configuration.
     * @param externalEncryptionKey Optional external encryption key.
     */
    public SessionSetup(
            @NonNull String configuration,
            @Nullable byte[] externalEncryptionKey) {
        this.configuration = configuration;
        this.externalEncryptionKey = externalEncryptionKey;
    }

    /**
     * @return true if configuration appears to be valid.
     */
    public boolean isValid() {
        boolean result = validateConfiguration(configuration);
        if (result && externalEncryptionKey != null) {
            result = externalEncryptionKey.length == 16;
        }
        return result;
    }

    /**
     * Validates whether string with the cryptographic configuration is correct.
     * @param configuration String with the cryptographic configuration.
     * @return true if configuration is formally correct (e.g. can be processed by SDK)
     */
    static native boolean validateConfiguration(String configuration);

    /**
     * Build configuration string from partial parameters. The method is useful for other projects,
     * such as React-Native wrapper, to temporarily support old way of SDK configuration.
     * @param appKey Application's key.
     * @param appSecret Application's secret.
     * @param publicKey Application's master server public key.
     * @return String with the cryptographic configuration.
     */
    static native String buildConfiguration(String appKey, String appSecret, String publicKey);
}
