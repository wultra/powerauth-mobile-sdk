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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * The SessionSetup class defines unique constants required during the lifetime
 * of the Session object.
 */
public class SessionSetup {

    /**
     * Defines APPLICATION_KEY for the session.
     */
    public final @NonNull String applicationKey;
    
    /**
     * Defines APPLICATION_SECRET for the session.
     */
    public final @NonNull String applicationSecret;
    
    /**
     * The master server public key, in BASE64 format.
     * It's strongly recommended to use different keys for the testing
     * and production servers.
     */
    public final @NonNull String masterServerPublicKey;
    
    /**
     * Optional session identifier helps with session identification
     * in multi-session environments. You can assign any value
     * which helps you identify multiple sessions in your system.
     * The DEBUG build of the underlying C++ code is using the identifier
     * when prints information to the debug console. For production builds,
     * the value is not used in the PA2 codes.
     */
    public final int sessionIdentifier;
    
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
     * @param applicationKey application key constant in Base64 format
     * @param applicationSecret application secret constant in Base64 format
     * @param masterServerPublicKey master server public key in Base64 format
     * @param sessionIdentifier numeric session identifier
     * @param externalEncryptionKey optional external encryption key
     */
    public SessionSetup(
            @NonNull String applicationKey,
            @NonNull String applicationSecret,
            @NonNull String masterServerPublicKey,
            int sessionIdentifier,
            @Nullable byte[] externalEncryptionKey) {
        this.applicationKey = applicationKey;
        this.applicationSecret = applicationSecret;
        this.masterServerPublicKey = masterServerPublicKey;
        this.sessionIdentifier = sessionIdentifier;
        this.externalEncryptionKey = externalEncryptionKey;
    }

    // Constructor accessed from JNI code.
    public SessionSetup() {
        this.applicationKey = null;
        this.applicationSecret = null;
        this.masterServerPublicKey = null;
        this.sessionIdentifier = 0;
        this.externalEncryptionKey = null;
    }
}
