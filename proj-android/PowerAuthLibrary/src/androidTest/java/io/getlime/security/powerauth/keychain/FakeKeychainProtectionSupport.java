/*
 * Copyright 2021 Wultra s.r.o.
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

package io.getlime.security.powerauth.keychain;

/**
 * Testing implementation of {@link KeychainProtectionSupport} interface that can simulate StrongBox support
 * level during the unit test.
 */
public class FakeKeychainProtectionSupport implements KeychainProtectionSupport {

    private final boolean isStrongBoxSupported;
    private final boolean isStrongBoxEnabled;
    private final boolean isKeyStoreEncryptionSupported;
    private final boolean isKeyStoreEncryptionEnabled;

    public static final FakeKeychainProtectionSupport
            NO_ENCRYPTION = new FakeKeychainProtectionSupport(false, false, false, false);
    public static final FakeKeychainProtectionSupport
            HAS_ENCRYPTION_DISABLED = new FakeKeychainProtectionSupport(false, false, true, false);
    public static final FakeKeychainProtectionSupport
            NO_STRONGBOX = new FakeKeychainProtectionSupport(false, false, true, true);
    public static final FakeKeychainProtectionSupport
            HAS_STRONGBOX = new FakeKeychainProtectionSupport(true, true, true, true);
    public static final FakeKeychainProtectionSupport
            HAS_STRONGBOX_DISABLED = new FakeKeychainProtectionSupport(true, false, true, true);

    /**
     * Set any combination of emulated StrongBox support.
     * @param strongBoxSupported Set StrongBox supported.
     * @param strongBoxEnabled Set StrongBox enabled.
     * @param keyStoreEncryptionSupported Set KeyStore encryption supported.
     * @param keyStoreEncryptionEnabled  Set KeyStore encryption enabled.
     */
    public FakeKeychainProtectionSupport(
            boolean strongBoxSupported,
            boolean strongBoxEnabled,
            boolean keyStoreEncryptionSupported,
            boolean keyStoreEncryptionEnabled) {
        isStrongBoxSupported = strongBoxSupported;
        isStrongBoxEnabled = strongBoxEnabled;
        isKeyStoreEncryptionSupported = keyStoreEncryptionSupported;
        isKeyStoreEncryptionEnabled = keyStoreEncryptionEnabled;
    }

    @Override
    public boolean isKeyStoreEncryptionSupported() {
        return isKeyStoreEncryptionSupported;
    }

    @Override
    public boolean isKeyStoreEncryptionEnabled() {
        return isKeyStoreEncryptionSupported && isKeyStoreEncryptionEnabled;
    }

    @Override
    public boolean isStrongBoxSupported() {
        return isStrongBoxSupported;
    }

    @Override
    public boolean isStrongBoxEnabled() {
        return isStrongBoxSupported && isStrongBoxEnabled;
    }
}
