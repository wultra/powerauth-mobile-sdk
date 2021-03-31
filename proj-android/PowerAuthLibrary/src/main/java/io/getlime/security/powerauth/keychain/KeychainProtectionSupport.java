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
 * The {@code KeychainProtectionSupport} interface provides information about what level of encryption
 * is available on the device.
 */
public interface KeychainProtectionSupport {

    /**
     * Determine whether encryption with KeyStore-backed key is supported on this device.
     * @return {@code true} if KeyStore-backed key is supported on this device.
     */
    boolean isKeyStoreEncryptionSupported();
    /**
     * Determine whether encryption with KeyStore-backed key is supported and enabled on this device.
     * @return {@code true} if KeyStore-backed key is supported and enabled on this device.
     */
    boolean isKeyStoreEncryptionEnabled();
    /**
     * Determine whether StrongBox is supported on this device.
     * @return {@code true} if StrongBox is supported on this device.
     */
    boolean isStrongBoxSupported();
    /**
     * Determine whether StrongBox is supported and enabled on this device.
     * @return {@code true} if StrongBox is enabled on this device.
     */
    boolean isStrongBoxEnabled();
}
