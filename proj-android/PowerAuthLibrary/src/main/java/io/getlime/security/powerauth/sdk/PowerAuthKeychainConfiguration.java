/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

/**
 * Class representing the keychain settings.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthKeychainConfiguration {

    private static final String KEYCHAIN_ID_STATUS = "io.getlime.PowerAuthKeychain.StatusKeychain";
    private static final String KEYCHAIN_ID_BIOMETRY = "io.getlime.PowerAuthKeychain.BiometryKeychain";
    private static final String KEYCHAIN_KEY_BIOMETRY_DEFAULT = "io.getlime.PowerAuthKeychain.BiometryKeychain.DefaultKey";

    private final String customKeychainIdStatus;
    private final String customKeychainIdBiometry;
    private final String customKeychainKeyBiometryDefault;

    /**
     * Default public constructor.
     */
    public PowerAuthKeychainConfiguration() {
        this.customKeychainIdStatus = null;
        this.customKeychainIdBiometry = null;
        this.customKeychainKeyBiometryDefault = null;
    }

    /**
     * Constructor that allows key name customization, in case it is required.
     *
     * @param customKeychainIdStatus Name of the Keychain file used for storing the status information.
     * @param customKeychainIdBiometry Name of the Keychain file used for storing the biometry key information.
     * @param customKeychainKeyBiometryDefault Name of the Keychain key used to store the default biometry key.
     */
    public PowerAuthKeychainConfiguration(String customKeychainIdStatus, String customKeychainIdBiometry, String customKeychainKeyBiometryDefault) {
        this.customKeychainIdStatus = customKeychainIdStatus;
        this.customKeychainIdBiometry = customKeychainIdBiometry;
        this.customKeychainKeyBiometryDefault = customKeychainKeyBiometryDefault;
    }

    /**
     * Get name of the Keychain file used for storing status information.
     * @return Name of the Keychain file.
     */
    public String getKeychainStatusId() {
        if (customKeychainIdStatus != null) {
            return customKeychainIdStatus;
        }
        return KEYCHAIN_ID_STATUS;
    }

    /**
     * Get name of the Keychain file used for storing biometry key information.
     * @return Name of the Keychain file.
     */
    public String getKeychainBiometryId() {
        if (customKeychainIdBiometry != null) {
            return customKeychainIdBiometry;
        }
        return KEYCHAIN_ID_BIOMETRY;
    }

    /**
     * Get name of the Keychain key used for storing the default biometry key information.
     * @return Name of the biometry Keychain key.
     */
    public String getKeychainBiometryDefaultKey() {
        if (customKeychainKeyBiometryDefault != null) {
            return customKeychainKeyBiometryDefault;
        }
        return KEYCHAIN_KEY_BIOMETRY_DEFAULT;
    }


}
