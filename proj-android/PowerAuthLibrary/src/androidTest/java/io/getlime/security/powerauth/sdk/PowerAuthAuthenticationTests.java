/*
 * Copyright 2022 Wultra s.r.o.
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

import io.getlime.security.powerauth.core.SecureData;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.RandomGenerator;
import io.getlime.security.powerauth.system.PowerAuthLog;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthAuthenticationTests {

    final RandomGenerator randomGenerator;
    final SecureData customPossessionKey;
    final SecureData biometryKey;
    final Password password;
    final String stringPassword;

    public PowerAuthAuthenticationTests() {
        this.randomGenerator = new RandomGenerator();
        this.customPossessionKey = SecureData.capture(randomGenerator.generateBytes(16));
        this.biometryKey = SecureData.capture(randomGenerator.generateBytes(16));
        this.stringPassword = "1234";
        this.password = new Password(stringPassword);

        PowerAuthLog.setEnabled(true);
    }

    @Test
    public void testPersistWithPassword() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.persistWithPassword(password);
        authentication.validateAuthenticationUsage(true);
        assertEquals(password, authentication.getPassword());

        authentication = PowerAuthAuthentication.persistWithPassword(stringPassword);
        authentication.validateAuthenticationUsage(true);
        assertEquals(password, authentication.getPassword());
    }

    @Test
    public void testPersisWithPasswordAndBiometry() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(password, biometryKey);
        authentication.validateAuthenticationUsage(true);
        assertEquals(password, authentication.getPassword());
        assertEquals(biometryKey, authentication.getBiometryFactorRelatedKey());

        authentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(stringPassword, biometryKey);
        authentication.validateAuthenticationUsage(true);
        assertEquals(password, authentication.getPassword());
        assertEquals(biometryKey, authentication.getBiometryFactorRelatedKey());
    }

    @Test
    public void testPossessionOnly() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possession();
        authentication.validateAuthenticationUsage(false);
        assertEquals(1, authentication.getAuthenticationCodeFactorsMask());
    }

    @Test
    public void testPossessionWithPassword() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword(password);
        authentication.validateAuthenticationUsage(false);
        assertEquals(password, authentication.getPassword());
        assertEquals(1 + 2, authentication.getAuthenticationCodeFactorsMask());

        authentication = PowerAuthAuthentication.possessionWithPassword(stringPassword);
        authentication.validateAuthenticationUsage(false);
        assertEquals(password, authentication.getPassword());
        assertEquals(1 + 2, authentication.getAuthenticationCodeFactorsMask());
    }

    @Test
    public void testPossessionWithBiometry() throws Exception {
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithBiometry(biometryKey);
        authentication.validateAuthenticationUsage(false);
        assertEquals(biometryKey, authentication.getBiometryFactorRelatedKey());
        assertEquals(1 + 4, authentication.getAuthenticationCodeFactorsMask());
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testWrongUsage() {
        PowerAuthErrorException exception;
        // wrong usage
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.persistWithPassword(password).validateAuthenticationUsage(false));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.possessionWithPassword(password).validateAuthenticationUsage(true));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());

        // deprecated API
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.persistWithPassword(password, customPossessionKey).validateAuthenticationUsage(true));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.persistWithPassword(stringPassword, customPossessionKey).validateAuthenticationUsage(true));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.persistWithPasswordAndBiometry(password, biometryKey, customPossessionKey).validateAuthenticationUsage(true));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.persistWithPasswordAndBiometry(stringPassword, biometryKey, customPossessionKey).validateAuthenticationUsage(true));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.possession(customPossessionKey).validateAuthenticationUsage(false));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.possessionWithPassword(password, customPossessionKey).validateAuthenticationUsage(false));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.possessionWithPassword(stringPassword, customPossessionKey).validateAuthenticationUsage(false));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
        exception = assertThrows(PowerAuthErrorException.class, () -> PowerAuthAuthentication.possessionWithBiometry(biometryKey, customPossessionKey).validateAuthenticationUsage(false));
        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, exception.getPowerAuthErrorCode());
    }
}
