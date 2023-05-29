/*
 * Copyright 2023 Wultra s.r.o.
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

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SessionSetupTest {
    @Test
    public void testValidV3Configuration() throws Exception {
        boolean result = SessionSetup.validateConfiguration("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==");
        assertTrue(result);
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        assertFalse(SessionSetup.validateConfiguration(""));
        assertFalse(SessionSetup.validateConfiguration(null));
    }

    @Test
    public void testConfigBuilder() throws Exception {
        String appKey = "w4+hAeogFLTZjcSjPwbG2g==";
        String appSecret = "Szls/7JWbKN+FAOijHcsPA==";
        String publicKey = "BEEOwljSgItBIAnzr3f7K36s+KKoUzC8LE+K+7Dy0X6iAkcPXAjLP1KKPxdqyM/iihHAcW5x/WzJPCbtytcJo2w=";
        String config = SessionSetup.buildConfiguration(appKey, appSecret, publicKey);
        assertEquals("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", config);
    }
}
