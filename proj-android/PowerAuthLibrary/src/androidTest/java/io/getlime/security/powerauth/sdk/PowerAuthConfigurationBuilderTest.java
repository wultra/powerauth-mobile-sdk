/*
 * Copyright 2020 Wultra s.r.o.
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

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.util.Objects;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthConfigurationBuilderTest {

    @Test
    public void testBasicParameters() throws Exception {
        PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                "com.wultra.android.powerauth.test",
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .build();
        assertNotNull(configuration);
        assertEquals("com.wultra.android.powerauth.test", configuration.getInstanceId());
        assertEquals("http://wultra.com", configuration.getBaseEndpointUrl());
        assertEquals("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", configuration.getConfiguration());
        assertNull(configuration.getExternalEncryptionKey());
        assertTrue(configuration.validateConfiguration());
    }

    @Test
    public void testDefaultParameters() throws Exception {
        PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                null,
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .build();
        assertNotNull(configuration);
        assertEquals(PowerAuthConfiguration.DEFAULT_INSTANCE_ID, configuration.getInstanceId());
        assertEquals("http://wultra.com", configuration.getBaseEndpointUrl());
        assertEquals("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", configuration.getConfiguration());
        assertNull(configuration.getExternalEncryptionKey());
        assertTrue(configuration.validateConfiguration());
        assertEquals(8, configuration.getOfflineSignatureComponentLength());
    }

    @Test
    public void testExternalEncryptionKey() throws Exception {
        final byte[] expectedEEK = "0123456789ABCDEF".getBytes(Charset.defaultCharset());
        PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                null,
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .externalEncryptionKey(expectedEEK)
                .build();
        assertNotNull(configuration);
        assertEquals(PowerAuthConfiguration.DEFAULT_INSTANCE_ID, configuration.getInstanceId());
        assertEquals("http://wultra.com", configuration.getBaseEndpointUrl());
        assertEquals("ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==", configuration.getConfiguration());
        assertArrayEquals(expectedEEK, configuration.getExternalEncryptionKey());
        assertTrue(configuration.validateConfiguration());
        // Test EEK after modify
        expectedEEK[0] = 'X';
        assertEquals('0', Objects.requireNonNull(configuration.getExternalEncryptionKey())[0]);
    }

    @Test
    public void testOfflineSignatureComponentLength() throws Exception {
        PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                null,
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .offlineSignatureComponentLength(4)
                .build();
        assertEquals(4, configuration.getOfflineSignatureComponentLength());
        // Invalid values
        configuration = new PowerAuthConfiguration.Builder(
                null,
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .offlineSignatureComponentLength(3)
                .build();
        assertFalse(configuration.validateConfiguration());
        configuration = new PowerAuthConfiguration.Builder(
                null,
                "http://wultra.com",
                "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==")
                .offlineSignatureComponentLength(9)
                .build();
        assertFalse(configuration.validateConfiguration());
    }
}
