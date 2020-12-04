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

import android.content.Context;

import androidx.test.filters.SmallTest;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;

import io.getlime.security.powerauth.networking.client.HttpClient;

import static org.junit.Assert.*;

/**
 * Test that PowerAuthSDK.Builder configuration
 * is properly propagated into the instances.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4.class)
public class PowerAuthSDKBuilderTest {

    private PowerAuthConfiguration powerAuthConfiguration;
    private Context androidContext;

    @Before
    public void setUp() {
        androidContext = InstrumentationRegistry.getInstrumentation().getContext();

        PowerAuthConfiguration.Builder builder = new PowerAuthConfiguration.Builder(
                "com.wultra.android.powerauth.test",
                "http://wultra.com",
                "aaa",
                "bbb",
                "ccc");
        powerAuthConfiguration = builder.build();
    }

    @Test
    public void testClientConfigurationNull() throws Exception {
        PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(powerAuthConfiguration)
                .build(androidContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field pa2ClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        pa2ClientField.setAccessible(true);
        HttpClient httpClient = (HttpClient) pa2ClientField.get(powerAuthSDK);
        assertNotNull(httpClient);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = httpClient.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);
    }

    @Test
    public void testClientConfigurationNonNull() throws Exception {
        PowerAuthClientConfiguration srcClientConfiguration = new PowerAuthClientConfiguration.Builder()
                .build();
        PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(powerAuthConfiguration)
                .clientConfiguration(srcClientConfiguration)
                .build(androidContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field httpClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        httpClientField.setAccessible(true);
        HttpClient httpClient = (HttpClient) httpClientField.get(powerAuthSDK);
        assertNotNull(httpClient);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = httpClient.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);
        assertEquals(srcClientConfiguration, powerAuthClientConfigurationInClient);
    }

    @Test
    public void testKeychainConfigurationNull() throws Exception {
        PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(powerAuthConfiguration)
                .build(androidContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field keychainConfigurationField = powerAuthSDK.getClass().getDeclaredField("mKeychainConfiguration");
        keychainConfigurationField.setAccessible(true);
        PowerAuthKeychainConfiguration keychainConfiguration = (PowerAuthKeychainConfiguration) keychainConfigurationField.get(powerAuthSDK);
        assertNotNull(keychainConfiguration);
        assertEquals(PowerAuthKeychainConfiguration.KEYCHAIN_ID_STATUS, keychainConfiguration.getKeychainStatusId());
    }

    @Test
    public void testKeychainConfigurationNonNull() throws Exception {
        PowerAuthKeychainConfiguration srcKeychainConfiguration = new PowerAuthKeychainConfiguration.Builder()
                .linkBiometricItemsToCurrentSet(false)
                .build();
        PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(powerAuthConfiguration)
                .keychainConfiguration(srcKeychainConfiguration)
                .build(androidContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field keychainConfigurationField = powerAuthSDK.getClass().getDeclaredField("mKeychainConfiguration");
        keychainConfigurationField.setAccessible(true);
        PowerAuthKeychainConfiguration keychainConfiguration = (PowerAuthKeychainConfiguration) keychainConfigurationField.get(powerAuthSDK);
        assertNotNull(keychainConfiguration);
        assertEquals(srcKeychainConfiguration, keychainConfiguration);
    }
}
