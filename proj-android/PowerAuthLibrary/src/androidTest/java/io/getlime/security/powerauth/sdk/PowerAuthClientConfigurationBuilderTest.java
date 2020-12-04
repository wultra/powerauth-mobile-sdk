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

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.HttpURLConnection;

import io.getlime.security.powerauth.networking.interceptors.HttpRequestInterceptor;
import io.getlime.security.powerauth.networking.ssl.PA2ClientSslNoValidationStrategy;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PowerAuthClientConfigurationBuilderTest {

    @Test
    public void testDefaultParameters() throws Exception {
        PowerAuthClientConfiguration configuration = new PowerAuthClientConfiguration.Builder()
                .build();
        assertFalse(configuration.isUnsecuredConnectionAllowed());
        assertEquals(PowerAuthClientConfiguration.DEFAULT_CONNECTION_TIMEOUT, configuration.getConnectionTimeout());
        assertEquals(PowerAuthClientConfiguration.DEFAULT_READ_TIMEOUT, configuration.getReadTimeout());
        assertNull(configuration.getClientValidationStrategy());
        assertNull(configuration.getRequestInterceptors());
    }

    @Test
    public void testCustomParameters() throws Exception {
        PowerAuthClientConfiguration configuration = new PowerAuthClientConfiguration.Builder()
                .allowUnsecuredConnection(true)
                .timeouts(200, 300)
                .requestInterceptor(new HttpRequestInterceptor() {
                    @Override
                    public void processRequestConnection(@NonNull HttpURLConnection connection) {
                        // Empty
                    }
                })
                .requestInterceptor(new HttpRequestInterceptor() {
                    @Override
                    public void processRequestConnection(@NonNull HttpURLConnection connection) {
                        // Empty
                    }
                })
                .clientValidationStrategy(new PA2ClientSslNoValidationStrategy())
                .build();
        assertTrue(configuration.isUnsecuredConnectionAllowed());
        assertEquals(200, configuration.getConnectionTimeout());
        assertEquals(300, configuration.getReadTimeout());
        assertNotNull(configuration.getClientValidationStrategy());
        assertNotNull(configuration.getRequestInterceptors());
        assertEquals(2, configuration.getRequestInterceptors().size());
    }
}
