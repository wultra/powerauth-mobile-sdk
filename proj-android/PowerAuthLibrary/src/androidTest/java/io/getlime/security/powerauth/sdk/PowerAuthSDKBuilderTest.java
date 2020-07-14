package io.getlime.security.powerauth.sdk;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

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

        Field clientConfigurationField = powerAuthSDK.getClass().getDeclaredField("mClientConfiguration");
        clientConfigurationField.setAccessible(true);
        PowerAuthClientConfiguration powerAuthClientConfiguration = (PowerAuthClientConfiguration) clientConfigurationField.get(powerAuthSDK);
        assertNotNull(powerAuthClientConfiguration);

        Field pa2ClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        pa2ClientField.setAccessible(true);
        HttpClient httpClient = (HttpClient) pa2ClientField.get(powerAuthSDK);
        assertNotNull(httpClient);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = httpClient.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);

        assertEquals(powerAuthClientConfiguration, powerAuthClientConfigurationInClient);
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

        Field clientConfigurationField = powerAuthSDK.getClass().getDeclaredField("mClientConfiguration");
        clientConfigurationField.setAccessible(true);
        PowerAuthClientConfiguration powerAuthClientConfiguration = (PowerAuthClientConfiguration) clientConfigurationField.get(powerAuthSDK);
        assertNotNull(powerAuthClientConfiguration);
        assertEquals(srcClientConfiguration, powerAuthClientConfiguration);

        Field httpClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        httpClientField.setAccessible(true);
        HttpClient httpClient = (HttpClient) httpClientField.get(powerAuthSDK);
        assertNotNull(httpClient);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = httpClient.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);
        assertEquals(srcClientConfiguration, powerAuthClientConfigurationInClient);

        assertEquals(powerAuthClientConfiguration, powerAuthClientConfigurationInClient);
    }
}
