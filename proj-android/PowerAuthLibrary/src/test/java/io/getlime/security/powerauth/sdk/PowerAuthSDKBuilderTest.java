package io.getlime.security.powerauth.sdk;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.lang.reflect.Field;

import io.getlime.security.powerauth.networking.client.PA2Client;
import io.getlime.security.powerauth.shadow.ShadowDefaultSavePowerAuthStateListener;
import io.getlime.security.powerauth.shadow.ShadowSession;

import static org.junit.Assert.*;

/**
 * Test that PowerAuthSDK.Builder configuration
 * is properly propagated into the instances.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(RobolectricTestRunner.class)
@Config(shadows = {
        ShadowSession.class,
        ShadowDefaultSavePowerAuthStateListener.class
})
public class PowerAuthSDKBuilderTest {

    private PowerAuthConfiguration powerAuthConfiguration;

    @Before
    public void setUp() {
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
        PowerAuthSDK.Builder builder = new PowerAuthSDK.Builder(powerAuthConfiguration);
        PowerAuthSDK powerAuthSDK = builder
                .build(RuntimeEnvironment.systemContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field clientConfigurationField = powerAuthSDK.getClass().getDeclaredField("mClientConfiguration");
        clientConfigurationField.setAccessible(true);
        PowerAuthClientConfiguration powerAuthClientConfiguration = (PowerAuthClientConfiguration) clientConfigurationField.get(powerAuthSDK);
        assertNotNull(powerAuthClientConfiguration);

        Field pa2ClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        pa2ClientField.setAccessible(true);
        PA2Client pa2Client = (PA2Client) pa2ClientField.get(powerAuthSDK);
        assertNotNull(pa2Client);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = pa2Client.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);

        assertEquals(powerAuthClientConfiguration, powerAuthClientConfigurationInClient);
    }

    @Test
    public void testClientConfigurationNonNull() throws Exception {
        PowerAuthClientConfiguration srcClientConfiguration = new PowerAuthClientConfiguration.Builder()
                .build();
        PowerAuthSDK.Builder builder = new PowerAuthSDK.Builder(powerAuthConfiguration);
        PowerAuthSDK powerAuthSDK = builder
                .clientConfiguration(srcClientConfiguration)
                .build(RuntimeEnvironment.systemContext);

        assertNotNull(powerAuthSDK);
        assertNotNull(powerAuthSDK.getConfiguration());

        Field clientConfigurationField = powerAuthSDK.getClass().getDeclaredField("mClientConfiguration");
        clientConfigurationField.setAccessible(true);
        PowerAuthClientConfiguration powerAuthClientConfiguration = (PowerAuthClientConfiguration) clientConfigurationField.get(powerAuthSDK);
        assertNotNull(powerAuthClientConfiguration);
        assertEquals(srcClientConfiguration, powerAuthClientConfiguration);

        Field pa2ClientField = powerAuthSDK.getClass().getDeclaredField("mClient");
        pa2ClientField.setAccessible(true);
        PA2Client pa2Client = (PA2Client) pa2ClientField.get(powerAuthSDK);
        assertNotNull(pa2Client);

        PowerAuthClientConfiguration powerAuthClientConfigurationInClient = pa2Client.getClientConfiguration();
        assertNotNull(powerAuthClientConfigurationInClient);
        assertEquals(srcClientConfiguration, powerAuthClientConfigurationInClient);

        assertEquals(powerAuthClientConfiguration, powerAuthClientConfigurationInClient);
    }
}
