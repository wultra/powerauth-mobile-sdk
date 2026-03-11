/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.tests;

import static org.junit.Assert.assertNotNull;

import androidx.annotation.NonNull;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;

import io.getlime.security.powerauth.integration.support.ITestExecution;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.TestActivity;
import io.getlime.security.powerauth.integration.support.TestFragment;
import io.getlime.security.powerauth.sdk.PowerAuthBiometricConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;

/**
 * Base class to support tests with {@link ActivityScenario}.
 */
public abstract class FragmentActivityBaseTest extends BaseTest implements PowerAuthTestHelper.IConfigurationObserver {

    ActivityScenario<TestActivity> activityScenario;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        activityScenario = ActivityScenario.launch(TestActivity.class);
    }

    @Override
    public void tearDown() {
        super.tearDown();
        activityScenario.close();
    }

    void runWithFragmentActivity(final ITestExecution execution) throws Exception {
        runWithFragmentActivity(this, execution);
    }

    void runWithFragmentActivity(final PowerAuthTestHelper.IConfigurationObserver configurationObserver,
                                 final ITestExecution execution) throws Exception {
        FragmentActivity[] capturedActivity = new FragmentActivity[1];
        TestFragment fragment = new TestFragment();

        // Create supporting UI
        activityScenario.moveToState(Lifecycle.State.STARTED);
        activityScenario.onActivity(activity -> {
            capturedActivity[0] = activity;
            activity.getSupportFragmentManager()
                    .beginTransaction()
                    .add(android.R.id.content, fragment)
                    .commitNow(); // Synchronously attach the fragment
        });
        assertNotNull(capturedActivity[0]);
        // Setup
        testHelper = new PowerAuthTestHelper.Builder()
                .configurationObserver(configurationObserver)
                .powerAuthAlgorithm(testHelper.getSharedPowerAuthConfiguration().getAlgorithm())
                .testFragmentActivity(capturedActivity[0])
                .testFragment(fragment)
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
        authenticationHelper = new AuthenticationHelper(testHelper);

        // Run test in the same thread
        execution.execute();
    }

    @Override
    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder) {
        builder.authenticateOnBiometricKeySetup(false);
    }

    @Override
    public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
    }

}
