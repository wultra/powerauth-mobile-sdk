/*
 * Copyright 2025 Wultra s.r.o.
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

import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import io.getlime.security.powerauth.biometry.IAddBiometryFactorListener;
import io.getlime.security.powerauth.biometry.IAuthenticateWithBiometricsListener;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.*;
import io.getlime.security.powerauth.integration.support.model.SignatureData;
import io.getlime.security.powerauth.integration.support.model.SignatureInfo;
import io.getlime.security.powerauth.integration.support.model.SignatureType;
import io.getlime.security.powerauth.sdk.*;
import io.getlime.security.powerauth.sdk.impl.MainThreadExecutor;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import java.util.Map;
import java.util.Objects;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
@Ignore("Require user interaction") // uncomment in case you want to manually test biometry
public class BiometricTests implements PowerAuthTestHelper.IConfigurationObserver {

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;
    private SignatureHelper signatureHelper;
    private ActivityScenario<TestActivity> activityScenario;

    @Before
    public void setUp() throws Exception {
        activityScenario = ActivityScenario.launch(TestActivity.class);
        signatureHelper = new SignatureHelper();
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
        activityScenario.close();
    }

    private void runWithFragmentActivity(final ITestExecution execution) throws Exception {
        runWithFragmentActivity(this, execution);
    }

    private void runWithFragmentActivity(final PowerAuthTestHelper.IConfigurationObserver configurationObserver,
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
                .testFragmentActivity(capturedActivity[0])
                .testFragment(fragment)
                .build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);

        // Tun test in the same thread
        execution.execute();
    }

    @Test
    public void testUsingBiometry() throws Exception {
        runWithFragmentActivity(() -> {
            activationHelper.createStandardActivation(true, null);
            AsyncHelper.await(resultCatcher -> {
                powerAuthSDK.addBiometryFactor(testHelper.getContext(), testHelper.getFragmentActivity(), "Dummy", "Dummy text", activationHelper.getValidPassword(), new IAddBiometryFactorListener() {
                    @Override
                    public void onAddBiometryFactorSucceed() {
                        resultCatcher.completeWithResult(true);
                    }

                    @Override
                    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                });
            });
            PowerAuthAuthentication authentication = AsyncHelper.await(resultCatcher -> {
                MainThreadExecutor.getInstance().execute(() -> powerAuthSDK.authenticateUsingBiometrics(testHelper.getContext(), testHelper.getFragmentActivity(), "Authenticate", "Authenticate with biometry", new IAuthenticateWithBiometricsListener() {
                    @Override
                    public void onBiometricDialogCancelled(boolean userCancel) {
                        resultCatcher.completeWithResult(null);
                    }

                    @Override
                    public void onBiometricDialogSuccess(@NonNull PowerAuthAuthentication authentication) {
                        resultCatcher.completeWithResult(authentication);
                    }

                    @Override
                    public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                        resultCatcher.completeWithError(error);
                    }
                }));
            });
            assertNotNull(authentication);
            // Now verify signature on the server
            PowerAuthAuthorizationHttpHeader header = powerAuthSDK.requestSignatureWithAuthentication(testHelper.getContext(), authentication, "POST", "/uri/id", null);
            assertNotNull(header);
            assertEquals(0, header.getPowerAuthErrorCode());
            Map<String, String> sigComponents = signatureHelper.parseAuthorizationHeader(header);
            final String sigVersion = sigComponents.get("pa_version");
            final String sigActivationId = sigComponents.get("pa_activation_id");
            final String sigNonce = Objects.requireNonNull(sigComponents.get("pa_nonce"));
            final String sigAppKey = sigComponents.get("pa_application_key");
            final String sigType = Objects.requireNonNull(sigComponents.get("pa_signature_type")).toUpperCase();
            final String sigValue = sigComponents.get("pa_signature");

            final String dataToVerifySignature = signatureHelper.normalizeOnlineData("", "POST", "/uri/id", sigNonce);
            SignatureData signatureData = new SignatureData();
            signatureData.setActivationId(sigActivationId);
            signatureData.setData(dataToVerifySignature);
            signatureData.setSignature(sigValue);
            signatureData.setSignatureType(SignatureType.valueOf(sigType));
            signatureData.setSignatureVersion(sigVersion);
            signatureData.setApplicationKey(sigAppKey);

            // Verify on server
            final SignatureInfo verifyResult = testHelper.getServerApi().verifyOnlineSignature(signatureData);
            assertTrue(verifyResult.isSignatureValid());
        });
    }

    @Override
    public void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder) {
    }

    @Override
    public void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder) {
        builder.authenticateOnBiometricKeySetup(false);
    }
}
