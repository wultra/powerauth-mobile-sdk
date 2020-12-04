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

package io.getlime.security.powerauth.integration.tests;

import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import android.text.TextUtils;
import android.util.Base64;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import androidx.test.filters.LargeTest;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;
import io.getlime.security.powerauth.networking.response.IDataSignatureListener;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class EcdsaSignatureTest {

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;

    @Before
    public void setUp() throws Exception {
        testHelper = new PowerAuthTestHelper.Builder().build();
        powerAuthSDK = testHelper.getSharedSdk();
        activationHelper = new ActivationHelper(testHelper);
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
    }

    @Test
    public void testDeviceSignedData() throws Exception {

        final String testData = "Data signed with device private key: " + testHelper.getRandomGenerator().generateRandomString(10, 32);

        activationHelper.createStandardActivation(true, null);

        final byte[] dataToSign = testData.getBytes(Charset.defaultCharset());
        final byte[] signatureForData = AsyncHelper.await(new AsyncHelper.Execution<byte[]>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<byte[]> resultCatcher) throws Exception {
                powerAuthSDK.signDataWithDevicePrivateKey(testHelper.getContext(), activationHelper.getValidAuthentication(), dataToSign, new IDataSignatureListener() {
                    @Override
                    public void onDataSignedSucceed(byte[] signature) {
                        resultCatcher.completeWithResult(signature);
                    }

                    @Override
                    public void onDataSignedFailed(Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
        assertNotNull(signatureForData);

        final String dataForVerification = Base64.encodeToString(dataToSign, Base64.NO_WRAP);
        final String signatureForVerification = Base64.encodeToString(signatureForData, Base64.NO_WRAP);

        // Now validate that signature on the server.
        boolean result = testHelper.getServerApi().verifyEcdsaSignature(activationHelper.getActivation().getActivationId(), dataForVerification, signatureForVerification);
        assertTrue(result);
    }

    @Test
    public void testNonPersonalizedServerSignedData() throws Exception {

        final String testData = "HELLO\nThis is a test for ECDSA signature signed with master server public key" + testHelper.getRandomGenerator().generateRandomString(10, 32);

        final OfflineSignaturePayload payload = testHelper.getServerApi().createNonPersonalizedOfflineSignaturePayload(testHelper.getSharedApplication().getApplicationId(), testData);
        assertNotNull(payload);
        assertNotNull(payload.getData());
        assertNotNull(payload.getNonce());

        List<String> components = Arrays.asList(TextUtils.split(payload.getData(), "\n"));
        assertTrue(components.size() > 0);
        // Extract signature part
        String signatureBase64 = components.get(components.size() - 1).substring(1);  // skip "0" indicating type of signature;
        // Extract signed data part (replaces last component with key type marker)
        components.set(components.size() - 1, "0");
        String dataForSigning = TextUtils.join("\n", components);

        final byte[] signature = Base64.decode(signatureBase64, Base64.NO_WRAP);
        final byte[] signedBytes = dataForSigning.getBytes(Charset.defaultCharset());


        boolean signatureValid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, true);
        assertTrue(signatureValid);

        // Modify signed bytes to invalidate signature
        signedBytes[33] += 1;
        boolean signatureInvalid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, true);
        assertFalse(signatureInvalid);
    }

    @Test
    public void testPersonalizedServerSignedData() throws Exception {

        activationHelper.createStandardActivation(true, null);

        final String testData = "HELLO\nThis is a test for ECDSA signature signed with server public key\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);

        final OfflineSignaturePayload payload = testHelper.getServerApi().createPersonalizedOfflineSignaturePayload(activationHelper.getActivation().getActivationId(), testData);
        assertNotNull(payload);
        assertNotNull(payload.getData());
        assertNotNull(payload.getNonce());

        List<String> components = Arrays.asList(TextUtils.split(payload.getData(), "\n"));
        assertTrue(components.size() > 0);
        // Extract signature part
        String signatureBase64 = components.get(components.size() - 1).substring(1);  // skip "1" indicating type of signature;
        // Extract signed data part (replaces last component with key type marker)
        components.set(components.size() - 1, "1");
        String dataForSigning = TextUtils.join("\n", components);

        final byte[] signature = Base64.decode(signatureBase64, Base64.NO_WRAP);
        final byte[] signedBytes = dataForSigning.getBytes(Charset.defaultCharset());


        boolean signatureValid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, false);
        assertTrue(signatureValid);

        // Modify signed bytes to invalidate signature
        signedBytes[33] += 1;
        boolean signatureInvalid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, false);
        assertFalse(signatureInvalid);

        // Back to valid data, but remove the activation.
        signedBytes[33] -= 1;
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        signatureInvalid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, false);
        assertFalse(signatureInvalid);
    }
}
