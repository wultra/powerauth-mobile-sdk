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

import android.text.TextUtils;
import android.util.Base64;

import androidx.annotation.NonNull;

import com.google.gson.reflect.TypeToken;

import io.getlime.security.powerauth.core.CoreEncryptor;
import io.getlime.security.powerauth.core.SecureData;
import io.getlime.security.powerauth.integration.support.model.SignatureFormat;
import io.getlime.security.powerauth.integration.support.model.SignatureType;
import io.getlime.security.powerauth.sdk.PowerAuthActivationState;
import io.getlime.security.powerauth.sdk.PowerAuthActivationStatus;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.impl.JsonSerialization;
import io.getlime.security.powerauth.networking.response.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.ActivationDetail;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.sdk.PowerAuthActivation;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.system.PowerAuthLog;
import io.getlime.security.powerauth.system.PowerAuthSystem;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class BaseSdkTest {

    @Parameterized.Parameter(0) public String alg;
    @Parameterized.Parameters(name = " {0} ")
    public static Iterable<Object[]> testParameters() {
        return TestParameters.getParameters();
    }

    @PowerAuthAlgorithm
    public int getAlgorithmForTest() {
        return PowerAuthTestHelper.getAlgorithmForName(alg);
    }

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private ActivationHelper activationHelper;

    @Before
    public void setUp() throws Exception {
        PowerAuthLog.setEnabled(true);
        PowerAuthLog.setVerbose(true);
        testHelper = new PowerAuthTestHelper.Builder()
                .powerAuthAlgorithm(getAlgorithmForTest())
                .build();
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
    public void configurationSelfTest() {
        assertEquals(getAlgorithmForTest(), getCurrentAlgorithm());
    }

    @PowerAuthAlgorithm
    public int getCurrentAlgorithm() {
        return powerAuthSDK.getCurrentAlgorithm();
    }

    // Using PowerAuthActivation

    @Test
    public void testCreateWithActivationCode() throws Exception {
        activationHelper.createStandardActivation(false, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateWithActivationCodeAndSignature() throws Exception {
        activationHelper.createStandardActivation(true, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateWithExtraAttributes() throws Exception {
        final String extras = "extra,attributes";
        final ActivationDetail activationDetail = activationHelper.createStandardActivation(true, extras);
        // Validate extras
        assertEquals(extras, activationDetail.getExtras());
        // Validate platform & device info
        assertEquals("android", activationDetail.getPlatform());
        assertEquals(PowerAuthSystem.getDeviceInfo(), activationDetail.getDeviceInfo());
    }

    @Test
    public void testCreateAndPersistWithPassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithPasswordDeprecated() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getValidPassword()));
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(ActivationHelper.extractPlaintextPassword(activationHelper.getInvalidPassword()));
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithCorePassword() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testCreateAndPersistWithCorePasswordDeprecated() throws Exception {
        activationHelper.createStandardActivation(ActivationHelper.TF_PERSIST_WITH_CORE_PASSWORD | ActivationHelper.TF_PERSIST_WITH_DEPRECATED, null);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    // Using legacy method

    @Test
    public void testLegacyCreateWithActivationCode() throws Exception {
        legacyCreateActivation(false);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    @Test
    public void testLegacyCreateWithActivationCodeAndSignature() throws Exception {
        legacyCreateActivation(true);
        // Validate valid and invalid password
        boolean passwordValid = activationHelper.validateUserPassword(activationHelper.getValidPassword());
        assertTrue(passwordValid);
        passwordValid = activationHelper.validateUserPassword(activationHelper.getInvalidPassword());
        assertFalse(passwordValid);
    }

    /**
     * Create activation with using legacy methods (e.g. without PowerAuthActivation object).
     * @param codeWithSignature true if activation should use code and signature.
     * @throws Exception In case of failure.
     */
    private void legacyCreateActivation(boolean codeWithSignature) throws Exception {
        // Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());

        final List<String> passwords = activationHelper.prepareAuthentications();

        // Initialize activation on the server
        final Activation activation = activationHelper.initActivation();

        // Create activation locally
        final String activationCode;
        if (codeWithSignature) {
            activationCode = activation.getActivationCode() + "#" + activation.getActivationSignatureLegacy();
        } else {
            activationCode = activation.getActivationCode();
        }
        final CreateActivationResult createActivationResult = AsyncHelper.await(new AsyncHelper.Execution<CreateActivationResult>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<CreateActivationResult> resultCatcher) throws Exception {
                powerAuthSDK.createActivation(testHelper.getDeviceInfo(), activationCode, new ICreateActivationListener() {
                    @Override
                    public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                        resultCatcher.completeWithResult(result);
                    }

                    @Override
                    public void onActivationCreateFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
                assertFalse(powerAuthSDK.hasValidActivation());
                assertTrue(powerAuthSDK.hasPendingActivation());
                assertFalse(powerAuthSDK.canStartActivation());
            }
        });

        assertFalse(powerAuthSDK.hasValidActivation());
        assertTrue(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Persist activation locally
        boolean persistResult = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), passwords.get(0), new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable error) {
                    resultCatcher.completeWithError(error);
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(persistResult);

        assertTrue(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertFalse(powerAuthSDK.canStartActivation());

        // Fetch status to test whether it's in "pending commit" state.
        final boolean isAutoCommit = testHelper.getTestConfig().isServerAutoCommit();
        final @PowerAuthActivationState int expectedState = isAutoCommit ? PowerAuthActivationState.ACTIVE : PowerAuthActivationState.PENDING_COMMIT;
        PowerAuthActivationStatus activationStatus = activationHelper.fetchActivationStatus();
        if (activationStatus.getState() != expectedState) {
            throw new Exception("Activation is in invalid state after creation. State = " + activationStatus.getState() + ", Expected = " + expectedState);
        }

        // Compare public key fingerprints
        final ActivationDetail activationDetail = activationHelper.getActivationDetail();
        if (!activationDetail.getDevicePublicKeyFingerprint().equals(createActivationResult.getActivationFingerprint())) {
            throw new Exception("Public key fingerprints doesn't match between server and client.");
        }

        // Commit activation on the server.
        if (!isAutoCommit) {
            testHelper.getServerApi().activationCommit(activation);

            // Fetch status to validate whether activation is now active
            activationStatus = activationHelper.fetchActivationStatus();
            if (activationStatus.getState() != PowerAuthActivationState.ACTIVE) {
                throw new Exception("Activation is in invalid state after commit. State = " + activationStatus.getState());
            }
        }
    }

    // Remove activation

    @Test
    public void testRemoveActivationLocal() throws Exception {
        activationHelper.createStandardActivation(true, null);
        // Remove activation
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        // Back to Initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    @Test
    public void testRemoveActivationWithAuthentication() throws Exception {

        activationHelper.createStandardActivation(true, null);

        boolean removed = AsyncHelper.await(resultCatcher -> {
            // Now remove activation
            powerAuthSDK.removeActivationWithAuthentication(testHelper.getContext(), activationHelper.getValidAuthentication(), new IActivationRemoveListener() {
                @Override
                public void onActivationRemoveSucceed() {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onActivationRemoveFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertTrue(removed);

        // Back to initial expectations
        assertFalse(powerAuthSDK.hasValidActivation());
        assertFalse(powerAuthSDK.hasPendingActivation());
        assertTrue(powerAuthSDK.canStartActivation());
    }

    // Activation status

    @Test
    public void testGetActivationStatus() throws Exception {
        activationHelper.createStandardActivation(true, null);
        PowerAuthActivationStatus status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        testHelper.getServerApi().activationBlock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.BLOCKED, status.getState());

        testHelper.getServerApi().activationUnblock(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.ACTIVE, status.getState());

        testHelper.getServerApi().activationRemove(activationHelper.getActivation());
        status = activationHelper.fetchActivationStatus();
        assertEquals(PowerAuthActivationState.REMOVED, status.getState());

        assertNotNull(powerAuthSDK.getLastFetchedActivationStatus());
        powerAuthSDK.removeActivationLocal(testHelper.getContext());
        assertNull(powerAuthSDK.getLastFetchedActivationStatus());
    }

    @Test
    public void testGetActivationStatusConcurrent() throws Exception {
        activationHelper.createStandardActivation(true, null);

        final PowerAuthActivationStatus[] status1 = new PowerAuthActivationStatus[1];
        final PowerAuthActivationStatus[] status2 = new PowerAuthActivationStatus[1];
        final PowerAuthActivationStatus[] status3 = new PowerAuthActivationStatus[1];
        final AtomicInteger counter = new AtomicInteger(0);

        AsyncHelper.await((AsyncHelper.Execution<Boolean>) resultCatcher -> {
            final ICancelable task1, task2, task3, task4;
            task1 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status1[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task1);
            task4 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    fail();
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task4);
            task2 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status2[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task2);
            task3 = powerAuthSDK.fetchActivationStatusWithCallback(testHelper.getContext(), new IActivationStatusListener() {
                @Override
                public void onActivationStatusSucceed(@NonNull PowerAuthActivationStatus status) {
                    status3[0] = status;
                    if (counter.addAndGet(1) == 3) {
                        resultCatcher.completeWithResult(true);
                    }
                }

                @Override
                public void onActivationStatusFailed(@NonNull Throwable t) {
                    fail();
                }
            });
            assertNotNull(task3);
            task4.cancel();
        });
        assertSame(status1[0], status2[0]);
        assertSame(status1[0], status3[0]);
        assertSame(status2[0], status3[0]);
    }

    @Test
    public void testCallToCreateActivationInWrongState() throws Exception {
        activationHelper.createStandardActivation(true, null);

        AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.persistActivationWithPassword(testHelper.getContext(), "1234", new IPersistActivationListener() {
                @Override
                public void onPersistActivationSucceeded() {
                    fail("Operation should not succeed");
                }

                @Override
                public void onPersistActivationFailed(@NonNull Throwable error) {
                    if (error instanceof PowerAuthErrorException) {
                        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, ((PowerAuthErrorException)error).getPowerAuthErrorCode());
                    }
                    resultCatcher.completeWithSuccess();
                }

                @Override
                public void onPersistActivationCancelled(boolean userCancel) {
                    fail("Operation should not be canceled");
                }
            });
        });
        assertTrue(powerAuthSDK.hasValidActivation());

        AsyncHelper.await((AsyncHelper.Execution<Boolean>) resultCatcher -> {
            final PowerAuthActivation activation = PowerAuthActivation.Builder.activation("MMMMM-MMMMM-MMMMM-MUTOA", null).build();
            powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
                @Override
                public void onActivationCreateSucceed(@NonNull CreateActivationResult result) {
                    fail("Create activation should not pass");
                }

                @Override
                public void onActivationCreateFailed(@NonNull Throwable t) {
                    if (t instanceof PowerAuthErrorException) {
                        assertEquals(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, ((PowerAuthErrorException) t).getPowerAuthErrorCode());
                        resultCatcher.completeWithSuccess();
                    } else {
                        fail("Unexpected error received");
                    }
                }
            });
        });
        assertTrue(powerAuthSDK.hasValidActivation());
    }

    // JWT

    @Test
    public void testUserInfo() throws Exception {
        activationHelper.createStandardActivation(true, null);

        final String userId = activationHelper.getUserId();
        assertNotNull(activationHelper.getCreateActivationResult().getUserInfo());
        assertNotNull(powerAuthSDK.getLastFetchedUserInfo());
        assertEquals(userId, powerAuthSDK.getLastFetchedUserInfo().getSubject());
        assertEquals(userId, activationHelper.getCreateActivationResult().getUserInfo().getSubject());

        // Now fetch user info from the server
        UserInfo info = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.fetchUserInfo(testHelper.getContext(), new IUserInfoListener() {
                @Override
                public void onUserInfoSucceed(@NonNull UserInfo userInfo) {
                    resultCatcher.completeWithResult(userInfo);
                }

                @Override
                public void onUserInfoFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
            assertNotNull(task);
        });
        assertEquals(userId, info.getSubject());
        assertEquals(info, powerAuthSDK.getLastFetchedUserInfo());
    }

    @Test
    public void testJwtSignature() throws Exception {
        activationHelper.createStandardActivation(true, null);

        // Get JWT
        final HashMap<String, Object> originalClaims = new HashMap<>();
        originalClaims.put("sub", "1234567890");
        originalClaims.put("name", "John Doe");
        originalClaims.put("admin", true);
        final String jwt = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.signJwtWithDevicePrivateKey(testHelper.getContext(), activationHelper.getValidAuthentication(), originalClaims, new IJwtSignatureListener() {
                @Override
                public void onJwtSignatureSucceed(@NonNull String jwt) {
                    resultCatcher.completeWithResult(jwt);
                }

                @Override
                public void onJwtSignatureFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
            assertNotNull(task);
        });

        // Parse JWT and validate result
        final JsonSerialization jsonSerialization = new JsonSerialization();
        final String[] jwtComponents = TextUtils.split(jwt, "\\.");
        assertEquals(3, jwtComponents.length);
        final String jwtHeader = jwtComponents[0];
        final String jwtClaims = jwtComponents[1];
        final String jwtSignature = jwtComponents[2];
        // Validate header
        Map<String, Object> headerObject = jsonSerialization.deserializeObject(Base64.decode(jwtHeader, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING), new TypeToken<Map<String, Object>>() {});
        assertEquals("JWT", headerObject.get("typ"));
        assertEquals("ES256", headerObject.get("alg"));
        // Validate claims
        Map<String, Object> claimsObject = jsonSerialization.deserializeObject(Base64.decode(jwtClaims, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING), new TypeToken<Map<String, Object>>() {});
        assertEquals(originalClaims.size(), claimsObject.size());
        claimsObject.forEach((key, value) -> {
            assertEquals(originalClaims.get(key), value);
        });
        // Prepare signed data
        final String jwtSignedDatasBase64 = Base64.encodeToString((jwtHeader + "." + jwtClaims).getBytes(StandardCharsets.US_ASCII), Base64.NO_WRAP);
        // Decode signature and encode back to Base64
        final String jwtSignatureBase64 = Base64.encodeToString(
                Base64.decode(jwtSignature, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING),
                Base64.NO_WRAP
        );

        // Validate signature
        // Note that signature format is supported from PAS 1.9+
        boolean result = testHelper.getServerApi().verifyDsaSignature(activationHelper.getActivation().getActivationId(), jwtSignedDatasBase64, jwtSignatureBase64, SignatureFormat.JOSE, SignatureType.ECDSA);
        assertTrue(result);
    }

    @Test
    public void testGetCoreEncryptors() throws Exception {
        CoreEncryptor appEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForApplicationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(appEncryptor);
        assertTrue(appEncryptor.canEncryptRequest());

        boolean success = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForActivationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    assertTrue(encryptor.canEncryptRequest());
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertFalse(success);

        // Now create activation
        activationHelper.createStandardActivation(false, null);

        appEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForApplicationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(appEncryptor);
        assertTrue(appEncryptor.canEncryptRequest());

        CoreEncryptor actEncryptor = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.getEncryptorForActivationScope(new IGetEncryptorListener() {
                @Override
                public void onGetEncryptorSuccess(@NonNull CoreEncryptor encryptor) {
                    resultCatcher.completeWithResult(encryptor);
                }

                @Override
                public void onGetEncryptorFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(actEncryptor);
        assertTrue(actEncryptor.canEncryptRequest());
    }

    @Test
    public void testTemporaryKeyExpiration() throws Exception {
        // This test requires PAS configured for a very short temporary key lifespan.
        activationHelper.createStandardActivation(true, null);

        Boolean result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchEncryptionKey(testHelper.getContext(), activationHelper.getValidAuthentication(), 1000, new IFetchEncryptionKeyListener() {
                @Override
                public void onFetchEncryptionKeySucceed(@NonNull SecureData encryptionKey) {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onFetchEncryptionKeyFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(result);

        Thread.sleep(15_000);
        result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchEncryptionKey(testHelper.getContext(), activationHelper.getValidAuthentication(), 1000, new IFetchEncryptionKeyListener() {
                @Override
                public void onFetchEncryptionKeySucceed(@NonNull SecureData encryptionKey) {
                    resultCatcher.completeWithResult(true);
                }

                @Override
                public void onFetchEncryptionKeyFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithResult(false);
                }
            });
        });
        assertTrue(result);
    }

    @Test
    public void testServerStatus() throws Exception {
        ServerStatus result = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.fetchServerStatus(new IServerStatusListener() {
                @Override
                public void onServerStatusSucceeded(@NonNull ServerStatus status) {
                    resultCatcher.completeWithResult(status);
                }

                @Override
                public void onServerStatusFailed(@NonNull Throwable t) {
                    resultCatcher.completeWithError(t);
                }
            });
        });
        assertNotNull(result);
        System.out.println("Server name: " + result.getApplicationName() + ", version: " + result.getApplicationVersion());
    }
}
