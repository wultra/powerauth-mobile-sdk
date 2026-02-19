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
import androidx.annotation.Nullable;

import android.text.TextUtils;
import android.util.Base64;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.model.Activation;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.integration.support.model.SignatureFormat;
import io.getlime.security.powerauth.integration.support.model.SignatureType;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.model.OfflineSignaturePayload;
import io.getlime.security.powerauth.networking.response.ICreateCertificateSigningRequestListener;
import io.getlime.security.powerauth.networking.response.IDataSignatureListener;
import io.getlime.security.powerauth.networking.response.IDigitalSignatureListener;
import io.getlime.security.powerauth.networking.response.IJwsSignatureListener;
import io.getlime.security.powerauth.networking.response.IJwtSignatureListener;
import io.getlime.security.powerauth.networking.response.IOfflineAuthenticationCodeListener;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthDevicePublicKeyData;
import io.getlime.security.powerauth.sdk.PowerAuthDevicePublicKeyFormat;
import io.getlime.security.powerauth.sdk.PowerAuthSignatureKeyId;
import io.getlime.security.powerauth.sdk.PowerAuthSignatureKeyType;
import io.getlime.security.powerauth.sdk.impl.JsonSerialization;

import static org.junit.Assert.*;

import com.google.gson.reflect.TypeToken;

public class DsaSignatureTest extends BaseTest {

    @Test
    public void testExportDevicePublicKey() throws Exception {
        // Without activation function should fail
        try {
            List<PowerAuthDevicePublicKeyData> keys = powerAuthSDK.exportDevicePublicKeys(PowerAuthDevicePublicKeyFormat.DER);
            fail();
        } catch (PowerAuthErrorException exception) {
            assertEquals(PowerAuthErrorCodes.MISSING_ACTIVATION, exception.getPowerAuthErrorCode());
        }

        // Now create activation
        activationHelper.createStandardActivation(false, null);

        HashMap<Integer, String> keyMapping = new HashMap<>(2);
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.LEGACY_P256:
                keyMapping.put(PowerAuthSignatureKeyType.EC, "P-256");
                break;
            case PowerAuthAlgorithm.EC_P384:
                keyMapping.put(PowerAuthSignatureKeyType.EC, "P-384");
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L3:
                keyMapping.put(PowerAuthSignatureKeyType.EC, "P-384");
                keyMapping.put(PowerAuthSignatureKeyType.ML_DSA, "ML-DSA-65");
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L5:
                keyMapping.put(PowerAuthSignatureKeyType.EC, "P-384");
                keyMapping.put(PowerAuthSignatureKeyType.ML_DSA, "ML-DSA-87");
                break;
            default:
                fail("Unsupported algorithm");
        }

        List<PowerAuthDevicePublicKeyData> keys = powerAuthSDK.exportDevicePublicKeys(PowerAuthDevicePublicKeyFormat.DER);
        int matched = 0;
        for (PowerAuthDevicePublicKeyData keyData : keys) {
            String expectedAlgorithm = keyMapping.get(keyData.getKeyType());
            assertNotNull(expectedAlgorithm);
            assertEquals(expectedAlgorithm, keyData.getKeyAlgorithm());
            matched++;
        }
        assertEquals(keyMapping.size(), matched);

        keys = powerAuthSDK.exportDevicePublicKeys(PowerAuthDevicePublicKeyFormat.RAW);
        matched = 0;
        for (PowerAuthDevicePublicKeyData keyData : keys) {
            String expectedAlgorithm = keyMapping.get(keyData.getKeyType());
            assertNotNull(expectedAlgorithm);
            assertEquals(expectedAlgorithm, keyData.getKeyAlgorithm());
            matched++;
        }
        assertEquals(keyMapping.size(), matched);
    }

    @Test
    public void testActivationCodeSignature() throws Exception {
        activationHelper.createStandardActivation(false, null);
        Activation activation = activationHelper.getActivation();
        final byte[] activationCodeData = activation.getActivationCode().getBytes(StandardCharsets.UTF_8);
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.LEGACY_P256:
                assertNotNull(activation.getActivationSignatureLegacy());
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureLegacy(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                break;
            case PowerAuthAlgorithm.EC_P384:
                assertNotNull(activation.getActivationSignatureEcdsaP384());
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureEcdsaP384(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L3:
                assertNotNull(activation.getActivationSignatureEcdsaP384());
                assertNotNull(activation.getActivationSignatureMlDsa65());
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureEcdsaP384(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureMlDsa65(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_ML_DSA
                );
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L5:
                assertNotNull(activation.getActivationSignatureEcdsaP384());
                assertNotNull(activation.getActivationSignatureMlDsa87());
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureEcdsaP384(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(activation.getActivationSignatureMlDsa87(), Base64.NO_WRAP),
                        activationCodeData,
                        PowerAuthSignatureKeyId.MASTER_ML_DSA
                );
                break;
            default:
                fail("Unsupported algorithm");
                break;
        }
    }

    @Test
    public void testVerifyOfflineServerSignedData() throws Exception {
        OfflineSignaturePayload payload;
        {
            // Verify data signed with master key (non-personalized)
            String dataForSigning = Base64.encodeToString("All your money are belong to us!".getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            // prepare signed data
            payload = testHelper.getServerApi().createNonPersonalizedOfflineSignaturePayload(testHelper.getSharedApplication().getApplicationId(), dataForSigning);
            assertEquals(payload.getParsedData(), dataForSigning);
            assertEquals("0", payload.getParsedSigningKey());
            // verify
            byte[] signedDataBytes = payload.getParsedSignedData().getBytes(StandardCharsets.UTF_8);
            powerAuthSDK.verifyDigitalSignature(
                    Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                    signedDataBytes,
                    PowerAuthSignatureKeyId.MASTER_EC);
            // Bad data
            signedDataBytes[0] ^= 127;
            try {
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                        signedDataBytes,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                fail("Function above must fail");
            } catch (PowerAuthErrorException exception) {
                assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
            }
        }
        // Create activation
        activationHelper.createStandardActivation(false, null);
        Activation activation = activationHelper.getActivation();
        PowerAuthAuthentication authentication = activationHelper.getValidAuthentication();
        {
            // Retry after activation creation
            // Verify data signed with master key (non-personalized)
            String dataForSigning = Base64.encodeToString("All your money are belong to us!".getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            // prepare signed data
            payload = testHelper.getServerApi().createNonPersonalizedOfflineSignaturePayload(testHelper.getSharedApplication().getApplicationId(), dataForSigning);
            assertEquals(payload.getParsedData(), dataForSigning);
            assertEquals("0", payload.getParsedSigningKey());
            // verify
            byte[] signedDataBytes = payload.getParsedSignedData().getBytes(StandardCharsets.UTF_8);
            powerAuthSDK.verifyDigitalSignature(
                    Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                    signedDataBytes,
                    PowerAuthSignatureKeyId.MASTER_EC);
            // Bad data
            signedDataBytes[0] ^= 127;
            try {
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                        signedDataBytes,
                        PowerAuthSignatureKeyId.MASTER_EC
                );
                fail("Function above must fail");
            } catch (PowerAuthErrorException exception) {
                assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
            }
        }
        {
            // Verify data signed with server key (personalized)
            final String expectedSigningKey;
            final int signingKeyId;
            if (getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256) {
                // V3 uses SERVER_EC key for signature
                expectedSigningKey = "1";
                signingKeyId = PowerAuthSignatureKeyId.SERVER_EC;
            } else {
                // V4 uses MAC key
                expectedSigningKey = "2";
                signingKeyId = PowerAuthSignatureKeyId.MAC_PERSONALIZED;
            }
            String dataForSigning = Base64.encodeToString("All your money are belong to us!".getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            // prepare signed data
            payload = testHelper.getServerApi().createPersonalizedOfflineSignaturePayload(activation.getActivationId(), dataForSigning);
            assertEquals(payload.getParsedData(), dataForSigning);
            assertEquals(expectedSigningKey, payload.getParsedSigningKey());
            // verify
            byte[] signedDataBytes = payload.getParsedSignedData().getBytes(StandardCharsets.UTF_8);
            powerAuthSDK.verifyDigitalSignature(
                    Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                    signedDataBytes,
                    signingKeyId
            );
            // Bad data
            signedDataBytes[0] ^= 127;
            try {
                powerAuthSDK.verifyDigitalSignature(
                        Base64.decode(payload.getParsedSignature(), Base64.NO_WRAP),
                        signedDataBytes,
                        signingKeyId
                );
                fail("Function above must fail");
            } catch (PowerAuthErrorException exception) {
                assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
            }
        }
        // Well, we have a data for offline signature, so let's try to verify it.
        String uriId = "/operation/authorize/offline";
        byte[] body = payload.getParsedDataBytes();
        String nonce = payload.getParsedNonce();
        String offlineAuthCode = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.offlineAuthenticationCode(testHelper.getContext(), authentication, uriId, body, nonce, new IOfflineAuthenticationCodeListener() {
                @Override
                public void onOfflineAuthenticationCodeSucceed(@NonNull String authenticationCode) {
                    resultCatcher.completeWithResult(authenticationCode);
                }

                @Override
                public void onOfflineAuthenticationCodeFailed(@NonNull PowerAuthErrorException error) {
                    resultCatcher.completeWithError(error);
                }
            });
        });
        AuthenticationResult authenticationResult = authenticationHelper.verifyAuthenticationCode(
                offlineAuthCode,
                nonce,
                payload.getParsedDataBytes(),
                uriId,
                activationHelper.getActivation().getActivationId(),
                false,
                null
        );
        assertTrue(authenticationResult.isAuthenticationValid());
    }

    /**
     * Function calculates signature with device private key and verifies such signature locally and on the server.
     * @param signatureKeyId Signature key identifier to use.
     * @param signatureType Signature type.
     * @param authentication Authentication object.
     * @param shouldPass If true, test should pass.
     * @throws Exception In case of failure.
     */
    private void verifyDataSignedWithSignatureKeyId(@PowerAuthSignatureKeyId int signatureKeyId, SignatureType signatureType, PowerAuthAuthentication authentication, boolean shouldPass) throws Exception {
        final byte[] dataForSigning = "This is a very sensitive information and must be signed.".getBytes(StandardCharsets.UTF_8);
        byte[] resultSignature = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.calculateDigitalSignature(authentication, dataForSigning, signatureKeyId, new IDigitalSignatureListener() {
                @Override
                public void onDigitalSignatureSucceed(@NonNull byte[] signature) {
                    resultCatcher.completeWithResult(signature);
                }

                @Override
                public void onDigitalSignatureFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithResult(null);
                }
            });
            if (shouldPass) {
                assertNotNull(task);
            }
        });
        if (shouldPass) {
            assertNotNull(resultSignature);
            // Verify on server
            boolean result = testHelper.getServerApi().verifyDsaSignature(
                    Objects.requireNonNull(powerAuthSDK.getActivationIdentifier()),
                    Base64.encodeToString(dataForSigning, Base64.NO_WRAP),
                    Base64.encodeToString(resultSignature, Base64.NO_WRAP),
                    SignatureFormat.DER,
                    signatureType);
            assertTrue(result);
            // Verify locally
            powerAuthSDK.verifyDigitalSignature(resultSignature, dataForSigning, signatureKeyId);
        } else {
            assertNull(resultSignature);
        }
    }

    @Test
    public void testSignDataWithDevicePrivateKey() throws Exception {
        activationHelper.createStandardActivation(false, null);
        PowerAuthAuthentication authentication = activationHelper.getValidAuthentication();
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.EC_P384_ML_L5:
            case PowerAuthAlgorithm.EC_P384_ML_L3:
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE, SignatureType.ECDSA, authentication, false);
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, SignatureType.ECDSA, authentication, true);
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_ML_DSA, SignatureType.MLDSA, authentication, true);
                break;
            case PowerAuthAlgorithm.EC_P384:
            case PowerAuthAlgorithm.LEGACY_P256:
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE, SignatureType.ECDSA, authentication, true);
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, SignatureType.ECDSA, authentication, true);
                verifyDataSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_ML_DSA, SignatureType.MLDSA, authentication, false);
                break;
            default:
                fail("Not supported algorithm");
                break;
        }
    }

    @Test
    public void testVerifyServerSignedData() throws Exception {
        activationHelper.createStandardActivation(false, null);

        final byte[] dataForSigning = "This is a very sensitive information and must be signed.".getBytes(StandardCharsets.UTF_8);
        final byte[] badSignedData  = "This is a very sens1tive information and must be signed.".getBytes(StandardCharsets.UTF_8);
        Map<SignatureType, String> signatures = testHelper.getServerApi().createDsaSignature(
                Objects.requireNonNull(powerAuthSDK.getActivationIdentifier()),
                Base64.encodeToString(dataForSigning, Base64.NO_WRAP));
        final byte[] mldsa = signatures.get(SignatureType.MLDSA) == null ? null : Base64.decode(signatures.get(SignatureType.MLDSA), Base64.NO_WRAP);
        final byte[] ecdsa = signatures.get(SignatureType.ECDSA) == null ? null : Base64.decode(signatures.get(SignatureType.ECDSA), Base64.NO_WRAP);
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.LEGACY_P256:
            case PowerAuthAlgorithm.EC_P384:
                assertNotNull(ecdsa);
                assertNull(mldsa);
                powerAuthSDK.verifyDigitalSignature(ecdsa, dataForSigning, PowerAuthSignatureKeyId.SERVER_EC);
                // bad data
                try {
                    powerAuthSDK.verifyDigitalSignature(ecdsa, badSignedData, PowerAuthSignatureKeyId.SERVER_EC);
                } catch (PowerAuthErrorException exception) {
                    assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
                }
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L5:
            case PowerAuthAlgorithm.EC_P384_ML_L3:
                assertNotNull(ecdsa);
                assertNotNull(mldsa);
                powerAuthSDK.verifyDigitalSignature(ecdsa, dataForSigning, PowerAuthSignatureKeyId.SERVER_EC);
                powerAuthSDK.verifyDigitalSignature(mldsa, dataForSigning, PowerAuthSignatureKeyId.SERVER_ML_DSA);
                // bad data
                try {
                    powerAuthSDK.verifyDigitalSignature(ecdsa, badSignedData, PowerAuthSignatureKeyId.SERVER_EC);
                } catch (PowerAuthErrorException exception) {
                    assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
                }
                try {
                    powerAuthSDK.verifyDigitalSignature(mldsa, badSignedData, PowerAuthSignatureKeyId.SERVER_ML_DSA);
                } catch (PowerAuthErrorException exception) {
                    assertEquals(PowerAuthErrorCodes.WRONG_SIGNATURE, exception.getPowerAuthErrorCode());
                }
                break;
            default:
                fail("Unsupported algorithm");
                break;
        }
    }

    /**
     * Sign data with server private key and verify locally.
     * @param signatureKeyId Key identifier to use for verify.
     * @param signatureType Signature type.
     * @param compactForm Use compact form.
     * @param strict Use strict verify.
     * @param shouldPass If true, test should pass.
     * @throws Exception In case of failure.
     */
    private void verifyJwsServerSignedData(@PowerAuthSignatureKeyId int signatureKeyId, SignatureType signatureType, boolean compactForm, boolean strict, boolean shouldPass) throws Exception {
        final byte[] dataForSigning = "This is a very sensitive information and must be signed.".getBytes(StandardCharsets.UTF_8);

        String jws = testHelper.getServerApi().createJwtSignature(
                Objects.requireNonNull(powerAuthSDK.getActivationIdentifier()),
                Base64.encodeToString(dataForSigning, Base64.NO_WRAP),
                compactForm,
                signatureType);
        try {
            powerAuthSDK.verifyJwsSignature(jws, compactForm, strict, signatureKeyId);
            assertTrue(shouldPass);
        } catch (PowerAuthErrorException exception) {
            assertFalse(shouldPass);
        }
    }

    @Test
    public void testVerifyJwsServerSignedData() throws Exception {
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.LEGACY_P256:
                // not available for legacy activations
                break;
            case PowerAuthAlgorithm.EC_P384:
                activationHelper.createStandardActivation(false, null);
                // JWT
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, true, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, true, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, true, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, true, false, true);
                // JWS
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, false, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, false, false, true);
                // JWT - hybrid (should work, there's only one key available)
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, true, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, true, false, true);
                // JWS - hybrid
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, false, false, true);
                break;
            case PowerAuthAlgorithm.EC_P384_ML_L3:
            case PowerAuthAlgorithm.EC_P384_ML_L5:
                activationHelper.createStandardActivation(false, null);
                // JWT - ecdsa
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, true, true, false); // strict mode require all keys to satisfy
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, true, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, true, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, true, false, true);
                // JWT - mldsa
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.MLDSA, true, true, false); // strict mode require all keys to satisfy
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_ML_DSA,SignatureType.MLDSA, true, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.MLDSA, true, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_ML_DSA,SignatureType.MLDSA, true, false, true);
                // JWS - ecdsa
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, false, true, false); // strict mode require all keys to satisfy
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.ECDSA, false, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_EC,    SignatureType.ECDSA, false, false, true);
                // JWS - mldsa
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.MLDSA, false, true, false); // strict mode require all keys to satisfy
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_ML_DSA,SignatureType.MLDSA, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       SignatureType.MLDSA, false, false, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER_ML_DSA,SignatureType.MLDSA, false, false, true);
                // JWS - hybrid
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, false, true, true);
                verifyJwsServerSignedData(PowerAuthSignatureKeyId.SERVER,       null, false, false, true);
                break;

            default:
                fail("Unsupported algorithm");
                break;
        }
    }

    /**
     * Calculate JWS signature and then verify signature on the server and locally.
     * @param signatureKeyId Key identifier to use for calculation.
     * @param compact Use compact form.
     * @param strict Use strict local verification.
     * @param authentication Authentication object.
     * @param shouldPass If true, then test should pass.
     * @throws Exception In case of failure.
     */
    private void verifyJwsSignedWithSignatureKeyId(@PowerAuthSignatureKeyId int signatureKeyId, boolean compact, boolean strict, PowerAuthAuthentication authentication, boolean shouldPass) throws Exception {
        final byte[] dataForSigning = "This is a very sensitive information and must be signed.".getBytes(StandardCharsets.UTF_8);
        String resultSignature = AsyncHelper.await(resultCatcher -> {
            ICancelable task = powerAuthSDK.calculateJwsSignature(authentication, dataForSigning, null, compact, signatureKeyId, new IJwsSignatureListener() {
                @Override
                public void onJwsSignatureSucceed(@NonNull String signedData, boolean compactForm) {
                    assertEquals(compact, compactForm);
                    resultCatcher.completeWithResult(signedData);
                }

                @Override
                public void onJwsSignatureFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithResult(null);
                }
            });
            if (shouldPass) {
                assertNotNull(task);
            }
        });
        if (shouldPass) {
            assertNotNull(resultSignature);
            // verify signature on the server
            boolean result = testHelper.getServerApi().verifyJwtSignature(Objects.requireNonNull(powerAuthSDK.getActivationIdentifier()), resultSignature, compact);
            assertTrue(result);
            // verify signature locally
            try {
                powerAuthSDK.verifyJwsSignature(resultSignature, compact, strict, signatureKeyId);
            } catch (PowerAuthErrorException exception) {
                assertFalse(shouldPass);
            }
        } else {
            assertNull(resultSignature);
        }
    }

    @Test
    public void testJwsSignDataWithDevicePrivateKey() throws Exception {
        PowerAuthAuthentication authentication;
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.EC_P384_ML_L3:
            case PowerAuthAlgorithm.EC_P384_ML_L5:
                activationHelper.createStandardActivation(false, null);
                authentication = activationHelper.getValidAuthentication();
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_ML_DSA, false, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_ML_DSA, true, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE, false, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, false, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, true, true, authentication, true);
                break;
            case PowerAuthAlgorithm.EC_P384:
                activationHelper.createStandardActivation(false, null);
                authentication = activationHelper.getValidAuthentication();
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE, true, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE, false, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, false, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_EC, true, true, authentication, true);
                verifyJwsSignedWithSignatureKeyId(PowerAuthSignatureKeyId.DEVICE_ML_DSA, false, true, authentication, false);
                break;
            case PowerAuthAlgorithm.LEGACY_P256:
                // API not supported on the server.
                break;
            default:
                fail("Unsupported algorithm");
                break;
        }
    }


    void testCSR(@PowerAuthSignatureKeyId int keyId, @NonNull PowerAuthAuthentication authentication,
                 @NonNull Map<String, String> dn, @Nullable List<String> san, boolean shouldPass) throws Exception {
        String csr = AsyncHelper.await(resultCatcher -> {
            powerAuthSDK.createCertificateSigningRequest(testHelper.getContext(), authentication, dn, san, keyId, new ICreateCertificateSigningRequestListener() {
                @Override
                public void onCreateCertificateSigningRequestSucceed(@NonNull String certificateSigningRequest) {
                    resultCatcher.completeWithResult(certificateSigningRequest);
                }

                @Override
                public void onCreateCertificateSigningRequestFailed(@NonNull Throwable throwable) {
                    resultCatcher.completeWithResult(null);
                }
            });
        });
        if (shouldPass) {
            assertNotNull(csr);
            assertTrue(csr.startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
            assertTrue(csr.endsWith("-----END CERTIFICATE REQUEST-----\n"));
        } else {
            assertNull(csr);
        }
    }

    @Test
    public void testCreateCertificateSigningRequest() throws Exception {
        Map<String, String> dnItems = Map.of(
                "C", "CZ",
                "O", "Example",
                "CN", "example.com"
        );
        List<String> sanItems = List.of("DNS:example.com", "DNS:www.example.com");
        activationHelper.createStandardActivation(false, null);
        PowerAuthAuthentication authentication = activationHelper.getValidAuthentication();
        switch (getAlgorithmForTest()) {
            case PowerAuthAlgorithm.EC_P384_ML_L3:
            case PowerAuthAlgorithm.EC_P384_ML_L5:
                testCSR(PowerAuthSignatureKeyId.DEVICE_EC, authentication,  dnItems, sanItems, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE_EC, authentication,  dnItems, null, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE_ML_DSA, authentication, dnItems, sanItems, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE_ML_DSA, authentication, dnItems, null, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE, authentication, dnItems, sanItems, false);
                testCSR(PowerAuthSignatureKeyId.DEVICE, authentication, dnItems, null, false);
                break;

            case PowerAuthAlgorithm.EC_P384:
            case PowerAuthAlgorithm.LEGACY_P256:
                testCSR(PowerAuthSignatureKeyId.DEVICE_EC, authentication, dnItems, sanItems, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE_EC, authentication, dnItems, null, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE_ML_DSA, authentication, dnItems, sanItems,  false);
                testCSR(PowerAuthSignatureKeyId.DEVICE_ML_DSA, authentication, dnItems, null,  false);
                testCSR(PowerAuthSignatureKeyId.DEVICE, authentication, dnItems, sanItems, true);
                testCSR(PowerAuthSignatureKeyId.DEVICE, authentication, dnItems, null, true);
                break;
            default:
                throw new Exception("Unsupported algorithm");
        }
    }

    // The next tests are using deprecated PowerAuthSDK methods. @Deprecated  // 2.0.0

    @Test
    public void testDeprecated_DeviceSignedData() throws Exception {

        final String testData = "Data signed with device private key: " + testHelper.getRandomGenerator().generateRandomString(10, 32);

        activationHelper.createStandardActivation(true, null);

        final byte[] dataToSign = testData.getBytes(Charset.defaultCharset());
        final byte[] signatureForData = AsyncHelper.await(new AsyncHelper.Execution<byte[]>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<byte[]> resultCatcher) throws Exception {
                ICancelable task = powerAuthSDK.signDataWithDevicePrivateKey(testHelper.getContext(), activationHelper.getValidAuthentication(), dataToSign, new IDataSignatureListener() {
                    @Override
                    public void onDataSignedSucceed(@NonNull byte[] signature) {
                        resultCatcher.completeWithResult(signature);
                    }

                    @Override
                    public void onDataSignedFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
                assertNotNull(task);
            }
        });
        assertNotNull(signatureForData);

        final String dataForVerification = Base64.encodeToString(dataToSign, Base64.NO_WRAP);
        final String signatureForVerification = Base64.encodeToString(signatureForData, Base64.NO_WRAP);

        // Now validate that signature on the server.
        boolean result = testHelper.getServerApi().verifyDsaSignature(activationHelper.getActivation().getActivationId(), dataForVerification, signatureForVerification, SignatureFormat.DER, SignatureType.ECDSA);
        assertTrue(result);
    }

    @Test
    public void testDeprecated_NonPersonalizedServerSignedData() throws Exception {

        final String testData = Base64.encodeToString("All your money are belong to us!".getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);

        final OfflineSignaturePayload payload = testHelper.getServerApi().createNonPersonalizedOfflineSignaturePayload(testHelper.getSharedApplication().getApplicationId(), testData);
        assertNotNull(payload);
        assertNotNull(payload.getData());
        assertNotNull(payload.getNonce());

        List<String> components = Arrays.asList(TextUtils.split(payload.getData(), "\n"));
        assertFalse(components.isEmpty());
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
    public void testDeprecated_PersonalizedServerSignedData() throws Exception {

        activationHelper.createStandardActivation(true, null);

        final String testData = "HELLO\nThis is a test for ECDSA signature signed with server public key\n" + testHelper.getRandomGenerator().generateRandomString(10, 32);

        final OfflineSignaturePayload payload = testHelper.getServerApi().createPersonalizedOfflineSignaturePayload(activationHelper.getActivation().getActivationId(), testData);
        assertNotNull(payload);
        assertNotNull(payload.getData());
        assertNotNull(payload.getNonce());

        List<String> components = Arrays.asList(TextUtils.split(payload.getData(), "\n"));
        assertFalse(components.isEmpty());
        // Extract signature part
        String signatureBase64 = components.get(components.size() - 1).substring(1);  // skip "1" indicating type of signature;
        // Extract signed data part (replaces last component with key type marker)
        components.set(components.size() - 1, "1");
        String dataForSigning = TextUtils.join("\n", components);

        final byte[] signature = Base64.decode(signatureBase64, Base64.NO_WRAP);
        final byte[] signedBytes = dataForSigning.getBytes(Charset.defaultCharset());

        // Only legacy mode should pass, because V4 uses MAC for verification.
        boolean shouldPass = getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256;

        boolean signatureValid = powerAuthSDK.verifyServerSignedData(signedBytes, signature, false);
        assertEquals(shouldPass, signatureValid);

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

    @Test
    public void testDeprecated_JwtSignature() throws Exception {
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
        String expectedAlgorithm = getAlgorithmForTest() == PowerAuthAlgorithm.LEGACY_P256 ? "ES256" : "ES384";
        Map<String, Object> headerObject = jsonSerialization.deserializeObject(Base64.decode(jwtHeader, Base64.NO_WRAP | Base64.URL_SAFE | Base64.NO_PADDING), new TypeToken<Map<String, Object>>() {});
        assertEquals("JWT", headerObject.get("typ"));
        assertEquals(expectedAlgorithm, headerObject.get("alg"));
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
}
