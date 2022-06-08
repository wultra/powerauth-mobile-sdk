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

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.SignatureType;
import io.getlime.security.powerauth.integration.support.model.TokenInfo;
import io.getlime.security.powerauth.networking.exceptions.ErrorResponseApiException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.IGetTokenListener;
import io.getlime.security.powerauth.networking.response.IRemoveTokenListener;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthAuthorizationHttpHeader;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.sdk.PowerAuthToken;
import io.getlime.security.powerauth.sdk.PowerAuthTokenStore;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class TokenStoreTest {

    private PowerAuthTestHelper testHelper;
    private PowerAuthSDK powerAuthSDK;
    private PowerAuthTokenStore tokenStore;
    private ActivationHelper activationHelper;
    private SignatureHelper signatureHelper;

    private static final String TOKEN_NAME_POSSESSION = "TestToken_POSSESSION";
    private static final String TOKEN_NAME_POSSESSION_KNOWLEDGE = "TestToken_POSSESSION_KNOWLEDGE";
    private static final String TOKEN_NAME_OTHER = "TestToken_OTHER";

    @Before
    public void setUp() throws Exception {
        testHelper = new PowerAuthTestHelper.Builder().build();
        powerAuthSDK = testHelper.getSharedSdk();
        tokenStore = powerAuthSDK.getTokenStore();
        activationHelper = new ActivationHelper(testHelper);
        signatureHelper = new SignatureHelper();
    }

    @After
    public void tearDown() {
        if (activationHelper != null) {
            activationHelper.cleanupAfterTest();
        }
    }

    @Test(expected = PowerAuthErrorException.class)
    public void testCreateTokenWithNoActivation() throws Throwable {
        assertFalse(tokenStore.hasLocalToken(testHelper.getContext(), TOKEN_NAME_POSSESSION));
        try {
            requestAccessToken(TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), true);
        } catch (Exception ex) {
            if (ex.getCause() != null) {
                throw ex.getCause();
            }
            throw ex;
        }
    }

    @Test
    public void testCreateAndRemoveToken() throws Exception {

        final Context context = testHelper.getContext();

        assertFalse(tokenStore.canRequestForAccessToken());

        activationHelper.createStandardActivation(true, null);

        assertTrue(tokenStore.canRequestForAccessToken());

        // Possession
        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION));
        PowerAuthToken token1 = requestAccessToken(TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), true);
        assertNotNull(token1);
        assertEquals(TOKEN_NAME_POSSESSION, token1.getTokenName());
        assertTrue(token1.isValid());
        assertTrue(token1.canGenerateHeader());
        assertTrue(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION));

        assertTrue(calculateAndValidateTokenDigest(token1, SignatureType.POSSESSION));

        // Possession + Knowledge
        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE));
        PowerAuthToken token2 = requestAccessToken(TOKEN_NAME_POSSESSION_KNOWLEDGE, activationHelper.getValidAuthentication(), true);
        assertNotNull(token2);
        assertEquals(TOKEN_NAME_POSSESSION_KNOWLEDGE, token2.getTokenName());
        assertTrue(token2.isValid());
        assertTrue(token2.canGenerateHeader());
        assertTrue(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE));

        assertTrue(calculateAndValidateTokenDigest(token2, SignatureType.POSSESSION_KNOWLEDGE));

        // Invalid password
        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_OTHER));
        assertNull(requestAccessToken(TOKEN_NAME_OTHER, activationHelper.getInvalidAuthentication(), false));

        // Remove tokens
        removeAccessToken(TOKEN_NAME_POSSESSION);
        removeAccessToken(TOKEN_NAME_POSSESSION_KNOWLEDGE);

        // Remove activation and test token validity.
        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION));
        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE));

        // Now remove activation, to invalidate also already acquired objects.
        powerAuthSDK.removeActivationLocal(context);

        assertFalse(tokenStore.canRequestForAccessToken());
        assertFalse(token1.canGenerateHeader());
        assertFalse(token2.canGenerateHeader());
    }

    @Test
    public void testGroupedCreateTokenRequests() throws Exception {
        final Context context = testHelper.getContext();
        activationHelper.createStandardActivation(true, null);

        final PowerAuthToken[] token1 = {null};
        final PowerAuthToken[] token2 = {null};
        final PowerAuthToken[] token3 = {null};
        final PowerAuthToken[] token4 = {null};
        final PowerAuthToken[] token5 = {null};

        AsyncHelper.await(new AsyncHelper.Execution<Boolean>() {

            @Override
            public void execute(final @NonNull AsyncHelper.ResultCatcher<Boolean> resultCatcher) throws Exception {
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        token1[0] = token;
                        complete(resultCatcher);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        complete(resultCatcher);
                    }
                });
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        token2[0] = token;
                        complete(resultCatcher);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        complete(resultCatcher);
                    }
                });
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE, activationHelper.getValidAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        token4[0] = token;
                        complete(resultCatcher);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        complete(resultCatcher);
                    }
                });
                ICancelable task = tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        fail();
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        fail();
                    }
                });
                if (task != null) {
                    task.cancel();
                }
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        token3[0] = token;
                        complete(resultCatcher);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        complete(resultCatcher);
                    }
                });
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE, activationHelper.getValidAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        token5[0] = token;
                        complete(resultCatcher);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        complete(resultCatcher);
                    }
                });
                // Try to create token with different auth when the grouped request is pending
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION_KNOWLEDGE, activationHelper.getPossessionAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        fail();
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, ((PowerAuthErrorException)t).getPowerAuthErrorCode());
                        complete(resultCatcher);
                    }
                });
            }

            // Await completion

            int responseCount = 0;
            final int maxResponseCount = 6;

            synchronized void complete(AsyncHelper.ResultCatcher<Boolean> resultCatcher) {
                responseCount++;
                if (responseCount >= maxResponseCount) {
                    resultCatcher.completeWithResult(true);
                }
            }

        });
        assertNotNull(token1[0]);
        assertNotNull(token2[0]);
        assertNotNull(token3[0]);
        assertNotNull(token4[0]);
        assertNotNull(token5[0]);
        assertEquals(token1[0], token2[0]);
        assertEquals(token1[0], token3[0]);
        assertEquals(token2[0], token2[0]);
        assertEquals(token4[0], token5[0]);
        assertNotEquals(token1[0], token4[0]);
    }

    @Test
    public void testCreateTokenRequestsWithDifferentAuth() throws Exception {
        final Context context = testHelper.getContext();
        activationHelper.createStandardActivation(true, null);

        assertFalse(tokenStore.hasLocalToken(context, TOKEN_NAME_POSSESSION));
        PowerAuthToken token1 = requestAccessToken(TOKEN_NAME_POSSESSION, activationHelper.getPossessionAuthentication(), true);
        assertNotNull(token1);

        // Try to create token with different auth when the token is already cached
        AsyncHelper.await(new AsyncHelper.Execution<Boolean>() {

            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Boolean> resultCatcher) throws Exception {
                tokenStore.requestAccessToken(context, TOKEN_NAME_POSSESSION, activationHelper.getValidAuthentication(), new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        fail();
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        assertEquals(PowerAuthErrorCodes.WRONG_PARAMETER, ((PowerAuthErrorException)t).getPowerAuthErrorCode());
                        resultCatcher.completeWithResult(true);
                    }
                });
            }
        });
    }


    /**
     * Request access token with using PowerAuthTokenStore.
     * @param tokenName Name of token.
     * @param authentication Authentication object.
     * @param throwOnAuthError If false, then method doesn't throw an error on authentication failure.
     * @return {@link PowerAuthToken} or null in case of authentication error and {@code throwOnAuthError} is false.
     * @throws Exception In case of failure.
     */
    private @Nullable PowerAuthToken requestAccessToken(@NonNull final String tokenName, @NonNull final PowerAuthAuthentication authentication, final boolean throwOnAuthError) throws Exception {
        return AsyncHelper.await(new AsyncHelper.Execution<PowerAuthToken>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<PowerAuthToken> resultCatcher) throws Exception {
                tokenStore.requestAccessToken(testHelper.getContext(), tokenName, authentication, new IGetTokenListener() {
                    @Override
                    public void onGetTokenSucceeded(@NonNull PowerAuthToken token) {
                        resultCatcher.completeWithResult(token);
                    }

                    @Override
                    public void onGetTokenFailed(@NonNull Throwable t) {
                        if (t instanceof ErrorResponseApiException) {
                            final ErrorResponseApiException apiException = (ErrorResponseApiException) t;
                            if (apiException.getResponseCode() == 401 && !throwOnAuthError) {
                                // Ignore error and report null.
                                resultCatcher.completeWithResult(null);
                                return;
                            }
                        }
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
    }

    /**
     * Removes access token from server and local token store.
     * @param tokenName Token to be removed.
     * @throws Exception In case of failure.
     */
    private void removeAccessToken(@NonNull final String tokenName) throws Exception {
        AsyncHelper.await(new AsyncHelper.Execution<Void>() {
            @Override
            public void execute(@NonNull final AsyncHelper.ResultCatcher<Void> resultCatcher) throws Exception {
                tokenStore.removeAccessToken(testHelper.getContext(), tokenName, new IRemoveTokenListener() {
                    @Override
                    public void onRemoveTokenSucceeded() {
                        resultCatcher.completeWithSuccess();
                    }

                    @Override
                    public void onRemoveTokenFailed(@NonNull Throwable t) {
                        resultCatcher.completeWithError(t);
                    }
                });
            }
        });
    }

    /**
     * Calculate and validate token digest.
     *
     * @param token Token to be tested.
     * @param expectedSignatureType Expected signature type.
     * @return Always return true.
     * @throws Exception In case of failure.
     */
    private boolean calculateAndValidateTokenDigest(@NonNull PowerAuthToken token, @NonNull SignatureType expectedSignatureType) throws Exception {
        assertTrue(token.canGenerateHeader());
        PowerAuthAuthorizationHttpHeader header = token.generateHeader();
        assertTrue(header.isValid());
        assertEquals("X-PowerAuth-Token", header.getKey());
        Map<String, String> headerComponents = signatureHelper.parseAuthorizationHeader(header);
        // Validate values
        assertEquals(testHelper.getProtocolVersionForHeader(), headerComponents.get("version"));
        assertEquals(token.getTokenIdentifier(), headerComponents.get("token_id"));

        String tokenId = Objects.requireNonNull(headerComponents.get("token_id"));
        long timestamp = Long.parseLong(Objects.requireNonNull(headerComponents.get("timestamp")));
        String nonce = Objects.requireNonNull(headerComponents.get("nonce"));
        String digest = Objects.requireNonNull(headerComponents.get("token_digest"));

        TokenInfo tokenInfo = testHelper.getServerApi().validateToken(tokenId, digest, nonce, timestamp);
        assertNotNull(tokenInfo);
        assertTrue(tokenInfo.isTokenValid());
        assertEquals(expectedSignatureType, tokenInfo.getSignatureType());
        return true;
    }
}
