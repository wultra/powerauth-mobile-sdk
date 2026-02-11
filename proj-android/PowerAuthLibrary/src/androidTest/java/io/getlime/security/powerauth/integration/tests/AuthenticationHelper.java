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

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import io.getlime.security.powerauth.integration.support.AsyncHelper;
import io.getlime.security.powerauth.integration.support.PowerAuthTestHelper;
import io.getlime.security.powerauth.integration.support.model.AuthCodeType;
import io.getlime.security.powerauth.integration.support.model.AuthenticationCodeData;
import io.getlime.security.powerauth.integration.support.model.AuthenticationResult;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthHttpHeader;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AuthenticationHelper {

    @NonNull
    final PowerAuthTestHelper testHelper;

    /**
     * Create helper with test helper object.
     * @param helper {@link PowerAuthTestHelper} instance.
     */
    public AuthenticationHelper(@NonNull PowerAuthTestHelper helper) {
        testHelper = helper;
    }

    /**
     * Normalize data for online signature verification.
     * @param body Request body bytes.
     * @param method Request method.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    public @NonNull String normalizeOnlineData(@Nullable byte[] body, @NonNull String method, @NonNull String uriId, @NonNull String nonce) {
        return normalizeImpl(body, method, uriId, nonce);
    }

    /**
     * Normalize data for offline signature verification.
     * @param body Request body bytes.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    public @NonNull String normalizeOfflineData(@Nullable byte[] body, @NonNull String uriId, @NonNull String nonce) {
        return normalizeImpl(body, "POST", uriId, nonce);
    }

    /**
     * Normalize data for any signature verification.
     * @param body Request body bytes.
     * @param method Request method.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    private @NonNull String normalizeImpl(@Nullable byte[] body, @NonNull String method, @NonNull String uriId, @NonNull String nonce) {
        if (body == null) {
            body = new byte[0];
        }
        String uriIdB64 = Base64.encodeToString(uriId.getBytes(Charset.defaultCharset()), Base64.NO_WRAP);
        String bodyB64 = Base64.encodeToString(body, Base64.NO_WRAP);
        return method + "&" + uriIdB64 + "&" + nonce + "&" + bodyB64;
    }

    /**
     * Parse signature header into map of key-value components.
     * @param header Token header.
     * @return Key-Value components.
     */
    public @NonNull Map<String, String> parseAuthenticationHeader(@NonNull PowerAuthHttpHeader header) {
        String value = header.getValue();
        assertNotNull(value);
        assertTrue(value.startsWith("PowerAuth "));
        value = value.substring(10);
        Map<String, String> components = new HashMap<>();
        for (String component : TextUtils.split(value, ",")) {
            component = component.trim();
            int equalSign = component.indexOf("=");
            assertTrue(equalSign > 0);
            // acquire value
            String componentKey = component.substring(0, equalSign);
            String componentValue = component.substring(equalSign + 1);
            assertTrue(componentValue.startsWith("\""));
            assertTrue(componentValue.endsWith("\""));
            componentValue = componentValue.substring(1, componentValue.length() - 1);
            components.put(componentKey, componentValue);
        }
        return components;
    }

    /**
     * Verify authentication header on the server.
     * @param header Authentication header.
     * @param body Request body.
     * @param uriId URI identifier.
     * @param method HTTP method (e.g. POST, GET, ...)
     * @return {@link AuthenticationResult} object.
     * @throws Exception In case of failure.
     */
    public AuthenticationResult verifyAuthenticationHeader(@NonNull PowerAuthHttpHeader header,
                                                           @Nullable byte[] body,
                                                           @NonNull String uriId,
                                                           @NonNull String method) throws Exception {
        // Parse header
        Map<String, String> headerData = parseAuthenticationHeader(header);
        // Extract variables
        final String acVersion = headerData.get("pa_version");
        final String acActivationId = headerData.get("pa_activation_id");
        final String acNonce = headerData.get("pa_nonce");
        final String acAppKey = headerData.get("pa_application_key");
        final String acType;
        final String acValue;
        assertNotNull(acVersion);
        if (PowerAuthTestHelper.PA_VERSION3_HEADER.equals(acVersion)) {
            acType = Objects.requireNonNull(headerData.get("pa_signature_type")).toUpperCase();
            acValue = headerData.get("pa_signature");
        } else if (PowerAuthTestHelper.PA_VERSION4_HEADER.equals(acVersion)) {
            acType = Objects.requireNonNull(headerData.get("pa_auth_code_type")).toUpperCase();
            acValue = headerData.get("pa_auth_code");
        } else {
            throw new Exception("Unsupported protocol version " + acVersion);
        }
        assertNotNull(acActivationId);
        assertNotNull(acNonce);
        assertNotNull(acAppKey);
        assertNotNull(acType);
        assertNotNull(acValue);

        // Now verify signature on the server
        final String dataToVerifySignature = normalizeOnlineData(body, method, uriId, acNonce);
        AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
        authenticationCodeData.setActivationId(acActivationId);
        authenticationCodeData.setData(dataToVerifySignature);
        authenticationCodeData.setAuthenticationCode(acValue);
        authenticationCodeData.setAuthenticationCodeType(AuthCodeType.valueOf(acType));
        authenticationCodeData.setAuthenticationVersion(acVersion);
        authenticationCodeData.setApplicationKey(acAppKey);

        // Verify on server
        return testHelper.getServerApi().verifyOnlineAuthenticationCode(authenticationCodeData);
    }

    /**
     * Verify offline authentication code.
     * @param authenticationCode Authentication code.
     * @param offlineNonce Offline nonce.
     * @param body Authenticated data.
     * @param uriId URI identifier.
     * @param activationId Activation identifier.
     * @param allowBiometry If true, then authentication with biometry is allowed.
     * @param authComponentLength Optional authentication code component length.
     * @return {@link AuthenticationResult} object.
     * @throws Exception In case of failure.
     */
    public AuthenticationResult verifyAuthenticationCode(@NonNull String authenticationCode,
                                                         @NonNull String offlineNonce,
                                                         @Nullable byte[] body,
                                                         @NonNull String uriId,
                                                         @NonNull String activationId,
                                                         boolean allowBiometry,
                                                         Long authComponentLength) throws Exception {
        final String dataToVerifySignature = normalizeOfflineData(body, uriId, offlineNonce);
        AuthenticationCodeData authenticationCodeData = new AuthenticationCodeData();
        authenticationCodeData.setActivationId(activationId);
        authenticationCodeData.setData(dataToVerifySignature);
        authenticationCodeData.setAuthenticationCode(authenticationCode);
        authenticationCodeData.setAllowBiometry(allowBiometry);
        authenticationCodeData.setOfflineAuthenticationCodeComponentLength(authComponentLength);

        return testHelper.getServerApi().verifyOfflineAuthenticationCode(authenticationCodeData);
    }
}
