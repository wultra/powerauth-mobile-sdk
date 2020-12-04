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
import android.text.TextUtils;
import android.util.Base64;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import io.getlime.security.powerauth.sdk.PowerAuthAuthorizationHttpHeader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SignatureHelper {

    /**
     * Normalize data for online signature verification.
     * @param body Request body bytes.
     * @param method Request method.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    public @NonNull String normalizeOnlineData(@NonNull byte[] body, @NonNull String method, @NonNull String uriId, @NonNull String nonce) {
        return normalizeImpl(body, method, uriId, nonce);
    }

    /**
     * Normalize data for online signature verification.
     * @param body Request body bytes.
     * @param method Request method.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    public @NonNull String normalizeOnlineData(@NonNull String body, @NonNull String method, @NonNull String uriId, @NonNull String nonce) {
        return normalizeImpl(body.getBytes(Charset.defaultCharset()), method, uriId, nonce);
    }

    /**
     * Normalize data for offline signature verification.
     * @param body Request body bytes.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    public @NonNull String normalizeOfflineData(@NonNull String body, @NonNull String uriId, @NonNull String nonce) {
        return normalizeImpl(body.getBytes(Charset.defaultCharset()), "POST", uriId, nonce);
    }

    /**
     * Normalize data for any signature verification.
     * @param body Request body bytes.
     * @param method Request method.
     * @param uriId URI identifier.
     * @param nonce Random nonce.
     * @return Normalized string.
     */
    private @NonNull String normalizeImpl(@NonNull byte[] body, @NonNull String method, @NonNull String uriId, @NonNull String nonce) {
        String uriIdB64 = Base64.encodeToString(uriId.getBytes(Charset.defaultCharset()), Base64.NO_WRAP);
        String bodyB64 = Base64.encodeToString(body, Base64.NO_WRAP);
        return method + "&" + uriIdB64 + "&" + nonce + "&" + bodyB64;
    }

    /**
     * Parse signature header into map of key-value components.
     * @param header Token header.
     * @return Key-Value components.
     */
    public @NonNull Map<String, String> parseAuthorizationHeader(@NonNull PowerAuthAuthorizationHttpHeader header) {
        String value = header.value;
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
}
