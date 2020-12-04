/*
 * Copyright 2018 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.interceptors;

import androidx.annotation.NonNull;
import android.util.Base64;

import java.nio.charset.Charset;

/**
 * The {@code BasicHttpAuthenticationRequestInterceptor} class implements Basic HTTP Authentication.
 * You can construct this object with username and password if your PowerAuth REST API requires
 * an additional authentication. Then, you can set the created interceptor to the list of interceptors
 * available in the {@link io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration} class.
 */
public class BasicHttpAuthenticationRequestInterceptor extends CustomHeaderRequestInterceptor {

    /**
     * Constructs object for given username and password.
     *
     * @param username String with username
     * @param password String with password
     */
    public BasicHttpAuthenticationRequestInterceptor(@NonNull String username, @NonNull String password) {
        super("Authorization", buildHeaderValue(username, password));
    }

    /**
     * Builds a Basic HTTP Authentication header's value for given username and password.
     *
     * @param username String with username
     * @param password String with password
     * @return Value for Basic HTTP Authentication header
     */
    private static @NonNull String buildHeaderValue(@NonNull String username, @NonNull String password) {
        final byte[] payload = (username + ":" + password).getBytes(Charset.defaultCharset());
        return "Basic " + Base64.encodeToString(payload, Base64.NO_WRAP);
    }
}
