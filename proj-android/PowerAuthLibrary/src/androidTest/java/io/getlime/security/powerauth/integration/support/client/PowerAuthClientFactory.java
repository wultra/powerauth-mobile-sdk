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

package io.getlime.security.powerauth.integration.support.client;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.integration.support.PowerAuthServerApi;
import io.getlime.security.powerauth.integration.support.PowerAuthTestConfig;
import io.getlime.security.powerauth.integration.support.model.ServerVersion;

/**
 * The {@code PowerAuthClientFactory} provides client that communicate with PowerAuth Server API,
 * depending on the version of the server.
 */
public class PowerAuthClientFactory {

    /**
     * Create instance of {@link PowerAuthServerApi} class that provide communication with PowerAuth
     * Server.
     *
     * @param testConfig Test configuration that contains value for an expected version of server.
     * @return Instance of {@link PowerAuthServerApi}.
     * @throws Exception In case that connection to server is invalid or API object cannot be constructed.
     */
    public PowerAuthServerApi createApiClient(@NonNull PowerAuthTestConfig testConfig) throws Exception {
        PowerAuthServerApi api = null;
        if (testConfig.getServerVersion().numericVersion >= ServerVersion.V1_0_0.numericVersion &&
                testConfig.getServerVersion().numericVersion <= ServerVersion.LATEST.numericVersion) {
            api = new PowerAuthClientV3(testConfig.getServerApiUrl(), testConfig.getAuthorizationHeaderValue(), null, null);
        }
        if (api == null) {
            throw new Exception("Missing implementation for server API, for server version " + testConfig.getServerVersion().version);
        }
        api.validateConnection();
        return api;
    }
}
