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
import io.getlime.security.powerauth.integration.support.v10.PowerAuthClientV3_ServerV10;
import io.getlime.security.powerauth.integration.support.v13.PowerAuthClientV3_ServerV13;
import io.getlime.security.powerauth.integration.support.v15.PowerAuthClientV3_ServerV15;
import io.getlime.security.powerauth.integration.support.v19.PowerAuthClientV3_ServerV19;

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
        final int numVer = testConfig.getServerVersion().numericVersion;
        if (numVer >= ServerVersion.V1_0_0.numericVersion && numVer < ServerVersion.V1_3_0.numericVersion) {
            api = new PowerAuthClientV3_ServerV10(testConfig.getServerApiUrl(), testConfig.getAuthorizationHeaderValue(), ServerVersion.V1_0_0, ServerVersion.V1_2_5);
        } else if (numVer >= ServerVersion.V1_3_0.numericVersion && numVer < ServerVersion.V1_5_0.numericVersion) {
            api = new PowerAuthClientV3_ServerV13(testConfig.getServerApiUrl(), testConfig.getAuthorizationHeaderValue(), ServerVersion.V1_3_0, ServerVersion.V1_4_0);
        } else if (numVer >= ServerVersion.V1_5_0.numericVersion && numVer <= ServerVersion.V1_8_0.numericVersion) {
            api = new PowerAuthClientV3_ServerV15(testConfig.getServerApiUrl(), testConfig.getAuthorizationHeaderValue(), ServerVersion.V1_5_0, ServerVersion.V1_8_0);
        } else if (numVer >= ServerVersion.V1_9_0.numericVersion && numVer <= ServerVersion.LATEST.numericVersion) {
            api = new PowerAuthClientV3_ServerV19(testConfig.getServerApiUrl(), testConfig.getAuthorizationHeaderValue(), ServerVersion.V1_9_0, null);
        }
        if (api == null) {
            throw new Exception("Missing implementation for server API, for server version " + testConfig.getServerVersion().version);
        }
        api.validateConnection();
        return api;
    }
}
