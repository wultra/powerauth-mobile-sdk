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

package io.getlime.security.powerauth.core.response;

import androidx.annotation.NonNull;

/**
 * The {@code RespServerStatus} class contains information about PowerAuth Server's status.
 */
public class CoreServerStatus {
    /**
     * Time on the server.
     */
    private final long serverTime;
    /**
     * Application's name (for example: "enrollment-server")
     */
    private final String applicationName;
    /**
     * Application's version (for example: "2.0.0")
     */
    private final String applicationVersion;

    /**
     * Construct status object with all required parameters
     * @param serverTime Time on the server represented as Unix timestamp with milliseconds precision.
     * @param applicationName Server application's name (e.g. "enrollment-server").
     * @param applicationVersion Server application's version (e.g. "2.0.0").
     *
     */
    public CoreServerStatus(long serverTime, @NonNull String applicationName, @NonNull String applicationVersion) {
        this.serverTime = serverTime;
        this.applicationName = applicationName;
        this.applicationVersion = applicationVersion;
    }

    /**
     * @return Time on the server represented as Unix timestamp with milliseconds precision.
     */
    public long getServerTime() {
        return serverTime;
    }

    /**
     * @return Server application's name (for example: "enrollment-server".)
     */
    @NonNull
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * @return Server application's version (for example: "2.0.0".)
     */
    @NonNull
    public String getApplicationVersion() {
        return applicationVersion;
    }
}
