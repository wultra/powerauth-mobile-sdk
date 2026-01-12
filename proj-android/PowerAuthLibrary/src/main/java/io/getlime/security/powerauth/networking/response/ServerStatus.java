/*
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.response.CoreServerStatus;

public class ServerStatus {

    private final long serverTime;
    @NonNull private final String applicationName;
    @NonNull private final String applicationVersion;

    public ServerStatus(@NonNull CoreServerStatus response) {
        this.serverTime = response.getServerTime();
        this.applicationName = response.getApplicationName();
        this.applicationVersion = response.getApplicationVersion();
    }

    /**
     * Get server time in milliseconds since 1.1.1970.
     * @return Server time in milliseconds since 1.1.1970.
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
