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

package io.getlime.security.powerauth.ecies;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

public class ECIESMetaData {

    private final @NonNull String applicationKey;
    private final @Nullable String activationIdentifier;

    public ECIESMetaData(@NonNull String applicationKey, @Nullable String activationIdentifier) {
        this.applicationKey = applicationKey;
        this.activationIdentifier = activationIdentifier;
    }

    // Getters

    public @NonNull String getActivationKey() {
        return applicationKey;
    }

    public @Nullable String getActivationIdentifier() {
        return activationIdentifier;
    }

    // HTTP header

    public @NonNull String getHttpHeaderKey() {
        return "X-PowerAuth-Encryption";
    }

    public @NonNull String getHttpHeaderValue() {
        final String result = "PowerAuth version=\"3.0\" application_key=\"" + applicationKey + "\"";
        if (activationIdentifier != null) {
            return result + " activation_id=\"" + activationIdentifier + "\"";
        }
        return result;
    }

}
