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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The {@code EciesMetadata} object represents an additional data associated to the ECIES encryptor.
 * The content stored in this object is typically required for the correct HTTP request &amp;
 * response processing, but is not involved in the actual data encryption.
 */
public class EciesMetadata {

    private final @NonNull String applicationKey;
    private final @NonNull String temporaryKeyId;
    private final @Nullable String activationIdentifier;

    /**
     * @param applicationKey Base64 string with an application key cryptographic constant
     * @param temporaryKeyId Temporary encryption key identifier
     * @param activationIdentifier String with an activation identifier
     */
    public EciesMetadata(@NonNull String applicationKey, @NonNull String temporaryKeyId, @Nullable String activationIdentifier) {
        this.applicationKey = applicationKey;
        this.temporaryKeyId = temporaryKeyId;
        this.activationIdentifier = activationIdentifier;
    }

    // Getters

    /**
     * @return Base64 string with an application key cryptographic constant.
     */
    public @NonNull String getActivationKey() {
        return applicationKey;
    }

    /**
     * @return Application key identifier.
     */
    public @NonNull String getApplicationKey() {
        return applicationKey;
    }

    /**
     * @return Base64 String with an activation identifier.
     */
    public @Nullable String getActivationIdentifier() {
        return activationIdentifier;
    }

    /**
     * @return Identifier of temporary key.
     */
    public @NonNull String getTemporaryKeyId() {
        return temporaryKeyId;
    }

    // HTTP header

    /**
     * @return String with HTTP request header's key.
     */
    public @NonNull String getHttpHeaderKey() {
        return "X-PowerAuth-Encryption";
    }

    /**
     * @return String with HTTP request header's value.
     */
    public @NonNull String getHttpHeaderValue() {
        final String result = "PowerAuth version=\"3.3\" application_key=\"" + applicationKey + "\"";
        if (activationIdentifier != null) {
            return result + " activation_id=\"" + activationIdentifier + "\"";
        }
        return result;
    }

}
