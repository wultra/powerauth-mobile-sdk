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

package io.getlime.security.powerauth.integration.support.model;

import androidx.annotation.NonNull;

import java.util.Collections;
import java.util.Map;

public class Activation {

    public static final String SIG_ES256 = "ES256";
    public static final String SIG_ES384 = "ES384";
    public static final String SIG_ML_DSA_65 = "ML-DSA-65";
    public static final String SIG_ML_DSA_87 = "ML-DSA-87";


    private String activationCode;
    private @NonNull String activationId = "INVALID_ID";
    private Map<String, String> activationSignatures = Collections.emptyMap();
    private String applicationId;
    private String userId;

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    @NonNull
    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(@NonNull String activationId) {
        this.activationId = activationId;
    }

    public String getActivationSignatureLegacy() {
        return activationSignatures.get(SIG_ES256);
    }
    public String getActivationSignatureEcdsaP384() {
        return activationSignatures.get(SIG_ES384);
    }

    public String getActivationSignatureMlDsa65() {
        return activationSignatures.get(SIG_ML_DSA_65);
    }

    public String getActivationSignatureMlDsa87() {
        return activationSignatures.get(SIG_ML_DSA_87);
    }

    public void setActivationSignatures(Map<String, String> activationSignatures) {
        this.activationSignatures = activationSignatures;
    }

    public Map<String, String> getActivationSignatures() {
        return activationSignatures;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
