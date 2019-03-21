/*
 * Copyright 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.networking.model.request;

/**
 * Request object for confirm recovery code ECIES payload.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ConfirmRecoveryRequestPayload {

    private String recoveryCode;

    /**
     * Get recovery code.
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }
}