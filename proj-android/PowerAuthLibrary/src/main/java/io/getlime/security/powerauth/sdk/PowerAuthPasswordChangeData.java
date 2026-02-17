/*
 * Copyright 2026 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import androidx.annotation.NonNull;

import io.getlime.security.powerauth.core.Password;

/**
 * Object representing data for the second step of the two-step password change operation.
 */
public class PowerAuthPasswordChangeData {

    @NonNull
    private final Password oldPassword;

    PowerAuthPasswordChangeData(@NonNull final Password oldPassword) {
        this.oldPassword = oldPassword;
    }

    /**
     * Get the old password.
     * @return The {@link Password} object holding the old password.
     */
    @NonNull
    public Password getOldPassword() {
        return oldPassword;
    }

    /**
     * Clear sensitive data stored in the object.
     */
    public void secureClear() {
        oldPassword.clear();
    }

}
