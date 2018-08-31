/*
 * Copyright 2017 Wultra s.r.o.
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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.Map;

/**
 * Interface used to allow the initiator of power auth activation to get the result from
 * the operation.
 */
public interface ICreateActivationListener {
    /**
     * Called when activation succeeds.
     * @param activationFingerprint      decimalized fingerprint calculated from device's public key
     * @param customActivationAttributes custom attributes received from the server. The value
     *                                   may be null in case that there are no custom attributes
     *                                   available.
     */
    void onActivationCreateSucceed(@NonNull String activationFingerprint,
                                   @Nullable Map<String, Object> customActivationAttributes);

    /**
     * Called when activation fails with an error.
     * @param t error occurred during the activation
     */
    void onActivationCreateFailed(@NonNull Throwable t);
}
