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

import androidx.annotation.MainThread;

import androidx.annotation.NonNull;
import io.getlime.security.powerauth.core.ActivationStatus;

/**
 * Listener for activation status retrieval.
 */
public interface IActivationStatusListener {

    /**
     * Called when activation status retrieval succeeds.
     *
     * @param status retrieved activation status.
     */
    @MainThread
    void onActivationStatusSucceed(ActivationStatus status);

    /**
     * Called when activation status fails.
     *
     * @param t error that occurred during the activation status retrieval.
     */
    @MainThread
    void onActivationStatusFailed(@NonNull Throwable t);
}
