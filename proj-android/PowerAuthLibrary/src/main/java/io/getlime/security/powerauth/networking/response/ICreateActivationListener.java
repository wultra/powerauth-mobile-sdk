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

import android.support.annotation.MainThread;
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
     *
     * @param result {@link CreateActivationResult} object representing a successful result of
     *               the activation process.
     */
    @MainThread
    void onActivationCreateSucceed(@NonNull CreateActivationResult result);

    /**
     * Called when activation fails with an error.
     *
     * @param t error that occurred during the activation.
     */
    @MainThread
    void onActivationCreateFailed(@NonNull Throwable t);
}
