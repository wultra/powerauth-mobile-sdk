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

package io.getlime.security.powerauth.sdk.impl;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Interface to be used to provide PA state storing functionality.
 *
 * @author miroslavmichalec
 */
public interface ISavePowerAuthStateListener {

    /**
     * Returns previously saved state of {@code PowerAuthSDK} object.
     *
     * @param instanceId {@code PowerAuthSDK} instance identifier
     * @return bytes with serialized object state or {@code null} if state was
     *         not previously serialized.
     */
    @Nullable byte[] serializedState(@NonNull String instanceId);


    /**
     * Notifies listener about change in the state of {@code PowerAuthSDK} instance. The listener
     * should save that state to the persistent storage.
     *
     * @param instanceId {@code PowerAuthSDK} instance identifier
     * @param serializedState serialized state
     */
    void onPowerAuthStateChanged(@NonNull String instanceId, @NonNull byte[] serializedState);
}
