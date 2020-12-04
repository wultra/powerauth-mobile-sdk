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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import io.getlime.security.powerauth.keychain.Keychain;

/**
 * Default implementation of PowerAuth state listener.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class DefaultSavePowerAuthStateListener implements ISavePowerAuthStateListener {

    private final Keychain keychain;

    public DefaultSavePowerAuthStateListener(@NonNull Keychain keychain) {
        this.keychain = keychain;
    }

    @Override
    public @Nullable byte[] serializedState(@NonNull String instanceId) {
        return keychain.getData(instanceId);
    }

    @Override
    public void onPowerAuthStateChanged(@NonNull String instanceId, @NonNull byte[] serializedState) {
        keychain.putData(serializedState, instanceId);
    }

}
