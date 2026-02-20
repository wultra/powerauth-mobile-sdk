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

package io.getlime.security.powerauth.networking.response;

import androidx.annotation.MainThread;
import androidx.annotation.NonNull;

/**
 * Listener for the protocol upgrade process.
 */
public interface IProtocolUpgradeListener {

    /**
     * Called when the protocol upgrade process finishes.
     * The returned {@link ProtocolUpgradeResult#isActivationStatusFetchRequired()} flag
     * may be {@code true}, indicating that an additional activation status fetch
     * is required to fully complete the protocol upgrade process.
     *
     * @param result Result of the protocol upgrade process.
     */
    @MainThread
    void onProtocolUpgradeSucceed(@NonNull ProtocolUpgradeResult result);

    /**
     * Called when the protocol upgrade process fails.
     *
     * @param throwable Error that occurred during the protocol upgrade process.
     */
    @MainThread
    void onProtocolUpgradeFailed(@NonNull Throwable throwable);
}
