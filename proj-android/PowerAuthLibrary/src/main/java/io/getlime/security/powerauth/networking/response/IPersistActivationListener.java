/*
 * Copyright 2025 Wultra s.r.o.
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
import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Listener for persist activation operation.
 */
public interface IPersistActivationListener {
    /**
     * Called when activation has been successfully persisted on the device.
     */
    @MainThread
    void onPersistActivationSucceeded();

    /**
     * Called when failed to persist activation on the device.
     *
     * @param error error occurred during the operation
     */
    @MainThread
    void onPersistActivationFailed(@NonNull PowerAuthErrorException error);

    /**
     * Called when persist activation operation failed due to cancellation of biometric authentication dialog.
     *
     * @param userCancel If parameter is {@code true}, then the dialog was canceled by the user. The {@code false}
     *                   value means that authentication request was canceled by your code, by calling {@code cancel()}
     *                   on provided cancelable object.
     */
    @MainThread
    void onPersistActivationCancelled(boolean userCancel);
}
