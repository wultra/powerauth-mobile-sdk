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

package io.getlime.security.powerauth.biometry;

import android.support.annotation.NonNull;
import android.support.annotation.UiThread;

import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Interface used as a callback for general biometric authentication.
 */
public interface IBiometricAuthenticationCallback {

    /**
     * Biometric authentication dialog was cancelled by the user or externally, by calling {@code cancel()}
     * on cancelable object returned from authenticate() method.
     *
     * @param userCancel If parameter is {@code true}, then the dialog was canceled by the user. The {@code false}
     *                   value means that authentication request was canceled by your code, by calling {@code cancel()}
     *                   on provided cancelable object.
     */
    @UiThread
    void onBiometricDialogCancelled(boolean userCancel);

    /**
     * Biometric authentication succeeded.
     *
     * @param biometricKeyData Object containing derived biometric key and key data that must be saved
     *                         to persistent storage.
     */
    @UiThread
    void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData);

    /**
     * Biometric authentication failed with the error.
     *
     * @param error {@link PowerAuthErrorException} contains reason of the failure.
     */
    @UiThread
    void onBiometricDialogFailed(@NonNull PowerAuthErrorException error);
}
