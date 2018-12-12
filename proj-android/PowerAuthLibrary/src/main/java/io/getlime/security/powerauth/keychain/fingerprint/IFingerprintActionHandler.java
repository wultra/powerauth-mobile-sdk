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

package io.getlime.security.powerauth.keychain.fingerprint;

import android.support.annotation.Nullable;
import android.support.annotation.UiThread;

/**
 * Interface used as a callback for fingerprint authentication.
 */
public interface IFingerprintActionHandler {

    /**
     * Fingerprint dialog was cancelled.
     */
    void onFingerprintDialogCancelled();

    /**
     * Fingerprint authentication succeeded.
     * @param biometricKeyEncrypted Biometric key encrypted with fingerprint protected key from Keystore - use this key as a value for biometric authentication.
     */
    @UiThread
    void onFingerprintDialogSuccess(@Nullable byte[] biometricKeyEncrypted);

    /**
     * Fingerprint dialog with information about missing fingers was closed.
     */
    void onFingerprintInfoDialogClosed();

}
