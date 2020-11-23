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

import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Interface used as a callback for committing the activation with biometric authentication.
 */
public interface ICommitActivationWithBiometryListener {

    /**
     * Biometric dialog was cancelled.
     */
    void onBiometricDialogCancelled();

    /**
     * Biometric authentication succeeded and the activation has been committed.
     */
    void onBiometricDialogSuccess();

    /**
     * Called when biometric dialog or the activation commit failed on error.
     *
     * @param error error that occurred during the activation commit.
     */
    void onBiometricDialogFailed(@NonNull PowerAuthErrorException error);

}
