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

import io.getlime.security.powerauth.exception.PowerAuthErrorException;

/**
 * Interface used as a callback for committing the activation with fingerprint authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface ICommitActivationWithFingerprintListener {

    /**
     * Fingerprint dialog was cancelled.
     */
    void onFingerprintDialogCancelled();

    /**
     * Fingerprint authentication succeeded.
     */
    void onFingerprintDialogSuccess();

    /**
     * Called when fingerprint dialog failed on error.
     *
     * @param error error that occurred during the activation commit.
     */
    void onFingerprintDialogFailed(PowerAuthErrorException error);

}
