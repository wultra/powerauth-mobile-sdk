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

package io.getlime.security.powerauth.networking.response;

import android.support.annotation.MainThread;
import android.support.annotation.NonNull;

/**
 * Listener for confirming recovery code.
 */
public interface IConfirmRecoveryCodeListener {
    /**
     * Called when recovery code confirmation succeeds.
     *
     * @param alreadyConfirmed true if recovery code has been already confirmed.
     */
    @MainThread
    void onRecoveryCodeConfirmed(boolean alreadyConfirmed);

    /**
     * Called when recovery code confirmation fails.
     *
     * @param t error that occurred during the confirmation.
     */
    @MainThread
    void onRecoveryCodeConfirmFailed(@NonNull Throwable t);
}
