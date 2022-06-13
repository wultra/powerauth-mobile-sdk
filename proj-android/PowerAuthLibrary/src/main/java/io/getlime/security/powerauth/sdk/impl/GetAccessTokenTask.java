/*
 * Copyright 2022 Wultra s.r.o.
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

import java.util.concurrent.locks.ReentrantLock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthToken;

/**
 * The GetAccessTokenTask groups multiple create token requests into one HTTP request
 * send to the server.
 */
public class GetAccessTokenTask extends GroupedTask<PowerAuthToken> {

    /**
     * Listener called when task is started or completed.
     */
    public interface Listener {
        /**
         * Called when task is started.
         * @param groupedTask Instance of task that is going to start.
         */
        void onTaskStart(@NonNull GetAccessTokenTask groupedTask);

        /**
         * Called when task is complete.
         * @param groupedTask Instance of task that is complete.
         * @param token Token, valid only when task succeeded.
         */
        void onTaskComplete(@NonNull GetAccessTokenTask groupedTask, @Nullable PowerAuthToken token);
    }

    /**
     * Contains authentication associated with this request.
     */
    public final int authenticationFactors;

    /**
     * Listener that implement task start and completion.
     */
    private final @NonNull Listener listener;

    /**
     * Initialize object with all required parameters.
     *
     * @param authenticationFactors Numeric value representing a combination of authentication factors used for the token creation.
     * @param sharedLock Instance of shared lock.
     * @param dispatcher Result dispatcher.
     * @param listener Listener that implements the task start and the completion.
     */
    public GetAccessTokenTask(
            int authenticationFactors,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher dispatcher,
            @NonNull Listener listener) {
        super("GetAccessTokenTask", sharedLock, dispatcher);
        this.authenticationFactors = authenticationFactors;
        this.listener = listener;
    }

    @Override
    public void onGroupedTaskStart() {
        listener.onTaskStart(this);
    }

    @Override
    public void onGroupedTaskComplete(@Nullable PowerAuthToken powerAuthToken, @Nullable Throwable failure) {
        listener.onTaskComplete(this, powerAuthToken);
    }
}
