/*
 * Copyright 2018 Wultra s.r.o.
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

import java.util.concurrent.locks.ReentrantLock;

import io.getlime.security.powerauth.core.ActivationStatus;

/**
 *  The {@code GetActivationStatusTask} class implements getting activation status from the server
 *  and the protocol upgrade. The upgrade is started automatically, depending on the
 *  local and server's state of the activation.
 */
public class GetActivationStatusTask extends GroupedTask<ActivationStatus> {

    public interface ICompletionListener {
        void onSessionStateChange();
        void onTaskCompletion(@NonNull GetActivationStatusTask task, @Nullable ActivationStatus status);
    }

    private final CoreHttpClient httpClient;
    private final ICompletionListener completionListener;

    /**
     * @param httpClient HTTP client
     * @param sharedLock Shared lock.
     * @param callbackDispatcher callback dispatcher from parent SDK object
     * @param completionListener final completion listener.
     */
    public GetActivationStatusTask(
            @NonNull CoreHttpClient httpClient,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher callbackDispatcher,
            @NonNull ICompletionListener completionListener) {
        super("GetActivationStatus", sharedLock, callbackDispatcher);
        this.httpClient = httpClient;
        this.completionListener = completionListener;
    }

    //
    // GroupedTask methods
    //

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        throw new IllegalStateException("TODO");
    }

    @Override
    public void onGroupedTaskComplete(@Nullable ActivationStatus activationStatus, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(activationStatus, failure);
        completionListener.onTaskCompletion(this, activationStatus);
    }

}
