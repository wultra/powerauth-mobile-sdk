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

import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.core.CoreSession;
import io.getlime.security.powerauth.core.CoreTask;
import io.getlime.security.powerauth.core.response.CoreActivationStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.sdk.PowerAuthActivationStatus;


/**
 *  The {@code GetActivationStatusTask} class implements getting activation status from the server
 *  and the protocol upgrade. The upgrade is started automatically, depending on the
 *  local and server's state of the activation.
 */
public class GetActivationStatusTask extends GroupedTask<PowerAuthActivationStatus> {

    public interface ICompletionListener {
        void onSessionStateChange();
        void onTaskCompletion(@NonNull GetActivationStatusTask task, @Nullable PowerAuthActivationStatus status);
    }

    @NonNull
    private final CoreHttpClient httpClient;
    @NonNull
    private final CoreSession session;
    @NonNull
    private final ICompletionListener completionListener;

    /**
     * Create task for getting activation status.
     *
     * @param httpClient HTTP client
     * @param session Core Session object.
     * @param sharedLock Shared lock.
     * @param callbackDispatcher callback dispatcher from parent SDK object
     * @param completionListener final completion listener.
     */
    public GetActivationStatusTask(
            @NonNull CoreHttpClient httpClient,
            @NonNull CoreSession session,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher callbackDispatcher,
            @NonNull ICompletionListener completionListener) {
        super("GetActivationStatus", sharedLock, callbackDispatcher);
        this.httpClient = httpClient;
        this.session = session;
        this.completionListener = completionListener;
    }

    //
    // GroupedTask methods
    //

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        try {
            final CoreTask<CoreActivationStatus> coreTask = session.fetchActivationStatus();
            final ICancelable cancelable = httpClient.post(coreTask, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable CoreActivationStatus status) {
                    final CoreActivationStatus coreStatus = Objects.requireNonNull(status);
                    complete(new PowerAuthActivationStatus(coreStatus));
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    complete(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
            addCancelableOperation(cancelable);
        } catch (CoreException exception) {
            complete(PowerAuthErrorException.wrapException(exception));
        }
    }

    @Override
    public void onGroupedTaskComplete(@Nullable PowerAuthActivationStatus activationStatus, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(activationStatus, failure);
        completionListener.onTaskCompletion(this, activationStatus);
    }
}
