/*
 * Copyright 2023 Wultra s.r.o.
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

import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.core.CoreTimeService;
import io.getlime.security.powerauth.core.response.CoreServerStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;
import jakarta.validation.constraints.Null;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

public class GetServerStatusTask extends GroupedTask<ServerStatus> {

    public interface TaskCompletion {
        void onGetServerStatusTaskCompletion(@NonNull GetServerStatusTask task);
    }

    private final CoreHttpClient httpClient;

    private final CoreTimeService timeService;

    private final TaskCompletion taskCompletion;


    /**
     * Initialize object with all required parameters.
     *
     * @param sharedLock Instance of shared lock.
     * @param dispatcher Result dispatcher.
     * @param httpClient HTTP client.
     * @param timeService Core time synchronization service.
     * @param completion Task completion
     */
    public GetServerStatusTask(
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher dispatcher,
            @NonNull CoreHttpClient httpClient,
            @NonNull CoreTimeService timeService,
            @NonNull TaskCompletion completion) {
        super("GetServerStatus", sharedLock, dispatcher);
        this.httpClient = httpClient;
        this.timeService = timeService;
        this.taskCompletion = completion;
    }

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        try {
            final CoreRequest<CoreServerStatus> request = timeService.createTimeSynchronizationRequest();
            final ICancelable cancelable = httpClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable CoreServerStatus coreServerStatus) {
                    complete(new ServerStatus(Objects.requireNonNull(coreServerStatus)));
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

        } catch (CoreException e) {
            complete(PowerAuthErrorException.wrapException(e));
        }
    }

    @Override
    public void onGroupedTaskComplete(@Nullable ServerStatus serverStatus, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(serverStatus, failure);
        taskCompletion.onGetServerStatusTaskCompletion(this);
    }
}
