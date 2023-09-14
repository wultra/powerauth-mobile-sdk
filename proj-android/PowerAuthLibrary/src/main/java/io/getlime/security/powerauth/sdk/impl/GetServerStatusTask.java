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
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.endpoints.GetServerStatusEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.model.response.ServerStatusResponse;
import io.getlime.security.powerauth.networking.response.ServerStatus;

import java.util.concurrent.locks.ReentrantLock;

public class GetServerStatusTask extends GroupedTask<ServerStatus> {

    public interface TaskCompletion {
        void onGetServerStatusTaskCompletion(@NonNull GetServerStatusTask task);
    }

    private final HttpClient httpClient;
    private final TaskCompletion taskCompletion;


    /**
     * Initialize object with all required parameters.
     *
     * @param sharedLock Instance of shared lock.
     * @param dispatcher Result dispatcher.
     * @param httpClient HTTP client.
     * @param completion Task completion
     */
    public GetServerStatusTask(
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher dispatcher,
            @NonNull HttpClient httpClient,
            @NonNull TaskCompletion completion) {
        super("GetServerStatus", sharedLock, dispatcher);
        this.httpClient = httpClient;
        this.taskCompletion = completion;
    }

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        final ICancelable cancelable = httpClient.post(
                null,
                new GetServerStatusEndpoint(),
                null,
                new INetworkResponseListener<ServerStatusResponse>() {
                    @Override
                    public void onNetworkResponse(@NonNull ServerStatusResponse response) {
                        complete(new ServerStatus(response));
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        complete(throwable);
                    }

                    @Override
                    public void onCancel() {
                    }
                }
        );
        addCancelableOperation(cancelable);
    }

    @Override
    public void onGroupedTaskComplete(@Nullable ServerStatus serverStatus, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(serverStatus, failure);
        taskCompletion.onGetServerStatusTaskCompletion(this);
    }
}
