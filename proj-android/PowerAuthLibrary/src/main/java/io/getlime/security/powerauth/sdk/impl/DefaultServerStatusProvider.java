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
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Default implementation of {@link IServerStatusListener} interface.
 */
public class DefaultServerStatusProvider implements IServerStatusProvider {

    private final ReentrantLock lock;
    private final HttpClient httpClient;
    private final ICallbackDispatcher callbackDispatcher;
    private GetServerStatusTask getStatusTask;

    /**
     * Construct provider with preconfigured HTTP client and shared reentrant lock.
     * @param httpClient HTTP client.
     * @param sharedLock Reentrant lock shared between multiple PowerAuthSDK internal classes.
     * @param callbackDispatcher Object dispatching callbacks to main thread.
     */
    public DefaultServerStatusProvider(
            @NonNull HttpClient httpClient,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher callbackDispatcher) {
        this.lock = sharedLock;
        this.httpClient = httpClient;
        this.callbackDispatcher = callbackDispatcher;
    }

    @Nullable
    @Override
    public ICancelable getServerStatus(@NonNull IServerStatusListener listener) {
        final ITaskCompletion<ServerStatus> taskCompletion = new ITaskCompletion<ServerStatus>() {
            @Override
            public void onSuccess(@NonNull ServerStatus serverStatus) {
                listener.onServerStatusSucceeded(serverStatus);
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                listener.onServerStatusFailed(failure);
            }
        };
        try {
            ICancelable task;
            lock.lock();
            if (getStatusTask != null) {
                task = getStatusTask.createChildTask(taskCompletion);
            } else {
                task = null;
            }
            if (task == null) {
                getStatusTask = new GetServerStatusTask(lock, callbackDispatcher, httpClient, this::onGetServerStatusTaskCompletion);
                task = getStatusTask.createChildTask(taskCompletion);
            }
            return task;
        } finally {
            lock.unlock();
        }
    }

    private void onGetServerStatusTaskCompletion(@NonNull GetServerStatusTask task) {
        try {
            lock.lock();
            if (task == getStatusTask) {
                getStatusTask = null;
            }
        } finally {
            lock.unlock();
        }
    }
}
