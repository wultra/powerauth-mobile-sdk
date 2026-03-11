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

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.core.CoreTimeService;
import io.getlime.security.powerauth.core.response.CoreServerStatus;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.IServerStatusListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.networking.response.ServerStatus;
import io.getlime.security.powerauth.sdk.IPowerAuthTimeSynchronizationService;

/**
 * The `TimeSynchronizationService` class implements time synchronization with the server.
 */
public class TimeSynchronizationService implements IPowerAuthTimeSynchronizationService, IServerStatusProvider {

    private final ReentrantLock lock;
    private final CoreTimeService coreTimeService;
    private final CoreHttpClient coreHttpClient;
    private final ICallbackDispatcher callbackDispatcher;
    private GetServerStatusTask getStatusTask;

    /**
     * Construct the time service with the internal TimeProvider instance. The constructor and the interface
     * are package private but suppose to be used only for the testing purposes.
     * @param coreTimeService Instance of {@link CoreTimeService}.
     * @param coreHttpClient Instance of HTTP client.
     * @param callbackDispatcher Instance implementing ICallbackDispatcher
     */
    public TimeSynchronizationService(
            @NonNull ReentrantLock sharedLock,
            @NonNull CoreTimeService coreTimeService,
            @NonNull CoreHttpClient coreHttpClient,
            @NonNull ICallbackDispatcher callbackDispatcher) {
        this.lock = sharedLock;
        this.coreTimeService = coreTimeService;
        this.coreHttpClient = coreHttpClient;
        this.callbackDispatcher = callbackDispatcher;
    }

    // IServerStatusProvider

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
                getStatusTask = new GetServerStatusTask(lock, callbackDispatcher, coreHttpClient, coreTimeService, this::onGetServerStatusTaskCompletion);
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

    // IPowerAuthTimeSynchronizationService

    @Override
    public long getLocalTimeAdjustment() {
        return coreTimeService.getLocalTimeAdjustment();
    }

    @Override
    public long getLocalTimeAdjustmentPrecision() {
        return coreTimeService.getLocalTimeAdjustmentPrecision();
    }

    @Override
    public boolean isTimeSynchronized() {
        return coreTimeService.isTimeSynchronized();
    }

    @Override
    public long getCurrentTime() {
        return coreTimeService.getCurrentTime();
    }

    @Nullable
    @Override
    public ICancelable synchronizeTime(@NonNull ITimeSynchronizationListener listener) {
        if (isTimeSynchronized()) {
            callbackDispatcher.dispatchCallback(listener::onTimeSynchronizationSucceeded);
            return null;
        }
        return getServerStatus(new IServerStatusListener() {
            @Override
            public void onServerStatusSucceeded(@NonNull ServerStatus status) {
                listener.onTimeSynchronizationSucceeded();
            }

            @Override
            public void onServerStatusFailed(@NonNull Throwable t) {
                listener.onTimeSynchronizationFailed(t);
            }
        });
    }

    @Override
    public void resetTimeSynchronization() {
        coreTimeService.resetTimeSynchronization();
    }
}
