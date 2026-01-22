/*
 * Copyright 2026 Wultra s.r.o.
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

import java.util.concurrent.Executor;

import io.getlime.security.powerauth.core.CoreEncryptorScope;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.core.CoreTask;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.sdk.IPowerAuthTimeSynchronizationService;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;

public class CoreHttpClient {

    private final @NonNull PowerAuthClientConfiguration configuration;
    private final @NonNull String baseUrl;
    private final @NonNull IExecutorProvider executorProvider;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private Runnable saveStateCallback;
    private IPowerAuthTimeSynchronizationService timeSynchronizationService;
    private IKeystoreService keystoreService;

    public CoreHttpClient(@NonNull PowerAuthClientConfiguration configuration,
                          @NonNull String baseUrl,
                          @NonNull IExecutorProvider executorProvider,
                          @NonNull ICallbackDispatcher callbackDispatcher) {

        this.configuration = configuration;
        this.baseUrl = baseUrl;
        this.executorProvider = executorProvider;
        this.callbackDispatcher = callbackDispatcher;
    }

    @NonNull
    public PowerAuthClientConfiguration getConfiguration() {
        return configuration;
    }

    public void setKeystoreService(@NonNull IKeystoreService keystoreService) {
        if (this.keystoreService != null) {
            throw new IllegalStateException();
        }
        this.keystoreService = keystoreService;
    }

    @NonNull
    public IKeystoreService getKeystoreService() {
        if (keystoreService == null) {
            throw new IllegalStateException("IKeystoreService is not set");
        }
        return keystoreService;
    }

    @NonNull
    public IPowerAuthTimeSynchronizationService getTimeSynchronizationService() {
        if (timeSynchronizationService == null) {
            throw new IllegalStateException("IPowerAuthTimeSynchronizationService is not set");
        }
        return timeSynchronizationService;
    }

    public void setTimeSynchronizationService(@NonNull IPowerAuthTimeSynchronizationService timeSynchronizationService) {
        if (this.timeSynchronizationService != null) {
            throw new IllegalStateException();
        }
        this.timeSynchronizationService = timeSynchronizationService;
    }

    public void setSaveStateCallback(@NonNull Runnable saveStateCallback) {
        if (this.saveStateCallback != null) {
            throw new IllegalStateException();
        }
        this.saveStateCallback = saveStateCallback;
    }

    @NonNull
    Runnable getSaveStateCallback() {
        if (saveStateCallback == null) {
            throw new IllegalStateException("Save state callback is not set");
        }
        return saveStateCallback;
    }

    @NonNull
    public <TResponse> ICancelable post(@NonNull CoreRequest<TResponse> request, @NonNull INetworkResponseListener<TResponse> listener) {
        final IKeystoreService kss = getKeystoreService();
        final IPowerAuthTimeSynchronizationService tss = getTimeSynchronizationService();
        final int encryptorScope = request.getEncryptorScope();
        final boolean requireTimeSynchronization = request.isRequireSynchronizedTime() && !tss.isTimeSynchronized();
        final boolean requireEncryptionKey = encryptorScope != CoreEncryptorScope.NONE && !kss.containsKeyForEncryptor(encryptorScope);

        if (requireTimeSynchronization || requireEncryptionKey) {
            // Endpoint require encryption key or time synchronization. We have to create a composite task that cover
            // multiple tasks including an actual request execution.
            final CompositeCancelableTask compositeTask = new CompositeCancelableTask(true);
            compositeTask.setCancelCallback(() -> {
                callbackDispatcher.dispatchCallback(listener::onCancel);
            });
            // Now determine what type of task should be executed before an actual task.
            if (requireEncryptionKey) {
                // Temporary encryption key must be acquired from the server. This operation also automatically
                // synchronize the time.
                final ICancelable getKeyTask = kss.createKeyForEncryptor(encryptorScope, new ICreateKeyListener() {
                    @Override
                    public void onCreateKeySucceeded() {
                        // Temporary encryption key successfully acquired, we can continue with the actual request.
                        compositePostImpl(request, compositeTask, listener);
                    }

                    @Override
                    public void onCreateKeyFailed(@NonNull Throwable throwable) {
                        setCoreRequestFinished(request, true);
                        if (compositeTask.setCompleted()) {
                            listener.onNetworkError(throwable);
                        }
                    }
                });
                if (getKeyTask != null) {
                    compositeTask.addCancelable(getKeyTask);
                }
            } else {
                // Only time synchronization is required
                final ICancelable synchronizationTask = tss.synchronizeTime(new ITimeSynchronizationListener() {
                    @Override
                    public void onTimeSynchronizationSucceeded() {
                        // The time has been successfully synchronized, we can continue with the actual request.
                        compositePostImpl(request, compositeTask, listener);
                    }

                    @Override
                    public void onTimeSynchronizationFailed(@NonNull Throwable t) {
                        setCoreRequestFinished(request, true);
                        if (compositeTask.setCompleted()) {
                            listener.onNetworkError(t);
                        }
                    }
                });
                if (synchronizationTask != null) {
                    compositeTask.addCancelable(synchronizationTask);
                }
            }
            // Return composite task instead of original operation.
            return compositeTask;
        }
        // Endpoint doesn't require time synchronization or encryption.
        return postImpl(request, listener);
    }

    private <TResponse> void setCoreRequestFinished(CoreRequest<TResponse> request, boolean isFailed) {
        if (request != null && !request.isDone()) {
            if (isFailed) {
                request.setFailed();
            } else {
                request.cancel();
            }
        }
    }

    private <TResponse> void compositePostImpl(@NonNull CoreRequest<TResponse> request,
                                               @NonNull CompositeCancelableTask compositeTask,
                                               @NonNull INetworkResponseListener<TResponse> listener) {
        // Create actual HTTP request
        final ICancelable actualTask = postImpl(request, new INetworkResponseListener<>() {
            @Override
            public void onNetworkResponse(@Nullable TResponse tResponse) {
                if (compositeTask.setCompleted()) {
                    listener.onNetworkResponse(tResponse);
                }
            }

            @Override
            public void onNetworkError(@NonNull Throwable throwable) {
                if (compositeTask.setCompleted()) {
                    listener.onNetworkError(throwable);
                }
            }

            @Override
            public void onCancel() {
                // We can ignore the cancel, because it's handled already by the composite task.
            }
        });
        // Add actual task to composite task.
        compositeTask.addCancelable(actualTask);
    }

    @NonNull
    private <TResponse> ICancelable postImpl(@NonNull CoreRequest<TResponse> request,
                                             @NonNull INetworkResponseListener<TResponse> listener) {
        // Create CoreHttpTask
        final CoreHttpRequest<TResponse> task = new CoreHttpRequest<>(baseUrl, configuration, request, getSaveStateCallback(), new CoreHttpRequest.ICompletion<>() {
            @Override
            public void onSuccess(@Nullable TResponse tResponse) {
                callbackDispatcher.dispatchCallback(() -> listener.onNetworkResponse(tResponse));
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                callbackDispatcher.dispatchCallback(() -> listener.onNetworkError(failure));
            }
        });
        // Execute task on the right executor
        final Executor taskExecutor = request.isRequireSerialQueue()
                ? executorProvider.getSerialExecutor()
                : executorProvider.getConcurrentExecutor();
        taskExecutor.execute(task::doInBackground);
        return task;
    }

    @NonNull
    public <TResponse> ICancelable post(@NonNull CoreTask<TResponse> task, @NonNull INetworkResponseListener<TResponse> listener) {
        final CoreHttpTask<TResponse> wrapper = new CoreHttpTask<>(task, this, listener);
        wrapper.start();
        return wrapper;
    }

}
