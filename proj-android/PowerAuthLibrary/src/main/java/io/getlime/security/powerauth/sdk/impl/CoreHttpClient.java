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

/**
 * The {@code CoreHttpClient} class communication with the server over HTTP protocol.
 * The target endpoint is specified by {@link CoreRequest} or {@link CoreTask} objects.
 */
public class CoreHttpClient {

    private final @NonNull PowerAuthClientConfiguration configuration;
    private final @NonNull String baseUrl;
    private final @NonNull IExecutorProvider executorProvider;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private Runnable saveStateCallback;
    private IPowerAuthTimeSynchronizationService timeSynchronizationService;
    private IKeystoreService keystoreService;

    /**
     * Construct client with required parameters.
     * @param configuration HTTP client configuration.
     * @param baseUrl Base URL.
     * @param executorProvider Interface providing serial or concurrent executors.
     * @param callbackDispatcher Interface for dispatching callbacks back to application.
     */
    public CoreHttpClient(@NonNull PowerAuthClientConfiguration configuration,
                          @NonNull String baseUrl,
                          @NonNull IExecutorProvider executorProvider,
                          @NonNull ICallbackDispatcher callbackDispatcher) {

        this.configuration = configuration;
        this.baseUrl = baseUrl;
        this.executorProvider = executorProvider;
        this.callbackDispatcher = callbackDispatcher;
    }

    /**
     * @return {@link PowerAuthClientConfiguration} provided in object's initialization.
     */
    @NonNull
    public PowerAuthClientConfiguration getConfiguration() {
        return configuration;
    }

    /**
     * Connect {@link IKeystoreService} with this HTTP client. The keystore service has to be
     * connected before the first HTTP request is executed.
     * @param keystoreService Object implementing {@link IKeystoreService}.
     */
    public void setKeystoreService(@NonNull IKeystoreService keystoreService) {
        if (this.keystoreService != null) {
            throw new IllegalStateException();
        }
        this.keystoreService = keystoreService;
    }

    /**
     * @return {@link IKeystoreService} connected with this client.
     */
    @NonNull
    public IKeystoreService getKeystoreService() {
        if (keystoreService == null) {
            throw new IllegalStateException("IKeystoreService is not set");
        }
        return keystoreService;
    }

    /**
     * Connect {@link IPowerAuthTimeSynchronizationService} with this HTTP client. The time synchronization
     * service has to be connected before the first HTTP request is executed.
     * @param timeSynchronizationService Object implementing {@link IPowerAuthTimeSynchronizationService}.
     */
    public void setTimeSynchronizationService(@NonNull IPowerAuthTimeSynchronizationService timeSynchronizationService) {
        if (this.timeSynchronizationService != null) {
            throw new IllegalStateException();
        }
        this.timeSynchronizationService = timeSynchronizationService;
    }

    /**
     * @return {@link IPowerAuthTimeSynchronizationService} connected with this HTTP client.
     */
    @NonNull
    public IPowerAuthTimeSynchronizationService getTimeSynchronizationService() {
        if (timeSynchronizationService == null) {
            throw new IllegalStateException("IPowerAuthTimeSynchronizationService is not set");
        }
        return timeSynchronizationService;
    }

    /**
     * Set callback that has to be called when state of the underlying session is changed and
     * needs to be saved. The callback has to be set before the first HTTP request is executed.
     * @param saveStateCallback Callback to set.
     */
    public void setSaveStateCallback(@NonNull Runnable saveStateCallback) {
        if (this.saveStateCallback != null) {
            throw new IllegalStateException();
        }
        this.saveStateCallback = saveStateCallback;
    }

    /**
     * @return Callback that has to be executed when state of underlying session is changed.
     */
    @NonNull
    Runnable getSaveStateCallback() {
        if (saveStateCallback == null) {
            throw new IllegalStateException("Save state callback is not set");
        }
        return saveStateCallback;
    }

    /**
     * Execute HTTP request specified in {@link CoreRequest} object.
     * @param request Request to execute.
     * @param listener Callback listener called when the request execution is finished.
     * @return {@link ICancelable} object representing an asynchronous operation.
     * @param <TResponse> Type of response object. If no response is provided, use {@link Object}.
     */
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

    /**
     * Set instance of {@link CoreRequest} as unexpectedly finished.
     * @param request Request to set.
     * @param isFailed If true, request is set as failed, otherwise canceled.
     * @param <TResponse> Type of response.
     */
    private <TResponse> void setCoreRequestFinished(CoreRequest<TResponse> request, boolean isFailed) {
        if (request != null && !request.isDone()) {
            if (isFailed) {
                request.setFailed();
            } else {
                request.cancel();
            }
        }
    }

    /**
     * Executes the HTTP request specified by the {@link CoreRequest} object in the context of
     * composite cancelable operation.
     * @param request {@link CoreRequest} to execute.
     * @param compositeTask Parent {@link CompositeCancelableTask}.
     * @param listener Callback interface.
     * @param <TResponse> Type of response.
     */
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

    /**
     * Executes the HTTP request specified by the {@link CoreRequest} object on the appropriate
     * task executor. If the request must be executed on a serial queue, the serial executor is used;
     * otherwise, a concurrent executor is used.
     * @param request {@link CoreRequest} to execute.
     * @param listener Callback interface.
     * @return {@link CoreHttpRequest} wrapping the request.
     * @param <TResponse> Type of response.
     */
    @NonNull
    private <TResponse> CoreHttpRequest<TResponse> postImpl(@NonNull CoreRequest<TResponse> request,
                                                            @NonNull INetworkResponseListener<TResponse> listener) {
        // Create CoreHttpTask
        final CoreHttpRequest<TResponse> task = new CoreHttpRequest<>(baseUrl, configuration, request, getSaveStateCallback(), callbackDispatcher, listener);
        // Execute task on the right executor
        final Executor taskExecutor = request.isRequireSerialQueue()
                ? executorProvider.getSerialExecutor()
                : executorProvider.getConcurrentExecutor();
        taskExecutor.execute(task::doInBackground);
        return task;
    }

    /**
     * Execute series of HTTP requests specified in {@link CoreTask} object.
     * @param task {@link CoreTask} object to execute.
     * @param listener Callback listener called when the task execution is finished.
     * @return {@link ICancelable} object representing an asynchronous operation.
     * @param <TResponse> Type of response.
     */
    @NonNull
    public <TResponse> ICancelable post(@NonNull CoreTask<TResponse> task, @NonNull INetworkResponseListener<TResponse> listener) {
        final CoreHttpTask<TResponse> wrapper = new CoreHttpTask<>(task, this, listener);
        wrapper.start();
        return wrapper;
    }
}
