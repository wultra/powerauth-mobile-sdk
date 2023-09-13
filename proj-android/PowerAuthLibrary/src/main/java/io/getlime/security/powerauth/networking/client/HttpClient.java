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

package io.getlime.security.powerauth.networking.client;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.concurrent.Executor;

import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.sdk.IPowerAuthTimeSynchronizationService;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.CompositeCancelableTask;
import io.getlime.security.powerauth.sdk.impl.ICallbackDispatcher;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;

/**
 * The {@code HttpClient} class provides a high level networking functionality, including
 * encryption &amp; data signing for the mobile SDK. The class is internal and cannot be used
 * by the application.
 *
 * Note that there's always only one instance of this client per {@link io.getlime.security.powerauth.sdk.PowerAuthSDK}
 * object instance.
 */
public class HttpClient {

    private final @NonNull PowerAuthClientConfiguration configuration;
    private final @NonNull String baseUrl;
    private final @NonNull IExecutorProvider executorProvider;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private IPowerAuthTimeSynchronizationService timeSynchronizationService;

    /**
     * @param configuration HTTP client configuration
     * @param baseUrl String with base URL to PowerAuth Server REST API
     * @param executorProvider object providing serial or concurrent thread executors
     * @param callbackDispatcher Object that dispatch callback to main thread.
     */
    public HttpClient(
            @NonNull PowerAuthClientConfiguration configuration,
            @NonNull String baseUrl,
            @NonNull IExecutorProvider executorProvider,
            @NonNull ICallbackDispatcher callbackDispatcher) {
        this.configuration = configuration;
        this.baseUrl = baseUrl;
        this.executorProvider = executorProvider;
        this.callbackDispatcher = callbackDispatcher;
    }

    /**
     * @return HTTP client configuration assigned to this object
     */
    public @NonNull PowerAuthClientConfiguration getClientConfiguration() {
        return configuration;
    }

    /**
     * @return String with base URL to PowerAuth Server REST API
     */
    public @NonNull String getBaseUrl() {
        return baseUrl;
    }


    /**
     * @return {@link IExecutorProvider} object assigned during the client initialization.
     */
    public @NonNull IExecutorProvider getExecutorProvider() {
        return executorProvider;
    }

    /**
     * Set time synchronization service to the HTTP client.
     * @param timeSynchronizationService Time synchronization service implementation.
     */
    public void setTimeSynchronizationService(@NonNull IPowerAuthTimeSynchronizationService timeSynchronizationService) {
        if (this.timeSynchronizationService != null) {
            throw new IllegalStateException();
        }
        this.timeSynchronizationService = timeSynchronizationService;
    }

    /**
     * Posts a HTTP request with provided object to the REST endpoint.
     *
     * @param object object to be serialized into POST request
     * @param endpoint object defining the endpoint
     * @param helper cryptographic helper
     * @param listener response listener
     * @param <TRequest> request type
     * @param <TResponse> response type
     * @return {@link ICancelable} object which allows application cancel the pending operation
     */
    @NonNull
    public <TRequest, TResponse> ICancelable post(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @Nullable IPrivateCryptoHelper helper,
            @NonNull INetworkResponseListener<TResponse> listener) {
        return post(object, endpoint, helper, null, listener);
    }

    /**
     * Posts a HTTP request with provided object to the REST endpoint.
     *
     * @param object object to be serialized into POST request
     * @param endpoint object defining the endpoint
     * @param helper cryptographic helper
     * @param authentication optional authentication object, if request has to be signed with PowerAuth signature.
     * @param listener response listener
     * @param <TRequest> type of request object
     * @param <TResponse> type of response object
     * @return {@link ICancelable} object which allows application cancel the pending operation
     */
    @NonNull
    public <TRequest, TResponse> ICancelable post(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @Nullable IPrivateCryptoHelper helper,
            @Nullable PowerAuthAuthentication authentication,
            @NonNull INetworkResponseListener<TResponse> listener) {

        if (endpoint.isRequireSynchronizedTime()) {
            // Get the time synchronization service. It supposed to be set by the PowerAuthSDK's builder in SDK construction.
            final IPowerAuthTimeSynchronizationService tss = timeSynchronizationService;
            if (tss == null) {
                throw new IllegalStateException("Time synchronization service is not set.");
            }
            if (!tss.isTimeSynchronized()) {
                // Endpoint require encryption and time is not synchronized yet. We have to create a composite task that cover both
                // time synchronization and actual request execution.
                final CompositeCancelableTask compositeTask = new CompositeCancelableTask(true);
                compositeTask.setCancelCallback(() -> {
                    callbackDispatcher.dispatchCallback(listener::onCancel);
                });
                final ICancelable synchronizationTask = tss.synchronizeTime(new ITimeSynchronizationListener() {
                    @Override
                    public void onTimeSynchronizationSucceeded() {
                        // The time has been successfully synchronized, we can continue with the actual request.
                        final ICancelable actualTask = postImpl(object, endpoint, helper, authentication, new INetworkResponseListener<TResponse>() {
                            @Override
                            public void onNetworkResponse(@NonNull TResponse tResponse) {
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
                        compositeTask.addCancelable(actualTask);
                    }

                    @Override
                    public void onTimeSynchronizationFailed(@NonNull Throwable t) {
                        if (compositeTask.setCompleted()) {
                            listener.onNetworkError(t);
                        }
                    }
                });
                if (synchronizationTask != null) {
                    compositeTask.addCancelable(synchronizationTask);
                }
                // Return composite task instead of original operation.
                return compositeTask;
            }
        }
        // Endpoint doesn't require time synchronization, or time is already synchronized.
        return postImpl(object, endpoint, helper, authentication, listener);
    }

    /**
     * Internal implementation of HTTP post request.
     *
     * @param object object to be serialized into POST request
     * @param endpoint object defining the endpoint
     * @param helper cryptographic helper
     * @param authentication optional authentication object, if request has to be signed with PowerAuth signature.
     * @param listener response listener
     * @param <TRequest> type of request object
     * @param <TResponse> type of response object
     * @return {@link ICancelable} object which allows application cancel the pending operation
     */
    @NonNull
    private <TRequest, TResponse> ICancelable postImpl(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @Nullable IPrivateCryptoHelper helper,
            @Nullable PowerAuthAuthentication authentication,
            @NonNull INetworkResponseListener<TResponse> listener) {
        final HttpRequestHelper<TRequest, TResponse> request = new HttpRequestHelper<>(object, endpoint, authentication);
        final HttpClientTask<TRequest, TResponse> task = new HttpClientTask<>(request, baseUrl, configuration, helper, listener);

        final Executor executor = endpoint.isSynchronized() ? executorProvider.getSerialExecutor() : executorProvider.getConcurrentExecutor();
        task.executeOnExecutor(executor, null, null);
        return task;
    }
}
