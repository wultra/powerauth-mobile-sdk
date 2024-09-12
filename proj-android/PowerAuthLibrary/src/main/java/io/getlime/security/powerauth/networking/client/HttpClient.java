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

import io.getlime.security.powerauth.core.EciesEncryptorScope;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.sdk.IPowerAuthTimeSynchronizationService;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.*;

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
    private IKeystoreService keystoreService;

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
     * Set time synchronization service to the HTTP client. If the service is already set, then throws {@link IllegalStateException}.
     * @param timeSynchronizationService Time synchronization service implementation.
     */
    public void setTimeSynchronizationService(@NonNull IPowerAuthTimeSynchronizationService timeSynchronizationService) {
        if (this.timeSynchronizationService != null) {
            throw new IllegalStateException();
        }
        this.timeSynchronizationService = timeSynchronizationService;
    }

    /**
     * Get time synchronization service associated to the HTTP client. If service is not set, then throws {@link IllegalStateException}.
     * @return Implementation of {@link IPowerAuthTimeSynchronizationService}.
     */
    @NonNull
    IPowerAuthTimeSynchronizationService getTimeSynchronizationService() {
        if (timeSynchronizationService == null) {
            throw new IllegalStateException();
        }
        return timeSynchronizationService;
    }

    /**
     * Set keystore service to the HTTP client. If the service is already set, then throws {@link IllegalStateException}.
     * @param keystoreService Keystore service implementation.
     */
    public void setKeystoreService(@Nullable IKeystoreService keystoreService) {
        if (this.keystoreService != null) {
            throw new IllegalStateException();
        }
        this.keystoreService = keystoreService;
    }

    /**
     * Get keystore service associated to the HTTP client. If service is not set, then throws {@link IllegalStateException}.
     * @return Implementation of {@link IKeystoreService}.
     */
    @NonNull
    IKeystoreService getKeystoreService() {
        if (keystoreService == null) {
            throw new IllegalStateException();
        }
        return keystoreService;
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

        final IKeystoreService kss = getKeystoreService();
        final IPowerAuthTimeSynchronizationService tss = getTimeSynchronizationService();
        final int encryptorScope = endpoint.isEncryptedWithApplicationScope() ? EciesEncryptorScope.APPLICATION : EciesEncryptorScope.ACTIVATION;
        final boolean requireTimeSynchronization = endpoint.isRequireSynchronizedTime() && !tss.isTimeSynchronized();
        final boolean requireEncryptionKey = endpoint.isEncrypted() && !kss.containsKeyForEncryptor(encryptorScope);

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
                if (helper == null) {
                    throw new IllegalArgumentException();
                }
                final ICancelable getKeyTask = kss.createKeyForEncryptor(encryptorScope, helper, new ICreateKeyListener() {
                    @Override
                    public void onCreateKeySucceeded() {
                        // Encryption key successfully acquired, we can continue with the actual request.
                        compositePostImpl(object, endpoint, helper, authentication, compositeTask, listener);
                    }

                    @Override
                    public void onCreateKeyFailed(@NonNull Throwable throwable) {
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
                        compositePostImpl(object, endpoint, helper, authentication, compositeTask, listener);
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
            }
            // Return composite task instead of original operation.
            return compositeTask;
        }

        // Endpoint doesn't require time synchronization or encryption.
        return postImpl(object, endpoint, helper, authentication, listener);
    }

    /**
     * Function creates an asynchronous operation with HTTP request and includes the operation into composite task.
     * @param object object to be serialized into POST request
     * @param endpoint object defining the endpoint
     * @param helper cryptographic helper
     * @param authentication optional authentication object, if request has to be signed with PowerAuth signature
     * @param compositeTask composite task reported back to the application
     * @param listener response listener
     * @param <TRequest> type of request object
     * @param <TResponse> type of response object
     */
    private <TRequest, TResponse> void compositePostImpl(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @Nullable IPrivateCryptoHelper helper,
            @Nullable PowerAuthAuthentication authentication,
            @NonNull CompositeCancelableTask compositeTask,
            @NonNull INetworkResponseListener<TResponse> listener) {
        // Create actual HTTP
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
