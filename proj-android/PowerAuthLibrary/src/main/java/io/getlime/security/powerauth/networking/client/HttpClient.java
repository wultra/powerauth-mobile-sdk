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

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.concurrent.Executor;

import io.getlime.security.powerauth.networking.interfaces.ICancellable;
import io.getlime.security.powerauth.networking.interfaces.IEndpointDefinition;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.sdk.PowerAuthAuthentication;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;

public class HttpClient {

    private final PowerAuthClientConfiguration configuration;
    private final String baseUrl;

    public HttpClient(@NonNull PowerAuthClientConfiguration configuration, @NonNull String baseUrl) {
        this.configuration = configuration;
        this.baseUrl = baseUrl;
    }

    /**
     * Posts a HTTP request with provided object to the REST endpoint.
     *
     * @param object object to be serialized into POST request
     * @param endpoint object defining the endpoint
     * @param helper cryptographic helper
     * @param executorProvider interface providing serialized or concurrent executors
     * @param listener response listener
     * @return {@link ICancellable} object which allows application cancel the pending operation
     */
    @NonNull
    public <TRequest, TResponse> ICancellable post(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @NonNull IPrivateCryptoHelper helper,
            @NonNull IExecutorProvider executorProvider,
            @NonNull INetworkResponseListener<TResponse> listener) {
        return post(object, endpoint, helper, null, executorProvider, listener);
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
     * @return {@link ICancellable} object which allows application cancel the pending operation
     */
    @NonNull
    public <TRequest, TResponse> ICancellable post(
            @Nullable TRequest object,
            @NonNull IEndpointDefinition<TResponse> endpoint,
            @NonNull IPrivateCryptoHelper helper,
            @Nullable PowerAuthAuthentication authentication,
            @NonNull IExecutorProvider executorProvider,
            @NonNull INetworkResponseListener<TResponse> listener) {

        final HttpRequestHelper<TRequest, TResponse> request = new HttpRequestHelper<>(object, endpoint, authentication);
        final HttpClientTask<TRequest, TResponse> task = new HttpClientTask<>(request, baseUrl, helper, configuration, listener);

        final Executor executor = endpoint.isSynchronized() ? executorProvider.getSerialExecutor() : executorProvider.getConcurrentExecutor();
        task.executeOnExecutor(executor, null, null);
        return task;
    }


}
