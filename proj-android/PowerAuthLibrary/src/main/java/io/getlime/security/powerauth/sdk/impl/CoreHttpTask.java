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

import io.getlime.security.powerauth.core.CoreException;
import io.getlime.security.powerauth.core.CoreRequest;
import io.getlime.security.powerauth.core.CoreTask;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;

/**
 * The {@code CoreHttpTask} wraps {@link CoreTask} and executes series of requests specified in
 * the task.
 * @param <TResponse> Type of response. Use {@link Object} if there's no response.
 */
public class CoreHttpTask<TResponse> extends CompositeCancelableTask {

    private final CoreTask<TResponse> task;
    private final CoreHttpClient httpClient;
    private final INetworkResponseListener<TResponse> listener;

    /**
     * Construct task with required parameters.
     * @param task {@link CoreTask} containing sequence of requests to execute.
     * @param httpClient Parent {@link CoreHttpClient}.
     * @param listener Callback listener interface.
     */
    public CoreHttpTask(@NonNull CoreTask<TResponse> task,
                        @NonNull CoreHttpClient httpClient,
                        @NonNull INetworkResponseListener<TResponse> listener) {
        super(true);
        this.task = task;
        this.httpClient = httpClient;
        this.listener = listener;
    }

    /**
     * Start the task.
     */
    public void start() {
        processNext();
    }

    /**
     * Process the next request, if there's any. If no next request is specified, then set
     * the whole task as complete.
     */
    private void processNext() {
        try {
            final CoreRequest<Object> request = task.getNextRequest();
            if (request == null) {
                if (task.isDone()) {
                    setFinished();
                } else {
                    setFinished(new PowerAuthErrorException(PowerAuthErrorCodes.OPERATION_CANCELED, "Task did not create next request"));
                }
            } else {
                addCancelable(httpClient.post(request, new INetworkResponseListener<>() {
                    @Override
                    public void onNetworkResponse(@Nullable Object o) {
                        processNext();
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        processNext();
                    }

                    @Override
                    public void onCancel() {
                        if (setCompleted()) {
                            listener.onCancel();
                        }
                    }
                }));
            }
        } catch (CoreException exception) {
            setFinished(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, exception));
        }
    }

    /**
     * Set the task finished with an error.
     * @param throwable Error to set as the result of the operation.
     */
    private void setFinished(@NonNull Throwable throwable) {
        if (setCompleted()) {
            listener.onNetworkError(throwable);
        }
    }

    /**
     * Set the task finished with the success.
     */
    private void setFinished() {
        if (setCompleted()) {
            try {
                final TResponse response = task.getResponseObject();
                listener.onNetworkResponse(response);
            } catch (CoreException exception) {
                listener.onNetworkError(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, exception));
            }
        }
    }
}
