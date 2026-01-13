/*
 * Copyright 2024 Wultra s.r.o.
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
import io.getlime.security.powerauth.core.*;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;

import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code GetTemporaryKeyTask} class implements getting temporary encryption key from the server.
 */
public class GetTemporaryKeyTask extends GroupedTask<Boolean> {

    /**
     * The task completion callback.
     */
    public interface TaskCompletion {
        /**
         * Function is called once the {@code GetTemporaryKeyTask} finishes its job.
         * @param task The completed task.
         * @param success If true, task succeeded.
         */
        void onGetTemporaryKeyTaskCompletion(@NonNull GetTemporaryKeyTask task, boolean success);
    }

    private final CoreEncryptorFactory coreEncryptorFactory;
    private final CoreHttpClient httpClient;
    private final TaskCompletion taskCompletion;
    private final @CoreEncryptorScope int scope;

    /**
     * Construct task with required parameters.
     * @param scope         Scope of key to obtain from the server.
     * @param sharedLock    Reentrant lock shared across multiple SDK objects.
     * @param dispatcher    Callback dispatcher.
     * @param httpClient    HTTP client.
     * @param completion    Listener to call once the task is completed.
     */
    public GetTemporaryKeyTask(
            @CoreEncryptorScope int scope,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher dispatcher,
            @NonNull CoreHttpClient httpClient,
            @NonNull CoreEncryptorFactory coreEncryptorFactory,
            @NonNull TaskCompletion completion) {
        super("GetTemporaryKey_" + scope, sharedLock, dispatcher);
        this.scope = scope;
        this.coreEncryptorFactory = coreEncryptorFactory;
        this.httpClient = httpClient;
        this.taskCompletion = completion;
    }

    /**
     * Return the scope of the temporary key.
     * @return Scope of the temporary key.
     */
    public @CoreEncryptorScope int getScope() {
        return scope;
    }

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        try {
            CoreRequest<Object> request = coreEncryptorFactory.fetchTemporaryKeyForScope(scope);
            httpClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    complete(true);
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    complete(throwable);
                }

                @Override
                public void onCancel() {
                    // Do nothing...
                }
            });
        } catch (Throwable t) {
            complete(PowerAuthErrorException.wrapException(t));
        }
    }

    @Override
    public void onGroupedTaskComplete(@Nullable Boolean response, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(response, failure);
        taskCompletion.onGetTemporaryKeyTaskCompletion(this, failure == null);
    }
}
