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

import io.getlime.security.powerauth.core.CoreAlgorithm;
import io.getlime.security.powerauth.core.CoreEncryptorFactory;
import io.getlime.security.powerauth.core.CoreEncryptorScope;
import io.getlime.security.powerauth.core.CoreSession;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;

import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code DefaultKeystoreService} class provides temporary encryption keys for End-To-End encryption acquired from the
 * server. The key itself is stored in {@link io.getlime.security.powerauth.core.CoreSession} instance and is available
 * for further encryption operations.
 */
public class DefaultKeystoreService implements IKeystoreService, GetTemporaryKeyTask.TaskCompletion {

    private final @NonNull ReentrantLock lock;
    private final @NonNull CoreSession session;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private final @NonNull CoreHttpClient httpClient;


    /**
     * Service constructor.
     * @param session               Instance of core CoreSession.
     * @param callbackDispatcher    Callback dispatcher.
     * @param sharedLock            Reentrant lock shared across multiple SDK objects.
     * @param httpClient            HTTP client implementation.
     */
    public DefaultKeystoreService(
            @NonNull CoreSession session,
            @NonNull ICallbackDispatcher callbackDispatcher,
            @NonNull ReentrantLock sharedLock,
            @NonNull CoreHttpClient httpClient) {
        this.lock = sharedLock;
        this.session = session;
        this.callbackDispatcher = callbackDispatcher;
        this.httpClient = httpClient;
    }

    @Override
    public boolean containsKeyForEncryptor(@CoreEncryptorScope int scope) {
        return getEncryptorFactory().hasTemporaryKeyForScope(scope);
    }

    @Nullable
    @Override
    public ICancelable createKeyForEncryptor(@CoreEncryptorScope int scope, @NonNull ICreateKeyListener listener) {
        try {
            lock.lock();
            final CoreEncryptorFactory encryptorFactory = getEncryptorFactory();
            if (encryptorFactory.hasTemporaryKeyForScope(scope)) {
                // Key is available, report success and return immediately,
                callbackDispatcher.dispatchCallback(listener::onCreateKeySucceeded);
                return null;
            }
            // Key is unavailable, create task for it.
            return getTaskForScope(encryptorFactory, scope).createChildTask(new ITaskCompletion<>() {
                @Override
                public void onSuccess(@NonNull Boolean aBoolean) {
                    callbackDispatcher.dispatchCallback(listener::onCreateKeySucceeded);
                }

                @Override
                public void onFailure(@NonNull Throwable failure) {
                    callbackDispatcher.dispatchCallback(() -> listener.onCreateKeyFailed(failure));
                }
            });

        } finally {
            lock.unlock();
        }
    }

    private GetTemporaryKeyTask applicationScopedTask;
    private GetTemporaryKeyTask activationScopedTask;

    @Override
    public void onGetTemporaryKeyTaskCompletion(@NonNull GetTemporaryKeyTask task, boolean success) {
        try {
            lock.lock();
            if (task.equals(applicationScopedTask)) {
                applicationScopedTask = null;
            } else if (task.equals(activationScopedTask)) {
                activationScopedTask = null;
            }
        } finally {
            lock.unlock();
        }
    }

    @NonNull
    private GetTemporaryKeyTask getTaskForScope(@NonNull CoreEncryptorFactory encryptorFactory, @CoreEncryptorScope int scope) {
        try {
            lock.lock();
            if (scope == CoreEncryptorScope.APPLICATION) {
                if (applicationScopedTask == null) {
                    applicationScopedTask = new GetTemporaryKeyTask(scope, lock, callbackDispatcher, httpClient, encryptorFactory, this);
                }
                return applicationScopedTask;
            } else {
                if (activationScopedTask == null) {
                    activationScopedTask = new GetTemporaryKeyTask(scope, lock, callbackDispatcher, httpClient, encryptorFactory, this);
                }
                return activationScopedTask;
            }
        } finally {
            lock.unlock();
        }
    }
    private CoreEncryptorFactory coreEncryptorFactory;
    private @CoreAlgorithm int coreAlgorithm;

    /**
     * @return Instance of {@link CoreEncryptorFactory}.
     */
    @NonNull
    private CoreEncryptorFactory getEncryptorFactory() {
        try {
            lock.lock();
            // TODO: session should manage the reference to factory.
            int currentAlgorithm = session.getCurrentAlgorithm();
            if (coreEncryptorFactory == null) {
                coreEncryptorFactory = session.getEncryptorFactory();
                coreAlgorithm = currentAlgorithm;
            } else {
                if (currentAlgorithm != coreAlgorithm) {
                    coreEncryptorFactory = session.getEncryptorFactory();
                    coreAlgorithm = currentAlgorithm;
                }
            }
            return coreEncryptorFactory;
        } finally {
            lock.unlock();
        }
    }
}
