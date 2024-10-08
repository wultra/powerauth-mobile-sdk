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
import io.getlime.security.powerauth.core.EciesEncryptorScope;
import io.getlime.security.powerauth.core.ErrorCode;
import io.getlime.security.powerauth.core.ICoreTimeService;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.model.response.GetTemporaryKeyResponse;
import io.getlime.security.powerauth.system.PowerAuthLog;

import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code DefaultKeystoreService} class provides temporary encryption keys for ECIES encryption acquired from the
 * server. The key itself is stored in {@link io.getlime.security.powerauth.core.Session} instance and is available
 * for further encryption operations.
 */
public class DefaultKeystoreService implements IKeystoreService, GetTemporaryKeyTask.TaskCompletion {

    private final @NonNull ReentrantLock lock;
    private final @NonNull Session session;
    private final @NonNull ICoreTimeService timeService;
    private final @NonNull ICallbackDispatcher callbackDispatcher;
    private final @NonNull HttpClient httpClient;

    private final PublicKeyInfo applicationScopePublicKeyInfo;
    private final PublicKeyInfo activationScopePublicKeyInfo;

    /**
     * We don't want to use the key that's close to its expiration on the server. This constant specifies for how much
     * we move the expiration time to backward.
     */
    private static final long EXPIRATION_THRESHOLD = 10_000;

    /**
     * Service constructor.
     * @param timeService           Time synchronization service.
     * @param session               Instance of core Session.
     * @param callbackDispatcher    Callback dispatcher.
     * @param sharedLock            Reentrant lock shared across multiple SDK objects.
     * @param httpClient            HTTP client implementation.
     */
    public DefaultKeystoreService(
            @NonNull ICoreTimeService timeService,
            @NonNull Session session,
            @NonNull ICallbackDispatcher callbackDispatcher,
            @NonNull ReentrantLock sharedLock,
            @NonNull HttpClient httpClient) {
        this.lock = sharedLock;
        this.timeService = timeService;
        this.session = session;
        this.callbackDispatcher = callbackDispatcher;
        this.httpClient = httpClient;
        this.applicationScopePublicKeyInfo = new PublicKeyInfo(EciesEncryptorScope.APPLICATION);
        this.activationScopePublicKeyInfo = new PublicKeyInfo(EciesEncryptorScope.ACTIVATION);
    }

    @Override
    public boolean containsKeyForEncryptor(int scope) {
        try {
            lock.lock();
            if (session.hasPublicKeyForEciesScope(scope)) {
                final PublicKeyInfo publicKeyInfo = getPublicKeyInfoForScope(scope);
                if (publicKeyInfo.expiration >= 0 && (timeService.getCurrentTime() < publicKeyInfo.expiration - EXPIRATION_THRESHOLD)) {
                    return true;
                }
                PowerAuthLog.d("Removing expired public key for ECIES encryptor " + scope);
                publicKeyInfo.expiration = -1;
                session.removePublicKeyForEciesScope(scope);
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    @Override
    @Nullable
    public ICancelable createKeyForEncryptor(@EciesEncryptorScope int scope, @NonNull IPrivateCryptoHelper cryptoHelper, @NonNull ICreateKeyListener listener) {
        if (scope == EciesEncryptorScope.ACTIVATION && !session.hasValidActivation()) {
            callbackDispatcher.dispatchCallback(() -> listener.onCreateKeyFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE)));
            return null;
        }
        try {
            lock.lock();
            if (containsKeyForEncryptor(scope)) {
                callbackDispatcher.dispatchCallback(listener::onCreateKeySucceeded);
                return null;
            }
            final PublicKeyInfo publicKeyInfo = getPublicKeyInfoForScope(scope);
            GetTemporaryKeyTask mainTask = publicKeyInfo.task;
            if (mainTask == null) {
                mainTask = new GetTemporaryKeyTask(scope, cryptoHelper, lock, callbackDispatcher, httpClient, this);
                publicKeyInfo.task = mainTask;
                publicKeyInfo.timeSynchronizationTask = timeService.startTimeSynchronizationTask();
            }
            return mainTask.createChildTask(new ITaskCompletion<>() {
                @Override
                public void onSuccess(@NonNull GetTemporaryKeyResponse response) {
                    listener.onCreateKeySucceeded();
                }

                @Override
                public void onFailure(@NonNull Throwable failure) {
                    listener.onCreateKeyFailed(failure);
                }
            });
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void onGetTemporaryKeyTaskCompletion(@NonNull GetTemporaryKeyTask task, @Nullable GetTemporaryKeyResponse response) {
        final int scope = task.getScope();
        final PublicKeyInfo publicKeyInfo = getPublicKeyInfoForScope(scope);
        publicKeyInfo.task = null;
        if (response != null) {
            final int errorCode = session.setPublicKeyForEciesScope(scope, response.getPublicKey(), response.getKeyId());
            if (errorCode == ErrorCode.OK) {
                publicKeyInfo.expiration = response.getExpiration();
                timeService.completeTimeSynchronizationTask(publicKeyInfo.timeSynchronizationTask, response.getServerTime());
                PowerAuthLog.d("Saving public key for ECIES encryptor " + scope);
            } else {
                PowerAuthLog.e("Failed to update public key for ECIES encryption. Code = " + errorCode);
            }
        }
        publicKeyInfo.timeSynchronizationTask = null;
    }

    /**
     * Get instance of {@link PublicKeyInfo} class depending on the scope.
     * @param scope Scope of encryption.
     * @return Instance of {@link PublicKeyInfo} class depending on the scope.
     */
    @NonNull
    private PublicKeyInfo getPublicKeyInfoForScope(@EciesEncryptorScope int scope) {
        return scope == EciesEncryptorScope.APPLICATION ? applicationScopePublicKeyInfo : activationScopePublicKeyInfo;
    }

    /**
     * Internal class containing additional information about retrieved public key.
     */
    private static class PublicKeyInfo {
        /**
         * Scope of the key.
         */
        final @EciesEncryptorScope int scope;
        /**
         * If positive number, then contain timestamp when the key expires on the server.
         */
        long expiration;
        /**
         * If not null, then service is currently retrieving the key from the server.
         */
        GetTemporaryKeyTask task;
        /**
         * Time synchronization task.
         */
        Object timeSynchronizationTask;

        PublicKeyInfo(@EciesEncryptorScope int scope) {
            this.scope = scope;
            this.expiration = -1;
            this.task = null;
            this.timeSynchronizationTask = null;
        }
    }
}
