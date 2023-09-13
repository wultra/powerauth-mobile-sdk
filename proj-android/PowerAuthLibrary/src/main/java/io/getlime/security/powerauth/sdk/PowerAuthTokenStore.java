/*
 * Copyright 2017 Wultra s.r.o.
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

package io.getlime.security.powerauth.sdk;

import android.content.Context;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import androidx.annotation.RequiresApi;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.endpoints.CreateTokenEndpoint;
import io.getlime.security.powerauth.networking.endpoints.RemoveTokenEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.model.entity.TokenResponsePayload;
import io.getlime.security.powerauth.networking.model.request.TokenRemoveRequest;
import io.getlime.security.powerauth.networking.response.IGenerateTokenHeaderListener;
import io.getlime.security.powerauth.networking.response.IGetTokenListener;
import io.getlime.security.powerauth.networking.response.IRemoveTokenListener;
import io.getlime.security.powerauth.networking.response.ITimeSynchronizationListener;
import io.getlime.security.powerauth.sdk.impl.*;
import io.getlime.security.powerauth.system.PowerAuthLog;

/**
 * The {@code PowerAuthTokenStore} provides interface for managing access tokens.
 * The class is using {@link Keychain} as underlying storage for received data.
 *
 * Note that the whole store's interface is thread safe, but it's not recommended to
 * query for the same token in overlapping asynchronous requests. This usage may lead
 * to leaking tokens on the PowerAuth server.
 */
public class PowerAuthTokenStore {

    /**
     * Internal lock
     */
    private final ReentrantLock lock;
    /**
     * Reference to parent {@link PowerAuthSDK} object
     */
    private final PowerAuthSDK sdk;
    /**
     * Reference to {@link Keychain} for persistent storage purposes
     */
    private final Keychain keychain;
    /**
     * Reference to @{link HttpClient} for networking purposes
     */
    private final HttpClient httpClient;
    /**
     * A dictionary mapping token's name to private token's data. This is the in-memory cache
     * which speeds up querying for tokens.
     */
    private final HashMap<String, PowerAuthPrivateTokenData> localTokens;
    /**
     * A prefix for all data stored to the keychain.
     */
    private final String keychainKeyPrefix;
    /**
     * Map of grouped HTTP requests that create token.
     */
    private final Map<String, GetAccessTokenTask> createTokenRequests;


    /**
     * Constructs a new token store with references to parent {@link PowerAuthSDK}, {@link Keychain}
     * as storage and {@link HttpClient} for networking.
     *
     * @param sdk a parent object which created this instance
     * @param keychain a keychain as persistent storage
     * @param httpClient a HTTP client for networking
     */
    public PowerAuthTokenStore(
            @NonNull PowerAuthSDK sdk,
            @NonNull Keychain keychain,
            @NonNull HttpClient httpClient) {
        this.lock = sdk.getSharedLock();
        this.sdk = sdk;
        this.keychain = keychain;
        this.httpClient = httpClient;
        this.localTokens = new HashMap<>();
        this.keychainKeyPrefix = TOKENS_KEY_PREFIX + "__" + sdk.getConfiguration().getInstanceId() + "__";
        this.createTokenRequests = new HashMap<>(2);
    }

    /**
     * @return true if this instance can provide {@link PowerAuthToken} objects.
     */
    public boolean canRequestForAccessToken() {
        try {
            lock.lock();
            return sdk != null && sdk.hasValidActivation();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Internal method that determine whether it's possible to generate header from private token data.
     * @param privateTokenData Private token's data.
     * @return {@code true} if it's possible to generate header from private token data.
     */
    boolean canGenerateHeaderForToken(@NonNull PowerAuthPrivateTokenData privateTokenData) {
        try {
            lock.lock();
            if (sdk != null) {
                final String activationId = sdk.getActivationIdentifier();
                if (sdk.hasValidActivation() && activationId != null) {
                    return activationId.equals(privateTokenData.activationId);
                }
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Cancel all pending requests created in the store.
     */
    void cancelAllRequests() {
        try {
            lock.lock();
            for (GetAccessTokenTask task : createTokenRequests.values()) {
                task.cancel();
            }
            createTokenRequests.clear();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Create a new access token with given name for requested signature factors.
     * <p>
     * Note that the method is thread safe, but it's not recommended to request for the same token
     * name in parallel when the token is not created yet. If the method returns an asynchronous task,
     * then the pending HTTP request to the server has been issued, so you should not ask for
     * the same token while the task is in processing. You can use {@code PowerAuthTokenStore.hasLocalToken()} method
     * to check, whether the token is already in the local database.
     *
     * @param context Context
     * @param tokenName Name of requested token.
     * @param authentication An authentication instance specifying what factors should be used for token creation.
     * @param listener Listener with callbacks to receive a token.
     * @return {@link ICancelable} object associated with the running HTTP request or null if request has been processed synchronously.
     */
    public @Nullable
    ICancelable requestAccessToken(@NonNull final Context context, @NonNull final String tokenName, @NonNull PowerAuthAuthentication authentication, @NonNull final IGetTokenListener listener) {

        final Throwable error;
        final PowerAuthToken token;
        final ICancelable task;

        try {
            lock.lock();
            if (canRequestForAccessToken()) {
                final PowerAuthPrivateTokenData tokenData = getTokenData(context, tokenName);
                if (tokenData != null) {
                    token = createAccessToken(context, tokenData, authentication);
                    task = null;
                    error = token == null ? new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Different PowerAuthAuthentication used for the same token creation.") : null;
                } else {
                    token = null;
                    task = createAccessTokenTask(context, tokenName, authentication, listener);
                    error = task == null ? new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Different PowerAuthAuthentication used for the same token creation.") : null;
                }

            } else {
                token = null;
                task = null;
                error = new PowerAuthErrorException(PowerAuthErrorCodes.MISSING_ACTIVATION);
            }
        } finally {
            lock.unlock();
        }

        // Dispatch token or error when we already know the result.
        if (error != null) {
            sdk.dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onGetTokenFailed(error);
                }
            });
        } else if (token != null) {
            sdk.dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onGetTokenSucceeded(token);
                }
            });
        }
        return task;
    }

    /**
     * Create PowerAuthToken from private token data. The method also validates whether the requested
     * authentication match the factors that was used to token creation. If the token was created in
     * older SDK, then the token data stored in the keychain is automatically upgraded to the new format.
     *
     * @param context Android context.
     * @param tokenData Private token data.
     * @param authentication Authentication object.
     * @return {@link PowerAuthToken} instance or null if authentication contains a different factors.
     */
    private @Nullable PowerAuthToken createAccessToken(@NonNull Context context, @NonNull PowerAuthPrivateTokenData tokenData, @NonNull PowerAuthAuthentication authentication) {
        if (tokenData.authenticationFactors != 0) {
            // Token data contains information about factors.
            if (tokenData.authenticationFactors != authentication.getSignatureFactorsMask()) {
                PowerAuthLog.e("Using different PowerAuthAuthentication for token '" + tokenData.name + "' creation is not allowed.");
                return null;
            }
        } else {
            // Token was created in OLD SDK, so we should upgrade data and assign a currently requested authentication factors.
            PowerAuthLog.d("PowerAuthTokenStore: Upgrading authentication data for token '" + tokenData.name + "'");
            tokenData = new PowerAuthPrivateTokenData(tokenData.name, tokenData.identifier, tokenData.secret, tokenData.activationId, authentication.getSignatureFactorsMask());
            storeTokenData(context, tokenData, true);
        }
        return new PowerAuthToken(this, sdk.getTimeSynchronizationService(), tokenData);
    }

    /**
     * Method that create an asynchronous task and solve request grouping when application ask
     * for the same token in a very short time.
     *
     * @param context         Android context.
     * @param tokenName       Name of token.
     * @param authentication  Authentication object.
     * @param listener        Callback to application.
     * @return Asynchronous task or null in case that this application request has PowerAuthAuthentication with a different set of factors.
     */
    private @Nullable ICancelable createAccessTokenTask(@NonNull final Context context, @NonNull final String tokenName, @NonNull final PowerAuthAuthentication authentication, @NonNull final IGetTokenListener listener) {

        // Create completion that wraps callback to the application
        final ITaskCompletion<PowerAuthToken> completion = new ITaskCompletion<PowerAuthToken>() {
            @Override
            public void onSuccess(@NonNull PowerAuthToken powerAuthToken) {
                listener.onGetTokenSucceeded(powerAuthToken);
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                listener.onGetTokenFailed(failure);
            }
        };

        // Try to find grouped task in task map.
        GetAccessTokenTask groupedTask = createTokenRequests.get(tokenName);
        if (groupedTask != null) {
            if (groupedTask.authenticationFactors != authentication.getSignatureFactorsMask()) {
                PowerAuthLog.e("Using different PowerAuthAuthentication for token '" + tokenName + "' creation is not allowed.");
                return null;
            }
        }

        ICancelable childTask = groupedTask != null ? groupedTask.createChildTask(completion) : null;
        if (childTask == null) {
            // Prepare activationID in advance, to do not store null when activation is suddenly
            // removed during the operation.
            final String activationIdentifier = sdk.getActivationIdentifier();
            final int authenticationFactors = authentication.getSignatureFactorsMask();

            // Create new grouped task
            groupedTask = new GetAccessTokenTask(authentication.getSignatureFactorsMask(), lock, sdk.getCallbackDispatcher(), new GetAccessTokenTask.Listener() {

                @Override
                public void onTaskStart(@NonNull final GetAccessTokenTask groupedTask) {
                    // Execute HTTP request
                    final ICancelable httpTask = httpClient.post(
                            null,
                            new CreateTokenEndpoint(),
                            sdk.getCryptoHelper(context),
                            authentication,
                            new INetworkResponseListener<TokenResponsePayload>() {
                                @Override
                                public void onNetworkResponse(@NonNull TokenResponsePayload response) {
                                    // Success, try to construct a new PowerAuthPrivateTokenData object.
                                    final byte[] tokenSecretBytes = Base64.decode(response.getTokenSecret(), Base64.NO_WRAP);
                                    final PowerAuthPrivateTokenData newTokenData = new PowerAuthPrivateTokenData(tokenName, response.getTokenId(), tokenSecretBytes, activationIdentifier, authenticationFactors);
                                    if (newTokenData.hasValidData()) {
                                        // Store token data & report to listener
                                        groupedTask.complete(new PowerAuthToken(PowerAuthTokenStore.this, sdk.getTimeSynchronizationService(), newTokenData));
                                    } else {
                                        // Report encryption error
                                        groupedTask.complete(new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR));
                                    }
                                }

                                @Override
                                public void onNetworkError(@NonNull Throwable t) {
                                    groupedTask.complete(t);
                                }

                                @Override
                                public void onCancel() {
                                }
                            });
                    // Register HTTP task to the grouped task.
                    if (!groupedTask.addCancelableOperation(httpTask)) {
                        // This case should never happen, because we're at task start.
                        throw new IllegalStateException();
                    }
                }

                @Override
                public void onTaskComplete(@NonNull GetAccessTokenTask groupedTask, @Nullable PowerAuthToken token) {
                    if (token != null) {
                        storeTokenData(context, token.getTokenData(), false);
                    }
                    createTokenRequests.remove(tokenName);
                }
            });

            // Register newly created grouped task
            createTokenRequests.put(tokenName, groupedTask);

            // And finally, create new child task with the completion
            childTask = groupedTask.createChildTask(completion);
        }
        return childTask;
    }

    /**
     * Remove previously created access token from the server and from local database.
     * <p>
     * Note that if the removal request doesn't succeed, then the local token's data is not removed.
     * The method is thread safe, but it's not recommended to issue conflicting request for the same
     * token's name in parallel (e.g. create &amp; remove token at the same time).
     *
     * @param context Context
     * @param tokenName Name of token to be removed
     * @param listener Listener with callbacks.
     * @return {@code ICancelable} associated with the running server request or null in case of error.
     */
    public @Nullable
    ICancelable removeAccessToken(@NonNull final Context context, @NonNull final String tokenName, @NonNull final IRemoveTokenListener listener) {

        Throwable error = null;
        PowerAuthPrivateTokenData tokenData;

        try {
            lock.lock();
            tokenData = getTokenData(context, tokenName);
            if (tokenData == null) {
                error = new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_TOKEN);
            }
        } finally {
            lock.unlock();
        }

        if (error != null) {
            final Throwable err = error;
            sdk.dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onRemoveTokenFailed(err);
                }
            });
            return null;
        }

        // Launch HTTP request...
        final TokenRemoveRequest request = new TokenRemoveRequest();
        request.setTokenId(tokenData.identifier);

        return httpClient.post(
                request,
                new RemoveTokenEndpoint(),
                sdk.getCryptoHelper(context),
                PowerAuthAuthentication.possession(),
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(@NonNull Void aVoid) {
                        // On success, remove local token data & notify listener
                        removeLocalToken(context, tokenName);
                        listener.onRemoveTokenSucceeded();
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable t) {
                        listener.onRemoveTokenFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }


    /**
     * Quick check whether the token with name is in local database.
     *
     * @param context Context
     * @param tokenName Name of access token to be checked.
     * @return true if token exists in local database.
     */
    public boolean hasLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        try {
            lock.lock();
            return getTokenData(context, tokenName) != null;
        } finally {
            lock.unlock();
        }
    }


    /**
     * Returns token if the token is already in local database
     * @param context Context
     * @param tokenName Name of access token to be returned
     * @return token object or null if token's not in the local database
     */
    public @Nullable PowerAuthToken getLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        try {
            lock.lock();
            PowerAuthPrivateTokenData tokenData = getTokenData(context, tokenName);
            return tokenData != null ? new PowerAuthToken(this, sdk.getTimeSynchronizationService(), tokenData) : null;
        } finally {
            lock.unlock();
        }
    }


    /**
     * Remove token from local database. This method doesn't issue a HTTP request to the server.
     *
     * @param context Context
     * @param tokenName token to be removed
     */
    public void removeLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        try {
            lock.lock();
            removeLocalTokenImpl(context, getLocalIdentifier(tokenName));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Remove token from the local database. This private method can be called only if private lock
     * is acquired.
     *
     * @param context Context
     * @param identifier Token's identifier
     */
    private void removeLocalTokenImpl(@NonNull Context context, @NonNull String identifier) {
        // Remove token from keychain and local cache
        localTokens.remove(identifier);
        keychain.remove(identifier);
        // Update index
        HashSet<String> allIdentifiers = loadTokensIndex(context);
        allIdentifiers.remove(identifier);
        saveTokensIndex(context, allIdentifiers);
    }


    /**
     * Remove all tokens from local database. This method doesn't issue a HTTP request to the server.
     *
     * @param context Context
     */
    public void removeAllLocalTokens(@NonNull final Context context) {
        try {
            lock.lock();
            clearTokensIndex(context);
            localTokens.clear();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Generate authorization header with token with given name. Unlike {@link PowerAuthToken#generateHeader()}, this
     * asynchronous function guarantees that time used for the token digest calculation is always synchronized
     * with the server.
     *
     * @param context Android context.
     * @param tokenName Token name to use for header calculation.
     * @param listener Listener with callbacks.
     * @return {@code ICancelable} associated with the time synchronization.
     */
    @RequiresApi(api = Build.VERSION_CODES.N)
    @NonNull
    public ICancelable generateAuthorizationHeader(@NonNull final Context context, @NonNull String tokenName, @NonNull IGenerateTokenHeaderListener listener) {
        // Prepare cancelable task and completion closure.
        final CompositeCancelableTask cancelableTask = new CompositeCancelableTask(true);
        final BiConsumer<Throwable, PowerAuthAuthorizationHttpHeader> taskCompletion = (Throwable t, PowerAuthAuthorizationHttpHeader header) -> {
            sdk.getCallbackDispatcher().dispatchCallback(() -> {
                if (cancelableTask.setCompleted()) {
                    // Execute only if cancelable task is not canceled
                    if (header != null) {
                        if (header.isValid()) {
                            // Token is valid
                            listener.onGenerateTokenHeaderSucceeded(header);
                        } else {
                            listener.onGenerateTokenHeaderFailed(new PowerAuthErrorException(header.getPowerAuthErrorCode(), "Failed to generate token header"));
                        }
                    } else {
                        listener.onGenerateTokenHeaderFailed(t);
                    }
                }
            });
        };
        // Now get local token
        final PowerAuthToken token = getLocalToken(context, tokenName);
        if (token != null) {
            if (sdk.getTimeSynchronizationService().isTimeSynchronized()) {
                taskCompletion.accept(null, token.generateHeader());
            } else {
                // Time is not synchronized yet
                final ICancelable timeSynchronization = sdk.getTimeSynchronizationService().synchronizeTime(new ITimeSynchronizationListener() {
                    @Override
                    public void onTimeSynchronizationSucceeded() {
                        // Time is now synchronized, so generate header and report result back to the application.
                        taskCompletion.accept(null, token.generateHeader());
                    }

                    @Override
                    public void onTimeSynchronizationFailed(@NonNull Throwable t) {
                        taskCompletion.accept(t, null);
                    }
                });
                if (timeSynchronization != null) {
                    cancelableTask.addCancelable(timeSynchronization);
                }
            }
        } else {
            // Token not found.
            taskCompletion.accept(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_TOKEN, "Token not found"), null);
        }
        return cancelableTask;
    }

    /**
     * Returns private token data for given token name. This private method can be called only if
     * private lock is acquired.
     *
     * @param context Context
     * @param tokenName token to be requested
     * @return Private data object or null if token doesn't exist in local database.
     */
    private @Nullable PowerAuthPrivateTokenData getTokenData(@NonNull final Context context, @NonNull String tokenName) {
        final String activationId = sdk.getActivationIdentifier();
        final String identifier = getLocalIdentifier(tokenName);
        PowerAuthPrivateTokenData tokenData = localTokens.get(identifier);
        if (tokenData == null) {
            byte[] tokenBytes = keychain.getData(identifier);
            if (tokenBytes != null) {
                HashSet<String> index = loadTokensIndex(context);
                if (index.contains(identifier)) {
                    // Token data present and index says we know this object.
                    tokenData = PowerAuthPrivateTokenData.deserializeWithData(tokenBytes);
                    if (tokenData != null) {
                        if (tokenData.activationId == null) {
                            // Old data format, so we have to add an activationId and re-save
                            PowerAuthLog.d("PowerAuthTokenStore: Upgrading activation data for token '" + tokenName + "'");
                            tokenData = new PowerAuthPrivateTokenData(tokenData.name, tokenData.identifier, tokenData.secret, activationId, tokenData.authenticationFactors);
                            storeTokenData(context, tokenData, true);
                        }
                        localTokens.put(identifier, tokenData);
                    }
                } else {
                    // Token data is present, but index is clear.
                    PowerAuthLog.d("PowerAuthTokenStore: WARNING: Token '" + tokenName + "' data not in index.");
                    keychain.remove(identifier);
                }
            }
        } else {
            // Validate whether activation identifier is still the same.
            if (tokenData.activationId != null && activationId != null) {
                if (!tokenData.activationId.equals(activationId)) {
                    PowerAuthLog.e("KeychainTokenStore: WARNING: Token '" + tokenName + "' is no longer valid.");
                    removeLocalTokenImpl(context, identifier);
                }
            }
        }
        return tokenData;
    }

    /**
     * Stores private token data to the local database.
     *
     * @param context Context
     * @param tokenData Private data to be stored
     * @param upgrade If true, then this is the data upgrade, so the update of token index is not required.
     */
    private void storeTokenData(@NonNull final Context context, @NonNull PowerAuthPrivateTokenData tokenData, boolean upgrade) {
        try {
            lock.lock();
            // If parent SDK object has no longer a valid activation, then we should not store this token.
            // Looks like that the activation has been removed during the token acquiring from the server.
            if (!canRequestForAccessToken()) {
                return;
            }
            String identifier = getLocalIdentifier(tokenData.name);
            // Store data into local dictionary
            localTokens.put(identifier, tokenData);
            // Store to keychain
            keychain.putData(tokenData.getSerializedData(), identifier);
            if (!upgrade) {
                // And finally, update index
                HashSet<String> index = loadTokensIndex(context);
                index.add(identifier);
                saveTokensIndex(context, index);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * A prefix for all keys stored in the keychain.
     * The final key for data is constructed as {@code TOKENS_KEY_PREFIX + "__" + instanceId + "__" + Base64(tokenName.getBytes())}
     */
    private final static String TOKENS_KEY_PREFIX = "powerAuthToken";
    /**
     * A constant for index entry stored in the keychain. The final key is constructed as {@code TOKENS_KEY_PREFIX + "__" + instanceId + "__" + TOKENS_INDEX_ENTRY}
     */
    private final static String TOKENS_INDEX_ENTRY = "$$index$$";

    /**
     * Converts token name into token's local identifier.
     *
     * @param tokenName symbolic name of token
     * @return Unique local identifier for the token
     */
    private @NonNull String getLocalIdentifier(@NonNull String tokenName) {
        return keychainKeyPrefix + Base64.encodeToString(tokenName.getBytes(), Base64.NO_WRAP);
    }

    /**
     * @return true if provided identifier is a valid key for this instance of store.
     */
    private boolean isValidLocalIdentifier(@NonNull String identifier) {
        return identifier.startsWith(keychainKeyPrefix);
    }

    //
    // Tokens index
    //
    // The tokens index is keeping all token names in separate keychain entry. The token needs
    // this entry for correct {code removeAllLocalTokens()} method implementation.
    //

    /**
     * @return String with key to keychain for store tokens index.
     */
    private String getIndexKey() {
        return keychainKeyPrefix + TOKENS_INDEX_ENTRY;
    }

    /**
     * Saves index into the keychain.
     *
     * @param context Android Context object
     * @param index full index for tokens
     */
    private void saveTokensIndex(@NonNull final Context context, @NonNull HashSet<String> index) {

        final String joinedIdentifiers = TextUtils.join("\n", index.toArray());
        keychain.putString(joinedIdentifiers, getIndexKey());
    }

    /**
     * Loads tokens index from the keychain.
     *
     * @return set of strings, loaded from index, stored in keychain.
     */
    private HashSet<String> loadTokensIndex(@NonNull final Context context) {
        HashSet<String> index = new HashSet<>();
        final String joinedIdentifiers = keychain.getString(getIndexKey());
        if (joinedIdentifiers != null) {
            // Split previously joined identifiers
            String[] tokenIdentifiers = joinedIdentifiers.split("\\n");
            for (String identifier: tokenIdentifiers) {
                if (isValidLocalIdentifier(identifier)) {
                    index.add(identifier);
                }
            }
        }
        return index;
    }

    /**
     * Removes all tokens from keychain, including token index data.
     *
     * @param context Android Context object
     */
    private void clearTokensIndex(@NonNull final Context context) {
        HashSet<String> identifiers = loadTokensIndex(context);
        for (String id: identifiers) {
            keychain.remove(id);
        }
        keychain.remove(getIndexKey());
    }
}
