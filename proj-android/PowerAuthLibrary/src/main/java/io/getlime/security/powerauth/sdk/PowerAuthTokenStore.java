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
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;

import java.util.HashMap;
import java.util.HashSet;

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
import io.getlime.security.powerauth.networking.response.IGetTokenListener;
import io.getlime.security.powerauth.networking.response.IRemoveTokenListener;
import io.getlime.security.powerauth.sdk.impl.PowerAuthPrivateTokenData;

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
        this.sdk = sdk;
        this.keychain = keychain;
        this.httpClient = httpClient;
        this.localTokens = new HashMap<>();
        this.keychainKeyPrefix = TOKENS_KEY_PREFIX + "__" + sdk.getConfiguration().getInstanceId() + "__";
    }

    /**
     * @return true if this instance can provide {@link PowerAuthToken} objects.
     */
    public synchronized boolean canRequestForAccessToken() {
        return sdk != null && sdk.hasValidActivation();
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

        Throwable error = null;
        PowerAuthPrivateTokenData tokenData = null;

        synchronized (this) {
            if (this.canRequestForAccessToken()) {
                tokenData = this.getTokenData(context, tokenName);
            } else {
                error = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeMissingActivation);
            }
        }

        // If there's private data or error available, then report that immediately to the listener.
        if (error != null) {
            final Throwable err = error;
            sdk.dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onGetTokenFailed(err);
                }
            });
            return null;
        } else if (tokenData != null) {
            final PowerAuthToken token = new PowerAuthToken(this, tokenData);
            sdk.dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onGetTokenSucceeded(token);
                }
            });
            return null;
        }

        // Execute HTTP request
        return httpClient.post(
                null,
                new CreateTokenEndpoint(),
                sdk.getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<TokenResponsePayload>() {
                    @Override
                    public void onNetworkResponse(TokenResponsePayload response) {
                        // Success, try to construct a new PowerAuthPrivateTokenData object.
                        final byte[] tokenSecretBytes = Base64.decode(response.getTokenSecret(), Base64.NO_WRAP);
                        final PowerAuthPrivateTokenData newTokenData = new PowerAuthPrivateTokenData(tokenName, response.getTokenId(), tokenSecretBytes);
                        if (newTokenData.hasValidData()) {
                            // Store token data & report to listener
                            storeTokenData(context, newTokenData);
                            listener.onGetTokenSucceeded(new PowerAuthToken(PowerAuthTokenStore.this, newTokenData));
                        } else {
                            // Report encryption error
                            listener.onGetTokenFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeEncryptionError));
                        }
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
                        listener.onGetTokenFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });

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

        synchronized (this) {
            tokenData = getTokenData(context, tokenName);
            if (tokenData == null) {
                error = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidToken);
            }
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

        final PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.usePossession = true;

        return httpClient.post(
                request,
                new RemoveTokenEndpoint(),
                sdk.getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(Void aVoid) {
                        // On success, remove local token data & notify listener
                        removeLocalToken(context, tokenName);
                        listener.onRemoveTokenSucceeded();
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
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
    public synchronized boolean hasLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        return this.getTokenData(context, tokenName) != null;
    }


    /**
     * Returns token if the token is already in local database
     * @param context Context
     * @param tokenName Name of access token to be returned
     * @return token object or null if token's not in the local database
     */
    public synchronized @Nullable PowerAuthToken getLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        PowerAuthPrivateTokenData tokenData = this.getTokenData(context, tokenName);
        if (tokenData != null) {
            return new PowerAuthToken(this, tokenData);
        }
        return null;
    }


    /**
     * Remove token from local database. This method doesn't issue a HTTP request to the server.
     *
     * @param context Context
     * @param tokenName token to be removed
     */
    public synchronized void removeLocalToken(@NonNull final Context context, @NonNull String tokenName) {
        String identifier = this.getLocalIdentifier(tokenName);
        this.localTokens.remove(identifier);
        this.keychain.remove(identifier);
        // Update index
        HashSet<String> allIdentifiers = this.loadTokensIndex(context);
        allIdentifiers.remove(identifier);
        this.saveTokensIndex(context, allIdentifiers);
    }


    /**
     * Remove all tokens from local database. This method doesn't issue a HTTP request to the server.
     *
     * @param context Context
     */
    public synchronized void removeAllLocalTokens(@NonNull final Context context) {
        this.clearTokensIndex(context);
        this.localTokens.clear();
    }

    /**
     * Returns private token data for given token name. Note that this private method has to be
     * called from the synchronized block.
     *
     * @param context Context
     * @param tokenName token to be requested
     * @return Private data object or null if token doesn't exist in local database.
     */
    private @Nullable PowerAuthPrivateTokenData getTokenData(@NonNull final Context context, @NonNull String tokenName) {
        // Note, must be called from another synchronized method...
        String identifier = this.getLocalIdentifier(tokenName);
        PowerAuthPrivateTokenData tokenData = this.localTokens.get(identifier);
        if (tokenData == null) {
            byte[] tokenBytes = this.keychain.getData(identifier);
            if (tokenBytes != null) {
                tokenData = PowerAuthPrivateTokenData.deserializeWithData(tokenBytes);
                if (tokenData != null) {
                    this.localTokens.put(identifier, tokenData);
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
     */
    private synchronized void storeTokenData(@NonNull final Context context, @NonNull PowerAuthPrivateTokenData tokenData) {
        // If parent SDK object has no longer a valid activation, then we should not store this token.
        // Looks like that the activation has been removed during the token acquiring from the server.
        if (!this.canRequestForAccessToken()) {
            return;
        }
        String identifier = this.getLocalIdentifier(tokenData.name);
        // Store data into local dictionary
        this.localTokens.put(identifier, tokenData);
        // Store to keychain
        this.keychain.putData(tokenData.getSerializedData(), identifier);

        // And finally, update index
        HashSet<String> index = loadTokensIndex(context);
        index.add(identifier);
        this.saveTokensIndex(context, index);
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
        this.keychain.putString(joinedIdentifiers, this.getIndexKey());
    }

    /**
     * Loads tokens index from the keychain.
     *
     * @return set of strings, loaded from index, stored in keychain.
     */
    private HashSet<String> loadTokensIndex(@NonNull final Context context) {
        HashSet<String> index = new HashSet<>();
        final String joinedIdentifiers = this.keychain.getString(this.getIndexKey());
        if (joinedIdentifiers != null) {
            // Split previously joined identifiers
            String[] tokenIdentifiers = joinedIdentifiers.split("\\n");
            for (String identifier: tokenIdentifiers) {
                if (this.isValidLocalIdentifier(identifier)) {
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
            this.keychain.remove(id);
        }
        this.keychain.remove(this.getIndexKey());
    }
}
