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
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Pair;

import java.util.HashMap;
import java.util.HashSet;

import io.getlime.security.powerauth.core.ECIESCryptogram;
import io.getlime.security.powerauth.core.ECIESEncryptor;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.PA2Keychain;
import io.getlime.security.powerauth.networking.client.PA2Client;
import io.getlime.security.powerauth.networking.endpoints.PA2CreateTokenEndpoint;
import io.getlime.security.powerauth.networking.endpoints.PA2RemoveTokenEndpoint;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.IGetTokenListener;
import io.getlime.security.powerauth.networking.response.IRemoveTokenListener;
import io.getlime.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import io.getlime.security.powerauth.rest.api.model.request.v2.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v2.TokenRemoveResponse;
import io.getlime.security.powerauth.sdk.impl.PowerAuthAuthorizationHttpHeader;
import io.getlime.security.powerauth.sdk.impl.PowerAuthPrivateTokenData;

/**
 * The {@code PowerAuthTokenStore} provides interface for managing access tokens.
 * The class is using {@link PA2Keychain} as underlying storage for received data.
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
     * Reference to {@link PA2Keychain} for persistent storage purposes
     */
    private final PA2Keychain keychain;
    /**
     * Reference to @{link PA2Client} for networking purposes
     */
    private final PA2Client httpClient;
    /**
     * A dictionary mapping token's name to private token's data. This is the in-memory cache
     * which speeds up querying for tokens.
     */
    private final HashMap<String, PowerAuthPrivateTokenData> localTokens;
    /**
     * A encryptor created from server's master public key.
     */
    private final ECIESEncryptor encryptor;
    /**
     * A prefix for all data stored to the keychain.
     */
    private final String keychainKeyPrefix;


    /**
     * Constructs a new token store with references to parent {@link PowerAuthSDK}, {@link PA2Keychain}
     * as storage and {@link PA2Client} for networking.
     *
     * @param sdk a parent object which created this instance
     * @param keychain a keychain as persistent storage
     * @param httpClient a HTTP client for networking
     */
    public PowerAuthTokenStore(
            @NonNull PowerAuthSDK sdk,
            @NonNull PA2Keychain keychain,
            @NonNull PA2Client httpClient) {
        this.sdk = sdk;
        this.keychain = keychain;
        this.httpClient = httpClient;
        this.localTokens = new HashMap<>();
        this.encryptor = new ECIESEncryptor(httpClient.getConfiguration().getMasterServerPublicKey(), null, null);
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
     * @return {@code AsyncTask} associated with the running server request or null if request has been processed synchronously.
     */
    public @Nullable AsyncTask requestAccessToken(@NonNull final Context context, @NonNull final String tokenName, @NonNull PowerAuthAuthentication authentication, @NonNull final IGetTokenListener listener) {

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
            listener.onGetTokenFailed(error);
            return null;
        } else if (tokenData != null) {
            listener.onGetTokenSucceeded(new PowerAuthToken(this, tokenData));
            return null;
        }
        // Launch HTTP request

        // 1) Encrypt empty data to get ephemeral key
        final Pair<ECIESEncryptor, ECIESCryptogram> pair = encryptor.encryptRequestSynchronized(null);
        if (pair == null) {
            listener.onGetTokenFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeEncryptionError));
            return null;
        }
        final ECIESEncryptor decryptor = pair.first;
        final ECIESCryptogram cryptogram = pair.second;

        // 2) Build post data
        final TokenCreateRequest request = new TokenCreateRequest();
        request.setEphemeralPublicKey(cryptogram.getKeyBase64());
        final Pair<byte[], String> postData = httpClient.serializeRequestObject(request);

        // 3) Sign that post data
        final PowerAuthAuthorizationHttpHeader authHeader = sdk.requestSignatureWithAuthentication(context, authentication, "POST", PA2CreateTokenEndpoint.CREATE_TOKEN, postData.first);
        if (!authHeader.isValid()) {
            listener.onGetTokenFailed(new PowerAuthErrorException(authHeader.powerAuthErrorCode));
            return null;
        }
        final HashMap<String, String> headers = new HashMap<>();
        headers.put(authHeader.getKey(), authHeader.getValue());

        // 4) Execute HTTP request
        return httpClient.createToken(headers, request, new INetworkResponseListener<TokenCreateResponse>() {
            @Override
            public void onNetworkResponse(TokenCreateResponse tokenCreateResponse) {
                // On success, we have to decrypt response
                PowerAuthPrivateTokenData newTokenData = decryptTokenData(decryptor, tokenCreateResponse, tokenName);
                if (newTokenData != null) {
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
                // On failure, just notify listener about that error
                listener.onGetTokenFailed(t);
            }
        });
    }

    /**
     * Decrypt response received from server and create a new {@link PowerAuthPrivateTokenData} token data.
     *
     * @param decryptor A decryptor for response data decryption
     * @param response An encrypted response
     * @param tokenName Name of token
     * @return Private token's data or null in case of failure.
     */
    private @Nullable PowerAuthPrivateTokenData decryptTokenData(ECIESEncryptor decryptor, TokenCreateResponse response, String tokenName) {
        final ECIESCryptogram cryptogram = new ECIESCryptogram(response.getEncryptedData(), response.getMac());
        final byte[] decryptedPayload = decryptor.decryptResponse(cryptogram);
        if (decryptedPayload == null) {
            return null;
        }
        TokenResponsePayload payload = httpClient.deserializePlainResponse(decryptedPayload, TokenResponsePayload.class);
        if (payload.getTokenId() == null || payload.getTokenSecret() == null) {
            return null;
        }
        final byte[] tokenSecretBytes = Base64.decode(payload.getTokenSecret(), Base64.NO_WRAP);
        final PowerAuthPrivateTokenData tokenData = new PowerAuthPrivateTokenData(tokenName, payload.getTokenId(), tokenSecretBytes);
        return tokenData.hasValidData() ? tokenData : null;
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
     * @return {@code AsyncTask} associated with the running server request or null in case of error.
     */
    public @Nullable AsyncTask removeAccessToken(@NonNull final Context context, @NonNull final String tokenName, @NonNull final IRemoveTokenListener listener) {

        Throwable error = null;
        PowerAuthPrivateTokenData tokenData;

        synchronized (this) {
            tokenData = getTokenData(context, tokenName);
            if (tokenData == null) {
                error = new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidToken);
            }
        }

        if (error != null) {
            listener.onRemoveTokenFailed(error);
            return null;
        }

        // Launch HTTP request...

        // 1) Build request data
        final TokenRemoveRequest request = new TokenRemoveRequest();
        request.setTokenId(tokenData.identifier);
        final Pair<byte[], String> postData = httpClient.serializeRequestObject(request);

        // 2) Sign request data with possession factor
        final PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.usePossession = true;
        //
        PowerAuthAuthorizationHttpHeader authHeader = sdk.requestSignatureWithAuthentication(context, authentication, "POST", PA2RemoveTokenEndpoint.REMOVE_TOKEN, postData.first);
        if (!authHeader.isValid()) {
            listener.onRemoveTokenFailed(new PowerAuthErrorException(authHeader.powerAuthErrorCode));
            return null;
        }
        final HashMap<String, String> headers = new HashMap<>();
        headers.put(authHeader.getKey(), authHeader.getValue());

        // 3) Execute HTTP request
        return httpClient.removeToken(headers, request, new INetworkResponseListener<TokenRemoveResponse>() {
            @Override
            public void onNetworkResponse(TokenRemoveResponse tokenRemoveResponse) {
               // On success, remove local token data & notify listener
               removeLocalToken(context, tokenName);
               listener.onRemoveTokenSucceeded();
            }

            @Override
            public void onNetworkError(Throwable t) {
                // On failure, just notify listener about that error
                listener.onRemoveTokenFailed(t);
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
        this.keychain.removeDataForKey(context, identifier);
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
            byte[] tokenBytes = this.keychain.dataForKey(context, identifier);
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
        this.keychain.putDataForKey(context, tokenData.getSerializedData(), identifier);

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
     */
    private @NonNull String getLocalIdentifier(@NonNull String tokenName) {
        return keychainKeyPrefix + Base64.encodeToString(tokenName.getBytes(), Base64.NO_WRAP);
    }

    /**
     * Returns true if provided identifier is a valid key for this instance of store.
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
     * Returns key to keychain for store tokens index.
     */
    private final String getIndexKey() {
        return keychainKeyPrefix + TOKENS_INDEX_ENTRY;
    }

    /**
     * Saves index into keychain.
     */
    private void saveTokensIndex(@NonNull final Context context, @NonNull HashSet<String> index) {

        final String joinedIdentifiers = TextUtils.join("\n", index.toArray());
         this.keychain.putStringForKey(context, joinedIdentifiers, this.getIndexKey());
    }

    /**
     * Returns set of strings, loaded from index, stored in keychain.
     */
    private HashSet<String> loadTokensIndex(@NonNull final Context context) {
        HashSet<String> index = new HashSet<>();
        final String joinedIdentifiers = this.keychain.stringForKey(context, this.getIndexKey());
        if (joinedIdentifiers != null) {
            // Split previously joinded indentifiers
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
     */
    private void clearTokensIndex(@NonNull final Context context) {
        HashSet<String> identifiers = loadTokensIndex(context);
        for (String id: identifiers) {
            this.keychain.removeDataForKey(context, id);
        }
        this.keychain.removeDataForKey(context, this.getIndexKey());
    }
}
