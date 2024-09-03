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

import android.text.TextUtils;
import android.util.Base64;
import android.util.Pair;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.gson.reflect.TypeToken;
import io.getlime.security.powerauth.core.*;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.client.JsonSerialization;
import io.getlime.security.powerauth.networking.endpoints.GetTemporaryKeyEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.model.entity.JwtHeader;
import io.getlime.security.powerauth.networking.model.entity.JwtObject;
import io.getlime.security.powerauth.networking.model.request.GetTemporaryKeyRequest;
import io.getlime.security.powerauth.networking.model.response.GetTemporaryKeyResponse;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The {@code GetTemporaryKeyTask} class implements getting temporary encryption key from the server.
 */
public class GetTemporaryKeyTask extends GroupedTask<GetTemporaryKeyResponse> {

    /**
     * The task completion callback.
     */
    public interface TaskCompletion {
        /**
         * Function is called once the {@code GetTemporaryKeyTask} finishes its job.
         * @param task The completed task.
         * @param response Response received from the server. If null, then task failed to get the response.
         */
        void onGetTemporaryKeyTaskCompletion(@NonNull GetTemporaryKeyTask task, @Nullable GetTemporaryKeyResponse response);
    }

    private final IPrivateCryptoHelper cryptoHelper;
    private final HttpClient httpClient;
    private final TaskCompletion taskCompletion;
    private final @EciesEncryptorScope int scope;
    private final JsonSerialization serialization;

    /**
     * Construct task with required parameters.
     * @param scope         Scope of key to obtain from the server.
     * @param cryptoHelper  Instance of {@link IPrivateCryptoHelper} interface.
     * @param sharedLock    Reentrant lock shared across multiple SDK objects.
     * @param dispatcher    Callback dispatcher.
     * @param httpClient    HTTP client.
     * @param completion    Listener to call once the task is completed.
     */
    public GetTemporaryKeyTask(
            @EciesEncryptorScope int scope,
            @NonNull IPrivateCryptoHelper cryptoHelper,
            @NonNull ReentrantLock sharedLock,
            @NonNull ICallbackDispatcher dispatcher,
            @NonNull HttpClient httpClient,
            @NonNull TaskCompletion completion) {
        super("GetTemporaryKey", sharedLock, dispatcher);
        this.scope = scope;
        this.cryptoHelper = cryptoHelper;
        this.httpClient = httpClient;
        this.taskCompletion = completion;
        this.serialization = new JsonSerialization();
    }

    /**
     * Return the scope of the temporary key.
     * @return Scope of the temporary key.
     */
    public @EciesEncryptorScope int getScope() {
        return scope;
    }

    /**
     * @return {@code true} if this task is configured to get the temporary key in application scope.
     */
    private boolean isApplicationScope() {
        return scope == EciesEncryptorScope.APPLICATION;
    }

    @Override
    public void onGroupedTaskStart() {
        super.onGroupedTaskStart();
        try {
            final Pair<GetTemporaryKeyRequest, JwtObject> requestPair = prepareRequestJwt();
            if (requestPair == null) {
                return;
            }
            ICancelable cancelable = httpClient.post(requestPair.first, new GetTemporaryKeyEndpoint(), cryptoHelper, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@NonNull JwtObject jwtObject) {
                    try {
                        final GetTemporaryKeyResponse response = processResponseJwt(jwtObject);
                        validateResponse(requestPair.first, response);
                        complete(response);
                    } catch (Throwable t) {
                        complete(t);
                    }
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    complete(throwable);
                }

                @Override
                public void onCancel() {

                }
            });
            addCancelableOperation(cancelable);
        } catch (Throwable t) {
            complete(t);
        }
    }

    @Override
    public void onGroupedTaskComplete(@Nullable GetTemporaryKeyResponse response, @Nullable Throwable failure) {
        super.onGroupedTaskComplete(response, failure);
        taskCompletion.onGetTemporaryKeyTaskCompletion(this, response);
    }

    /**
     * Prepare a pair of objects. The first object contains information before its encoded into JWT request. The second
     * object is the same object, but encoded and signed as JWT.
     * @return A pair of objects. The first object contains information before its encoded into JWT request. The second
     *         object is the same object, but encoded and signed as JWT.
     */
    private Pair<GetTemporaryKeyRequest, JwtObject> prepareRequestJwt() {
        final Session session = cryptoHelper.getCoreSession();
        final SignatureUnlockKeys unlockKeys;
        final String activationId;
        final int signingKey;
        if (isApplicationScope()) {
            signingKey = SigningDataKey.HMAC_APPLICATION;
            activationId = null;
            unlockKeys = null;
        } else {
            signingKey = SigningDataKey.HMAC_ACTIVATION;
            activationId = session.getActivationIdentifier();
            if (activationId == null) {
                this.complete(new PowerAuthErrorException(PowerAuthErrorCodes.MISSING_ACTIVATION));
                return null;
            }
            unlockKeys = new SignatureUnlockKeys(cryptoHelper.getDeviceRelatedKey(), null, null);
        }
        // Prepare request data
        final String applicationKey = session.getApplicationKey();
        final String challenge = Base64.encodeToString(CryptoUtils.randomBytes(18), Base64.NO_WRAP);
        final GetTemporaryKeyRequest request = new GetTemporaryKeyRequest(applicationKey, activationId, challenge);
        // Prepare JWT string
        final String jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.";     // {"alg":"HS256","typ":"JWT"} with dot separator
        final String jwtPayload = serialization.serializeJwtObject(request);
        final String jwtHeaderPlusPayload = jwtHeader + jwtPayload;
        final SignedData dataToSign = new SignedData(jwtHeaderPlusPayload.getBytes(StandardCharsets.US_ASCII), null, signingKey, SignatureFormat.DEFAULT);
        if (ErrorCode.OK != session.signDataWithHmacKey(dataToSign, unlockKeys)) {
            this.complete(new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR));
            return null;
        }
        final String jwtSignature = Base64.encodeToString(dataToSign.signature, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
        final JwtObject jwtObject = new JwtObject(jwtHeaderPlusPayload + "." + jwtSignature);
        return Pair.create(request, jwtObject);
    }

    /**
     * Process JWT response received from the server.
     * @param response JWT response.
     * @return Decoded payload extracted from the JWT response.
     * @throws PowerAuthErrorException In case of failure.
     */
    private GetTemporaryKeyResponse processResponseJwt(@NonNull JwtObject response) throws PowerAuthErrorException {
        final String jwtString = response.jwt;
        if (jwtString == null) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Empty JWT response");
        }
        final String[] jwtComponents = TextUtils.split(jwtString, "\\.");
        if (jwtComponents.length != 3) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Invalid JWT response");
        }
        final String jwtHeader = jwtComponents[0];
        final String jwtPayload = jwtComponents[1];
        final String jwtSignature = jwtComponents[2];
        if (jwtHeader.isEmpty() || jwtPayload.isEmpty() || jwtSignature.isEmpty()) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Invalid JWT response");
        }
        final JwtHeader jwtHeaderObject = serialization.deserializeJwtObject(jwtHeader, TypeToken.get(JwtHeader.class));
        if (!"JWT".equals(jwtHeaderObject.typ)) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Unsupported JWT type in response");
        }
        if (!"ES256".equals(jwtHeaderObject.alg)) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.NETWORK_ERROR, "Unsupported JWT algorithm in response");
        }
        final SignedData signedData = new SignedData(
                (jwtHeader + "." + jwtPayload).getBytes(StandardCharsets.US_ASCII),
                Base64.decode(jwtSignature, Base64.NO_WRAP| Base64.URL_SAFE | Base64.NO_PADDING),
                isApplicationScope() ? SigningDataKey.ECDSA_MASTER_SERVER_KEY : SigningDataKey.ECDSA_PERSONALIZED_KEY,
                SignatureFormat.ECDSA_JOSE);
        if (ErrorCode.OK != cryptoHelper.getCoreSession().verifyServerSignedData(signedData)) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Invalid signature in JWT response");
        }
        return serialization.deserializeJwtObject(jwtPayload, TypeToken.get(GetTemporaryKeyResponse.class));
    }

    /**
     * Validate whether values in response object match the important values form the request.
     * @param request Request object.
     * @param response Response object.
     * @throws PowerAuthErrorException In case that important value doesn't match.
     */
    private void validateResponse(@NonNull GetTemporaryKeyRequest request, @NonNull GetTemporaryKeyResponse response) throws PowerAuthErrorException {
        boolean match = request.getChallenge().equals(response.getChallenge());
        match = match && request.getApplicationKey().equals(response.getApplicationKey());
        if (!isApplicationScope()) {
            match = match && request.getActivationId() != null && request.getActivationId().equals(response.getActivationId());
        }
        if (!match) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "JWT response doesn't match request");
        }
    }
}
