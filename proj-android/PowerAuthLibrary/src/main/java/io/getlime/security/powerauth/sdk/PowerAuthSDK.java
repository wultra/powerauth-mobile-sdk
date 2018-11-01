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
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v4.app.FragmentManager;

import com.google.gson.reflect.TypeToken;

import java.util.HashMap;
import java.util.Map;

import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.core.ActivationStep1Param;
import io.getlime.security.powerauth.core.ActivationStep1Result;
import io.getlime.security.powerauth.core.ActivationStep2Param;
import io.getlime.security.powerauth.core.ActivationStep2Result;
import io.getlime.security.powerauth.core.ECIESEncryptor;
import io.getlime.security.powerauth.core.ErrorCode;
import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SessionSetup;
import io.getlime.security.powerauth.core.SignatureFactor;
import io.getlime.security.powerauth.core.SignatureRequest;
import io.getlime.security.powerauth.core.SignatureResult;
import io.getlime.security.powerauth.core.SignatureUnlockKeys;
import io.getlime.security.powerauth.core.SignedData;
import io.getlime.security.powerauth.ecies.ECIESEncryptorFactory;
import io.getlime.security.powerauth.ecies.ECIESEncryptorId;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.exception.PowerAuthMissingConfigException;
import io.getlime.security.powerauth.keychain.PA2Keychain;
import io.getlime.security.powerauth.keychain.fingerprint.FingerprintAuthenticationDialogFragment;
import io.getlime.security.powerauth.keychain.fingerprint.FingerprintKeystore;
import io.getlime.security.powerauth.keychain.fingerprint.ICommitActivationWithFingerprintListener;
import io.getlime.security.powerauth.keychain.fingerprint.IFingerprintActionHandler;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.client.JsonSerialization;
import io.getlime.security.powerauth.networking.endpoints.CreateActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.GetActivationStatusEndpoint;
import io.getlime.security.powerauth.networking.endpoints.RemoveActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.ValidateSignatureEndpoint;
import io.getlime.security.powerauth.networking.endpoints.VaultUnlockEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancellable;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.IActivationRemoveListener;
import io.getlime.security.powerauth.networking.response.IActivationStatusListener;
import io.getlime.security.powerauth.networking.response.IAddBiometryFactorListener;
import io.getlime.security.powerauth.networking.response.IChangePasswordListener;
import io.getlime.security.powerauth.networking.response.ICreateActivationListener;
import io.getlime.security.powerauth.networking.response.IDataSignatureListener;
import io.getlime.security.powerauth.networking.response.IFetchEncryptionKeyListener;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.VaultUnlockResponsePayload;
import io.getlime.security.powerauth.sdk.impl.DefaultExecutorProvider;
import io.getlime.security.powerauth.sdk.impl.ISavePowerAuthStateListener;
import io.getlime.security.powerauth.networking.response.IValidatePasswordListener;
import io.getlime.security.powerauth.sdk.impl.DefaultSavePowerAuthStateListener;
import io.getlime.security.powerauth.sdk.impl.IPrivateCryptoHelper;
import io.getlime.security.powerauth.sdk.impl.VaultUnlockReason;
import io.getlime.security.powerauth.util.otp.Otp;
import io.getlime.security.powerauth.util.otp.OtpUtil;

/**
 * Class used for the main interaction with the PowerAuth SDK components.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthSDK {

    private Session mSession;
    private PowerAuthConfiguration mConfiguration;
    private PowerAuthClientConfiguration mClientConfiguration;
    private PowerAuthKeychainConfiguration mKeychainConfiguration;
    private HttpClient mClient;
    private ISavePowerAuthStateListener mStateListener;
    private PA2Keychain mStatusKeychain;
    private PA2Keychain mBiometryKeychain;
    private PowerAuthTokenStore mTokenStore;

    /**
     * Helper class for building new instances.
     */
    public static class Builder {

        private PowerAuthConfiguration mConfiguration;
        private PowerAuthClientConfiguration mClientConfiguration;
        private PowerAuthKeychainConfiguration mKeychainConfiguration;
        private ISavePowerAuthStateListener mStateListener;

        public Builder(@NonNull PowerAuthConfiguration mConfiguration) {
            this.mConfiguration = mConfiguration;
        }

        public Builder clientConfiguration(PowerAuthClientConfiguration configuration) {
            this.mClientConfiguration = configuration;
            return this;
        }

        public Builder keychainConfiguration(PowerAuthKeychainConfiguration configuration) {
            this.mKeychainConfiguration = configuration;
            return this;
        }

        public Builder stateListener(ISavePowerAuthStateListener stateListener) {
            this.mStateListener = stateListener;
            return this;
        }

        public PowerAuthSDK build(@NonNull final Context context) {
            PowerAuthSDK instance = new PowerAuthSDK();
            instance.mConfiguration = mConfiguration;

            if (mKeychainConfiguration != null) {
                instance.mKeychainConfiguration = mKeychainConfiguration;
            } else {
                instance.mKeychainConfiguration = new PowerAuthKeychainConfiguration();
            }

            if (mClientConfiguration != null) {
                instance.mClientConfiguration = mClientConfiguration;
            } else {
                instance.mClientConfiguration = new PowerAuthClientConfiguration.Builder().build();
            }
            instance.mClient = new HttpClient(mClientConfiguration, mConfiguration.getBaseEndpointUrl(), new DefaultExecutorProvider());
            instance.mStatusKeychain = new PA2Keychain(instance.mKeychainConfiguration.getKeychainStatusId());
            instance.mBiometryKeychain = new PA2Keychain(instance.mKeychainConfiguration.getKeychainBiometryId());

            if (mStateListener != null) {
                instance.mStateListener = mStateListener;
            } else {
                instance.mStateListener = new DefaultSavePowerAuthStateListener(context, instance.mStatusKeychain);
            }

            final SessionSetup sessionSetup = new SessionSetup(
                    mConfiguration.getAppKey(),
                    mConfiguration.getAppSecret(),
                    mConfiguration.getMasterServerPublicKey(),
                    0,
                    mConfiguration.getExternalEncryptionKey()
            );

            instance.mSession = new Session(sessionSetup);

            boolean b = instance.restoreState(instance.mStateListener.serializedState(instance.mConfiguration.getInstanceId()));

            return instance;
        }

    }

    private PowerAuthSDK() {
    }

    /**
     * Constructs a new private crypto helper object. The method is package-private.
     *
     * @param context android context, required for activation scope.
     * @return new instance of {@link IPrivateCryptoHelper}
     */
    @NonNull IPrivateCryptoHelper getCryptoHelper(@Nullable final Context context) {
        return new IPrivateCryptoHelper() {
            @Nullable
            @Override
            public ECIESEncryptor getEciesEncryptor(@NonNull ECIESEncryptorId identifier) throws PowerAuthErrorException {
                final byte[] deviceRelatedKey = context == null ? null : deviceRelatedKey(context);
                ECIESEncryptorFactory factory = new ECIESEncryptorFactory(mSession, deviceRelatedKey);
                return factory.getEncryptor(identifier);
            }

            @NonNull
            @Override
            public PowerAuthAuthorizationHttpHeader getAuthorizationHeader(@NonNull byte[] body, @NonNull String method, @NonNull String uriIdentifier, @NonNull PowerAuthAuthentication authentication) {
                return requestSignatureWithAuthentication(context, authentication, method, uriIdentifier, body);
            }
        };
    }

    /**
     * Checks for valid SessionSetup and throws a PowerAuthMissingConfigException when the provided configuration
     * is not correct or is missing.
     *
     * @throws PowerAuthMissingConfigException if configuration is not valid or is missing.
     */
    private void checkForValidSetup() {
        // Check for the session setup
        if (mSession == null || !mSession.hasValidSetup()) {
            throw new PowerAuthMissingConfigException("Invalid PowerAuthSDK configuration. You must set a valid PowerAuthConfiguration to PowerAuthSDK instance using initializer.");
        }
    }

    /**
     * Return a default device related key used for computing the possession factor encryption key.
     * @param context Context.
     * @return Default device related key.
     */
    private byte[] deviceRelatedKey(@NonNull Context context) {
        return mSession.normalizeSignatureUnlockKeyFromData(mConfiguration.getFetchKeysStrategy().getPossessionUnlockKey(context).getBytes());
    }

    /**
     * Converts high level authentication object into low level {@link SignatureUnlockKeys} object.
     *
     * @param context android context object
     * @param authentication authentication object to be converted
     * @return {@link SignatureUnlockKeys} object with
     */
    private @NonNull SignatureUnlockKeys signatureKeysForAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication) {
        // Generate signature key encryption keys
        byte[] possessionKey = null;
        byte[] biometryKey = null;
        Password knowledgeKey = null;

        if (authentication.usePossession) {
            if (authentication.overridenPossessionKey != null) {
                possessionKey = authentication.overridenPossessionKey;
            } else {
                possessionKey = deviceRelatedKey(context);
            }
        }

        if (authentication.useBiometry != null) {
            biometryKey = authentication.useBiometry;
        }

        if (authentication.usePassword != null) {
            knowledgeKey = new Password(authentication.usePassword);
        }

        // Prepare signature unlock keys structure
        return new SignatureUnlockKeys(possessionKey, biometryKey, knowledgeKey);
    }

    /**
     * Converts signature factors from {@link PowerAuthAuthentication} into numeric constant
     * usable in low level signature calculation routines.
     *
     * @param authentication {@link PowerAuthAuthentication} object with signature factors set.
     * @return Integer with an appropriate bits set. Each bit represents one signature factor.
     */
    private int determineSignatureFactorForAuthentication(@NonNull PowerAuthAuthentication authentication) {
        int factor = 0;
        if (authentication.usePossession) {
            factor |= SignatureFactor.Possession;
        }
        if (authentication.usePassword != null) {
            factor |= SignatureFactor.Knowledge;
        }
        if (authentication.useBiometry != null) {
            factor |= SignatureFactor.Biometry;
        }
        return factor;
    }

    /**
     * Private, defines callback interface for {@link #fetchEncryptedVaultUnlockKey(Context, PowerAuthAuthentication, String, IFetchEncryptedVaultUnlockKeyListener)}
     * method.
     */
    private interface IFetchEncryptedVaultUnlockKeyListener {
        /**
         * Called after the vault key has been successfully acquired.
         *
         * @param encryptedEncryptionKey encrypted vault key
         */
        void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey);

        /**
         * Called after the vault key was not acquired from the server.
         *
         * @param throwable Cause of the failure
         */
        void onFetchEncryptedVaultUnlockKeyFailed(Throwable throwable);
    }

    /**
     * Private method receives an encrypted vault unlock key from the server.
     *
     * @param context android context object
     * @param authentication authentication object, with at least 2 factors defined.
     * @param reason reason for vault unlock operation (See {@link VaultUnlockReason})
     * @param listener private listener called with the operation result.
     * @return {@link ICancellable} object with asynchronous operation.
     */
    private @Nullable
    ICancellable fetchEncryptedVaultUnlockKey(@NonNull final Context context, @NonNull final PowerAuthAuthentication authentication, @NonNull final String reason, @NonNull final IFetchEncryptedVaultUnlockKeyListener listener) {
        // Input validations
        checkForValidSetup();
        if (!mSession.hasValidActivation()) {
            listener.onFetchEncryptedVaultUnlockKeyFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeMissingActivation));
            return null;
        }
        // Execute HTTP request
        final VaultUnlockRequestPayload request = new VaultUnlockRequestPayload();
        request.setReason(reason);
        return mClient.post(
                request,
                new VaultUnlockEndpoint(),
                getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<VaultUnlockResponsePayload>() {
                    @Override
                    public void onNetworkResponse(VaultUnlockResponsePayload response) {
                        listener.onFetchEncryptedVaultUnlockKeySucceed(response.getEncryptedVaultEncryptionKey());
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
                        listener.onFetchEncryptedVaultUnlockKeyFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    /**
     * Returns reference to {@code PowerAuthTokenStore} instance. The internal instance is created on demand, when
     * the getter is called for first time.
     *
     * @return Reference to {@code PowerAuthTokenStore} instance.
     */
    public synchronized PowerAuthTokenStore getTokenStore() {
        if (mTokenStore == null) {
            PA2Keychain tokenStoreKeychain = new PA2Keychain(mKeychainConfiguration.getKeychainTokenStoreId());
            mTokenStore = new PowerAuthTokenStore(this, tokenStoreKeychain, mClient);
        }
        return mTokenStore;
    }

    /**
     * Reference to the low-level Session class.
     * <p>
     * WARNING: This property is exposed only for the purpose of giving developers full low-level control over the cryptographic algorithm and managed activation state.
     * For example, you can call a direct password change method without prior check of the password correctness in cooperation with the server API. Be extremely careful when
     * calling any methods of this instance directly. There are very few protective mechanisms for keeping the session state actually consistent in the functional (not low level)
     * sense. As a result, you may break your activation state (for example, by changing password from incorrect value to some other value).
     */
    public Session getSession() {
        return mSession;
    }

    /**
     * Get activation identifier.
     * @return Activation identifier or null if object has no activation.
     */
    public @Nullable String getActivationIdentifier() {
        return mSession.getActivationIdentifier();
    }

    /**
     * Get activation fingerprint calculated from device's public key.
     * @return Activation fingerprint or null if object has no activation.
     */
    public @Nullable String getActivationFingerprint() {
        return mSession.getActivationFingerprint();
    }

    /**
     * @return Configuration provided during the SDK object construction.
     */
    public @NonNull PowerAuthConfiguration getConfiguration() {
        return mConfiguration;
    }

    /**
     * The method is used for saving serialized state of Session, for example after password change method called directly via Session instance. See {@link PowerAuthSDK#getSession()} method.
     */
    public void saveSerializedState() {
        final byte[] state = mSession.serializedState();
        mStateListener.onPowerAuthStateChanged(mConfiguration.getInstanceId(), state);
    }

    /**
     * Restores previously saved PA state.
     *
     * @param state saved PA state.
     * @return TRUE when state restored successfully, otherwise FALSE.
     */
    @CheckResult
    public boolean restoreState(byte[] state) {
        mSession.resetSession();
        final int result = mSession.deserializeState(state);
        return result == ErrorCode.OK;
    }

    /**
     * Checks if the PA library has not been compiled with debug parameters
     *
     * @return Returns TRUE if dynamic library was compiled with a debug features. It is highly recommended
     * to check this boolean and force application to crash, if the production, final app
     * is running against a debug featured library.
     */
    @CheckResult
    public boolean hasDebugFeatures() {
        return mSession.hasDebugFeatures();
    }

    /**
     * Check if it is possible to start an activation process.
     *
     * @return TRUE if activation process can be started, FALSE otherwise.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    public boolean canStartActivation() {
        checkForValidSetup();
        return mSession.canStartActivation();
    }

    /**
     * Checks if there is a pending activation (activation in progress).
     *
     * @return TRUE if there is a pending activation, FALSE otherwise.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    public boolean hasPendingActivation() {
        checkForValidSetup();
        return mSession.hasPendingActivation();
    }

    /**
     * Checks if there is a valid activation.
     *
     * @return TRUE if there is a valid activation, FALSE otherwise.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    public boolean hasValidActivation() {
        checkForValidSetup();
        return mSession.hasValidActivation();
    }

    /**
     * Destroy the PowerAuthSDK instance. Internal objects will be securely destroyed and PowerAuthSDK instance
     * can't be more used after this call.
     */
    public void destroy() {
        mSession.destroy();
        mSession = null;
    }


    /**
     * Create a new standard activation with given name and activation code by calling a PowerAuth Standard RESTful API.
     *
     * @param name           Activation name, for example "John's phone".
     * @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
     * @param listener       A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable createActivation(@Nullable String name, @NonNull String activationCode, @NonNull ICreateActivationListener listener) {
        return createActivation(name, activationCode, null, null, listener);
    }


    /**
     * Create a new standard activation with given name and activation code by calling a PowerAuth Standard RESTful API.
     *
     * @param name              Activation name, for example "John's iPhone".
     * @param activationCode    Activation code, obtained either via QR code scanning or by manual entry.
     * @param extras            Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param listener          A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable createActivation(@Nullable String name, @NonNull String activationCode, @Nullable String extras, @NonNull final ICreateActivationListener listener) {
        return createActivation(name, activationCode, extras, null, listener);
    }


    /**
     * Create a new standard activation with given name and activation code by calling a PowerAuth Standard RESTful API.
     *
     * @param name              Activation name, for example "John's iPhone".
     * @param activationCode    Activation code, obtained either via QR code scanning or by manual entry.
     * @param extras            Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param customAttributes  Extra attributes of the activation, used for application specific purposes. Unlike the {code extras} parameter, this dictionary is visible for the Application Server.
     * @param listener          A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable createActivation(@Nullable String name, @NonNull String activationCode, @Nullable String extras, @Nullable Map<String, Object> customAttributes, @NonNull final ICreateActivationListener listener) {

        // Validate the code first
        final Otp otp = OtpUtil.parseFromActivationCode(activationCode);
        if (otp == null) {
            listener.onActivationCreateFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationCode));
            return null;
        }

        // Prepare identity attributes for "code" based activation
        final HashMap<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("code", otp.activationCode);

        // Prepare request for a standard activation
        final ActivationLayer1Request request = new ActivationLayer1Request();
        request.setType(ActivationType.CODE);
        request.setIdentityAttributes(identityAttributes);
        request.setCustomAttributes(customAttributes);

        return createActivationImpl(name, request, otp, extras, listener);
    }


    /**
     * Create a new custom activation with given name and identity attributes by calling a PowerAuth Standard RESTful API.
     *
     * @param name                  Activation name, for example "John's iPhone".
     * @param identityAttributes    Attributes identifying user on the Application Server.
     * @param extras                Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param customAttributes      Extra attributes of the activation, used for application specific purposes. Unlike the {code extras} parameter, this dictionary is visible for the Application Server.
     * @param listener              A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable createCustomActivation(@Nullable String name, @NonNull Map<String,String> identityAttributes, @Nullable String extras, @Nullable Map<String, Object> customAttributes, @NonNull final ICreateActivationListener listener) {

        // Prepare request for a custom activation
        final ActivationLayer1Request request = new ActivationLayer1Request();
        request.setType(ActivationType.CUSTOM);
        request.setIdentityAttributes(identityAttributes);
        request.setCustomAttributes(customAttributes);

        return createActivationImpl(name, request, null, extras, listener);
    }


    /**
     * Create an arbitrary activation. This method is an actual implementation for the activation creation.
     *
     * @param name          Activation name, for example "John's iPhone".
     * @param request       Activation request. The type & identity attributes must be set in the object.
     * @param otp           Otp object, which is valid only for standard activations
     * @param extras        Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param listener      A callback listener called when the process finishes
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    private @Nullable ICancellable createActivationImpl(@Nullable String name, @NonNull ActivationLayer1Request request, @Nullable Otp otp, @Nullable String extras, @NonNull final ICreateActivationListener listener) {

        // Initial validation
        checkForValidSetup();

        // Check if activation may be started
        if (!canStartActivation()) {
            listener.onActivationCreateFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
            return null;
        }

        final IPrivateCryptoHelper cryptoHelper = getCryptoHelper(null);
        final JsonSerialization serialization = new JsonSerialization();
        final ECIESEncryptor encryptor;

        try {
            // Prepare cryptographic helper & Layer2 ECIES encryptor
            encryptor = cryptoHelper.getEciesEncryptor(ECIESEncryptorId.ActivationPayload);
            if (encryptor == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState);
            }

            // Prepare low level activation parameters
            final ActivationStep1Param step1Param;
            if (otp != null) {
                step1Param = new ActivationStep1Param(otp.activationCode, otp.activationSignature);
            } else {
                step1Param = null;
            }

            // Start the activation
            final ActivationStep1Result step1Result = mSession.startActivation(step1Param);
            if (step1Result.errorCode != ErrorCode.OK) {
                // Looks like create activation failed
                final int errorCode = step1Result.errorCode == ErrorCode.Encryption
                        ? PowerAuthErrorCodes.PA2ErrorCodeSignatureError
                        : PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData;
                listener.onActivationCreateFailed(new PowerAuthErrorException(errorCode));
                return null;
            }

            // Prepare private payload & encrypt it
            final ActivationLayer2Request privateData = new ActivationLayer2Request();
            privateData.setActivationName(name);
            privateData.setExtras(extras);
            privateData.setDevicePublicKey(step1Result.devicePublicKey);

            // Complete Layer1 request data
            request.setActivationData(serialization.encryptObjectToRequest(privateData, encryptor));

        } catch (PowerAuthErrorException e) {
            mSession.resetSession();
            listener.onActivationCreateFailed(e);
            return null;
        }

        // Fire HTTP request
        return mClient.post(
                request,
                new CreateActivationEndpoint(),
                cryptoHelper,
                new INetworkResponseListener<ActivationLayer1Response>() {
                    @Override
                    public void onNetworkResponse(ActivationLayer1Response response) {
                        // Process response from the server
                        try {
                            // Try to decrypt Layer2 object from response
                            final ActivationLayer2Response layer2Response = serialization.decryptObjectFromResponse(response.getActivationData(), encryptor, TypeToken.get(ActivationLayer2Response.class));
                            // Prepare Step2 param for low level session
                            final ActivationStep2Param step2Param = new ActivationStep2Param(layer2Response.getActivationId(), layer2Response.getServerPublicKey(), layer2Response.getCtrData());
                            // Validate the response
                            final ActivationStep2Result step2Result = mSession.validateActivationResponse(step2Param);
                            //
                            if (step2Result.errorCode == ErrorCode.OK) {
                                listener.onActivationCreateSucceed(step2Result.activationFingerprint, response.getCustomAttributes());
                                return;
                            }
                            throw new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData, "Invalid activation data received from the server.");

                        } catch (PowerAuthErrorException e) {
                            // In case of error, reset the session & report that exception
                            mSession.resetSession();
                            listener.onActivationCreateFailed(e);
                        }
                    }

                    @Override
                    public void onNetworkError(Throwable throwable) {
                        // In case of error, reset the session & report that exception
                        mSession.resetSession();
                        listener.onActivationCreateFailed(throwable);
                    }

                    @Override
                    public void onCancel() {
                        // In case of cancel, reset the session
                        mSession.resetSession();
                    }
                });
    }


    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    public int commitActivationWithPassword(@NonNull Context context, @NonNull String password) {
        PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.useBiometry = null;
        authentication.usePossession = true;
        authentication.usePassword = password;
        return commitActivationWithAuthentication(context, authentication);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentManager Fragment manager for the dialog.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void commitActivation(final @NonNull Context context, FragmentManager fragmentManager, String title, String description, @NonNull final String password, final ICommitActivationWithFingerprintListener callback) {
        authenticateUsingFingerprint(context, fragmentManager, title, description, true, new IFingerprintActionHandler() {
            @Override
            public void onFingerprintDialogCancelled() {
                callback.onFingerprintDialogCancelled();
            }

            @Override
            public void onFingerprintDialogSuccess(@Nullable byte[] biometricKeyEncrypted) {
                int b = commitActivationWithPassword(context, password, biometricKeyEncrypted);
                callback.onFingerprintDialogSuccess(b);
            }

            @Override
            public void onFingerprintInfoDialogClosed() {
                callback.onFingerprintDialogCancelled();
            }
        });
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password.
     * <p>
     * Calling this method is equivalent to commitActivationWithAuthentication with authentication object set to use all factors and provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @param encryptedBiometryKey Optional biometry related factor key.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    @CheckResult
    public int commitActivationWithPassword(@NonNull Context context, @NonNull String password, @Nullable byte[] encryptedBiometryKey) {
        PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.useBiometry = encryptedBiometryKey;
        authentication.usePossession = true;
        authentication.usePassword = password;
        return commitActivationWithAuthentication(context, authentication);
    }

    /**
     * Commit activation that was created and store related data using provided authentication instance.
     *
     * @param authentication An authentication instance specifying what factors should be stored.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    public int commitActivationWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication) {

        // Input validations
        checkForValidSetup();
        // Check if there is a pending activation present and not an already existing valid activation
        if (!mSession.hasPendingActivation()) {
            return PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState;
        }

        // Prepare key encryption keys
        final byte[] possessionKey = authentication.usePossession ? deviceRelatedKey(context) : null;
        final byte[] biometryKey = authentication.useBiometry;
        final Password knowledgeKey = authentication.usePassword != null ? new Password(authentication.usePassword) : null;

        // Prepare signature unlock keys structure
        final SignatureUnlockKeys keys = new SignatureUnlockKeys(possessionKey, biometryKey, knowledgeKey);

        // Complete the activation
        final int result = mSession.completeActivation(keys);

        if (result == ErrorCode.OK) {
            // Update state after each successful calculations
            saveSerializedState();

            return PowerAuthErrorCodes.PA2Succeed;
        } else {
            return PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState;
        }
    }

    /**
     * Fetch the activation status for current activation.
     * <p>
     * If server returns custom object, it is returned in the callback as NSDictionary.
     *
     * @param context  Context
     * @param listener A callback listener with activation status result - it contains status information in case of success and error in case of failure.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable fetchActivationStatusWithCallback(@NonNull final Context context, @NonNull final IActivationStatusListener listener) {

        // Input validations
        checkForValidSetup();

        // Check if there is an activation present, valid or pending
        if (!mSession.hasValidActivation()) {
            final int errorCode = mSession.hasPendingActivation()
                                    ? PowerAuthErrorCodes.PA2ErrorCodeActivationPending
                                    : PowerAuthErrorCodes.PA2ErrorCodeMissingActivation;
            listener.onActivationStatusFailed(new PowerAuthErrorException(errorCode));
            return null;
        }

        // Execute request
        final ActivationStatusRequest request = new ActivationStatusRequest();
        request.setActivationId(mSession.getActivationIdentifier());

        return mClient.post(
                request,
                new GetActivationStatusEndpoint(),
                getCryptoHelper(context),
                new INetworkResponseListener<ActivationStatusResponse>() {
                    @Override
                    public void onNetworkResponse(ActivationStatusResponse response) {
                        // Network communication completed correctly
                        // Prepare unlocking key (possession factor only)
                        final SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), null, null);
                        // Attempt to decode the activation status
                        final ActivationStatus activationStatus = mSession.decodeActivationStatus(response.getEncryptedStatusBlob(), keys);
                        if (activationStatus != null) {
                            // Everything was OK
                            listener.onActivationStatusSucceed(activationStatus);
                        } else {
                            // Error occurred when decoding status
                            listener.onActivationStatusFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData));
                        }
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
                        listener.onActivationStatusFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    /**
     * Remove current activation by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/activation/remove'.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param listener       A callback with activation removal result - in case of an error, an error instance is not 'nil'.
     * @return ICancellable associated with the running request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable removeActivationWithAuthentication(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final IActivationRemoveListener listener) {

        // Input validations
        checkForValidSetup();

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            listener.onActivationRemoveFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeMissingActivation));
            return null;
        }

        // Execute request
        return mClient.post(
                null,
                new RemoveActivationEndpoint(),
                getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(Void aVoid) {
                        removeActivationLocal(context);
                        listener.onActivationRemoveSucceed();
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
                        listener.onActivationRemoveFailed(t);
                    }

                    @Override
                    public void onCancel() {

                    }
                });
    }

    /**
     * Removes existing activation from the device.
     * <p>
     * This method removes the activation session state and shared biometry factor key. Cached possession related key remains intact.
     * Unlike the `removeActivationWithAuthentication`, this method doesn't inform server about activation removal. In this case
     * user has to remove the activation by using another channel (typically internet banking, or similar web management console)
     * <p>
     * <b>WARNING:</b> Note that if you have multiple activated SDK instances used in your application at the same time, then you should keep
     * shared biometry key intact if it's still used in another SDK instance. For this kind of situations, it's recommended to use
     * another form of this method, where you can decide whether the key should be removed.
     *
     * @param context  Context
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public void removeActivationLocal(@NonNull Context context) {
        removeActivationLocal(context, true);
    }

    /**
     * Removes existing activation from the device.
     * <p>
     * This method removes the activation session state and optionally also shared biometry factor key. Cached possession related
     * key remains intact. Unlike the `removeActivationWithAuthentication`, this method doesn't inform server about activation removal.
     * In this case user has to remove the activation by using another channel (typically internet banking, or similar web management console)
     * <p>
     * <b>NOTE:</b> This method is useful for situations, where the application has multiple SDK instances activated at the same time and
     * you need to manage a lifetime of shared biometry key.
     *
     * @param context                   Context, may be null if removeSharedBiometryKey is false.
     * @param removeSharedBiometryKey   If set to true, then also shared biometry key will be removed.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public void removeActivationLocal(@Nullable Context context, boolean removeSharedBiometryKey) {

        checkForValidSetup();

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            if (removeSharedBiometryKey && mSession.hasBiometryFactor() && context != null) {
                mBiometryKeychain.removeDataForKey(context, mKeychainConfiguration.getKeychainBiometryDefaultKey());
                FingerprintKeystore keyStore = new FingerprintKeystore();
                if (keyStore.isKeystoreReady()) {
                    keyStore.removeDefaultKey();
                }
            }
        }
        // Remove all tokens from token store
        if (context != null) {
            this.getTokenStore().removeAllLocalTokens(context);
        }
        // Reset C++ session
        mSession.resetSession();
        // Serialize will notify state listener
        saveSerializedState();
    }

    /**
     * Compute the HTTP signature header for given GET request, URI identifier and query parameters using provided authentication information.
     * <p>
     * This method may block a main thread - make sure to dispatch it asynchronously.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param uriId          URI identifier.
     * @param params         GET request query parameters
     * @return HTTP header with PowerAuth authorization signature when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public PowerAuthAuthorizationHttpHeader requestGetSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, Map<String, String> params) {
        byte[] body = this.mSession.prepareKeyValueDictionaryForDataSigning(params);
        return requestSignatureWithAuthentication(context, authentication, "GET", uriId, body);
    }

    /**
     * Compute the HTTP signature header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
     * <p>
     * This method may block a main thread - make sure to dispatch it asynchronously.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param method         HTTP method used for the signature computation.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @return HTTP header with PowerAuth authorization signature when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public PowerAuthAuthorizationHttpHeader requestSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String method, String uriId, byte[] body) {

        checkForValidSetup();

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            return PowerAuthAuthorizationHttpHeader.createError(PowerAuthErrorCodes.PA2ErrorCodeMissingActivation);
        }

        // Determine authentication factor type
        final int signatureFactor = determineSignatureFactorForAuthentication(authentication);
        if (signatureFactor == 0) {
            return PowerAuthAuthorizationHttpHeader.createError(PowerAuthErrorCodes.PA2ErrorCodeWrongParameter);
        }

        // Generate signature key encryption keys
        SignatureUnlockKeys keys = signatureKeysForAuthentication(context, authentication);
        if (keys == null) {
            return PowerAuthAuthorizationHttpHeader.createError(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData);
        }

        // Compute authorization header for provided values and return result.
        SignatureRequest signatureRequest = new SignatureRequest(body, method, uriId, null);
        SignatureResult signatureResult = mSession.signHTTPRequest(signatureRequest, keys, signatureFactor);

        // Update state after each successful calculation
        saveSerializedState();

        if (signatureResult.errorCode == ErrorCode.OK) {
            return PowerAuthAuthorizationHttpHeader.createAuthorizationHeader(signatureResult.authHeaderValue);
        } else {
            return PowerAuthAuthorizationHttpHeader.createError(PowerAuthErrorCodes.PA2ErrorCodeSignatureError);
        }
    }

    /**
     * Compute the offline signature for given HTTP method, URI identifier and HTTP request body using provided authentication information.
     * <p>
     * This method may block a main thread - make sure to dispatch it asynchronously.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @param nonce          NONCE in Base64 format
     * @return String representing a calculated signature for all involved factors. In case of error, this method returns null.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public String offlineSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, byte[] body, String nonce) {

        checkForValidSetup();

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            return null;
        }

        // Generate signature key encryption keys
        SignatureUnlockKeys keys = signatureKeysForAuthentication(context, authentication);
        if (keys == null) {
            return null;
        }

        // nonce is mandatory for this operation
        if (nonce == null) {
            return null;
        }

        // Determine authentication factor type
        final int signatureFactor = determineSignatureFactorForAuthentication(authentication);
        if (signatureFactor == 0) {
            // Wrong parameter
            return null;
        }

        // Compute authorization header for provided values and return result.
        SignatureRequest signatureRequest = new SignatureRequest(body, "POST", uriId, nonce);
        SignatureResult signatureResult = mSession.signHTTPRequest(signatureRequest, keys, signatureFactor);

        // Update state after each successful calculation
        saveSerializedState();

        if (signatureResult.errorCode == ErrorCode.OK) {
            return signatureResult.signatureCode;
        }
        return null;
    }

    /***
     * Validates whether the data has been signed with master server private key, or personalized server's private key.
     *
     * @param data An arbitrary data
     * @param signature A signature calculated for data
     * @param useMasterKey If true, then master server's public key is used for validation, otherwise personalized server's key.
     * @return true if signature is valid
     */
    public boolean verifyServerSignedData(byte[] data, byte[] signature, boolean useMasterKey) {

        checkForValidSetup();

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            return false;
        }

        // Verify signature
        SignedData signedData = new SignedData(data, signature, useMasterKey);
        return mSession.verifyServerSignedData(signedData) == ErrorCode.OK;
    }

    /**
     * Sign provided data with a private key that is stored in secure vault.
     * @param context Context.
     * @param authentication Authentication object for vault unlock request.
     * @param data Data to be signed.
     * @param listener Listener with callbacks to signature status.
     * @return Async task associated with vault unlock request.
     */
    public @Nullable ICancellable signDataWithDevicePrivateKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final byte[] data, @NonNull final IDataSignatureListener listener) {

        // Fetch vault encryption key using vault unlock request.
        return this.fetchEncryptedVaultUnlockKey(context, authentication, VaultUnlockReason.SIGN_WITH_DEVICE_PRIVATE_KEY, new IFetchEncryptedVaultUnlockKeyListener() {
            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey) {
                if (encryptedEncryptionKey != null) {
                    // Let's sign the data
                    SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), null, null);
                    byte[] signature = mSession.signDataWithDevicePrivateKey(encryptedEncryptionKey, keys, data);
                    // Propagate error
                    if (signature != null) {
                        listener.onDataSignedSucceed(signature);
                    } else {
                        listener.onDataSignedFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData));
                    }
                } else {
                    listener.onDataSignedFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onDataSignedFailed(t);
            }
        });
    }

    /**
     * Change the password using local re-encryption, do not validate old password by calling any endpoint.
     *
     * You are responsible for validating the old password against some server endpoint yourself before using it in this method.
     * If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
     * existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
     *
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password to be set to store the data.
     * @return Returns 'true' in case password was changed without error, 'false' otherwise.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public boolean changePasswordUnsafe(@NonNull final String oldPassword, @NonNull final String newPassword) {
        final int result = mSession.changeUserPassword(new Password(oldPassword), new Password(newPassword));
        if (result == ErrorCode.OK) {
            saveSerializedState();
            return true;
        }
        return false;
    }

    /**
     * Change the password, validate old password by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock'.
     *
     * @param context     Context.
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password, to be set in case authentication with old password passes.
     * @param listener    The callback method with the password change result.
     * @return {@link ICancellable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancellable changePassword(@NonNull Context context, @NonNull final String oldPassword, @NonNull final String newPassword, @NonNull final IChangePasswordListener listener) {
        // At first, validate the old password
        return validatePasswordCorrect(context, oldPassword, new IValidatePasswordListener() {
            @Override
            public void onPasswordValid() {
                // Old password is valid, so let's change it to new one
                final int result = mSession.changeUserPassword(new Password(oldPassword), new Password(newPassword));
                if (result == ErrorCode.OK) {
                    // Update state
                    saveSerializedState();
                    listener.onPasswordChangeSucceed();
                } else {
                    listener.onPasswordChangeFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
                }
            }

            @Override
            public void onPasswordValidationFailed(Throwable t) {
                listener.onPasswordChangeFailed(t);
            }
        });
    }

    /**
     * Check if the current PowerAuth instance has biometry factor in place.
     *
     * @return True in case biometry factor is present, false otherwise.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean hasBiometryFactor(@NonNull Context context) {

        checkForValidSetup();

        // Initialize keystore
        FingerprintKeystore keyStore = new FingerprintKeystore();
        if (!keyStore.isKeystoreReady()) {
            return false;
        }

        // Check if there is biometry factor in session, key in PA2Keychain and key in keystore.
        return mSession.hasBiometryFactor() &&
                mBiometryKeychain.containsDataForKey(context, mKeychainConfiguration.getKeychainBiometryDefaultKey()) &&
                keyStore.containsDefaultKey();
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancellable} object associated with the running HTTP request.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public @Nullable ICancellable addBiometryFactor(@NonNull final Context context, final FragmentManager fragmentManager, final String title, final String description, String password, @NonNull final IAddBiometryFactorListener listener) {

        // Initial authentication object, used for vault unlock call on server
        final PowerAuthAuthentication authAuthentication = new PowerAuthAuthentication();
        authAuthentication.usePossession = true;
        authAuthentication.usePassword = password;

        // Fetch vault unlock key
        return fetchEncryptedVaultUnlockKey(context, authAuthentication, VaultUnlockReason.ADD_BIOMETRY, new IFetchEncryptedVaultUnlockKeyListener() {

            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(final String encryptedEncryptionKey) {
                if (encryptedEncryptionKey != null) {

                    // Authenticate using fingerprint to generate a key
                    authenticateUsingFingerprint(context, fragmentManager, title, description, true, new IFingerprintActionHandler() {
                        @Override
                        public void onFingerprintDialogCancelled() {
                            listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeTouchIDCancel));
                        }

                        @Override
                        public void onFingerprintDialogSuccess(@Nullable byte[] biometricKeyEncrypted) {
                            // Let's add the biometry key
                            SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), biometricKeyEncrypted, null);
                            final int result = mSession.addBiometryFactor(encryptedEncryptionKey, keys);
                            if (result == ErrorCode.OK) {
                                // Update state after each successful calculations
                                saveSerializedState();

                                listener.onAddBiometryFactorSucceed();
                            } else {
                                listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
                            }
                        }

                        @Override
                        public void onFingerprintInfoDialogClosed() {
                            listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeTouchIDCancel));
                        }
                    });
                } else {
                    listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onAddBiometryFactorFailed(t);
            }
        });
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancellable} object associated with the running HTTP request.
     */
    public @Nullable ICancellable addBiometryFactor(@NonNull final Context context, String password, final byte[] encryptedBiometryKey, @NonNull final IAddBiometryFactorListener listener) {
        final PowerAuthAuthentication authAuthentication = new PowerAuthAuthentication();
        authAuthentication.usePossession = true;
        authAuthentication.usePassword = password;

        return fetchEncryptedVaultUnlockKey(context, authAuthentication, VaultUnlockReason.ADD_BIOMETRY, new IFetchEncryptedVaultUnlockKeyListener() {

            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey) {
                if (encryptedEncryptionKey != null) {
                    // Let's add the biometry key
                    SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), encryptedBiometryKey, null);
                    final int result = mSession.addBiometryFactor(encryptedEncryptionKey, keys);
                    if (result == ErrorCode.OK) {
                        // Update state after each successful calculations
                        saveSerializedState();
                        listener.onAddBiometryFactorSucceed();
                    } else {
                        listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
                    }
                } else {
                    listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationState));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onAddBiometryFactorFailed(t);
            }
        });
    }

    /**
     * Remove the biometry related factor key.
     *
     * @param context Context.
     * @return TRUE if the key was successfully removed, FALSE otherwise.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean removeBiometryFactor(@NonNull Context context) {

        checkForValidSetup();

        final int result = mSession.removeBiometryFactor();
        if (result == ErrorCode.OK) {
            // Update state after each successful calculations
            saveSerializedState();
            mBiometryKeychain.removeDataForKey(context, mKeychainConfiguration.getKeychainBiometryDefaultKey());
            // Initialize keystore
            FingerprintKeystore keyStore = new FingerprintKeystore();
            if (keyStore.isKeystoreReady()) {
                keyStore.removeDefaultKey();
            }
        }
        return result == ErrorCode.OK;
    }

    /**
     * Generate an derived encryption key with given index.
     * <p>
     * This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for subsequent key derivation using given index.
     *
     * @param context        Context.
     * @param authentication Authentication used for vault unlocking call.
     * @param index          Index of the derived key using KDF.
     * @param listener       The callback method with the derived encryption key.
     * @return {@link ICancellable} object associated with the running HTTP request.
     */
    public @Nullable ICancellable fetchEncryptionKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, final long index, @NonNull final IFetchEncryptionKeyListener listener) {
        return fetchEncryptedVaultUnlockKey(context, authentication, VaultUnlockReason.FETCH_ENCRYPTION_KEY, new IFetchEncryptedVaultUnlockKeyListener() {

            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey) {

                // Let's unlock encryption key
                final SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), null, null);
                final byte[] key = mSession.deriveCryptographicKeyFromVaultKey(encryptedEncryptionKey, keys, index);
                if (key != null) {
                    listener.onFetchEncryptionKeySucceed(key);
                } else {
                    // Propagate error
                    listener.onFetchEncryptionKeyFailed(new PowerAuthErrorException(PowerAuthErrorCodes.PA2ErrorCodeInvalidActivationData));
                }

            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onFetchEncryptionKeyFailed(t);
            }
        });
    }

    /**
     * Validate a user password.
     * <p>
     * This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to validate the signature value.
     * @param context  Context.
     * @param password Password to be verified.
     * @param listener The callback method with error associated with the password validation.
     * @return {@link ICancellable} object associated with the running HTTP request.
     */
    public @Nullable ICancellable validatePasswordCorrect(@NonNull Context context, String password, @NonNull final IValidatePasswordListener listener) {

        // Prepare authentication object
        PowerAuthAuthentication authentication = new PowerAuthAuthentication();
        authentication.usePossession = true;
        authentication.usePassword = password;

        // Execute HTTP request
        return mClient.post(
                null,
                new ValidateSignatureEndpoint(),
                getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(Void aVoid) {
                        listener.onPasswordValid();
                    }

                    @Override
                    public void onNetworkError(Throwable t) {
                        listener.onPasswordValidationFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    /**
     * Authenticate a client using fingerprint authentication. In case of the authentication is successful and 'onFingerprintDialogSuccess' callback is called,
     * you can use 'biometricKeyEncrypted' as a 'useBiometry' key on 'PowerAuthAuthentication' instance.
     *
     * @param context Context.
     * @param fragmentManager Fragment manager for the dialog.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param callback Callback with the authentication result.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void authenticateUsingFingerprint(Context context, FragmentManager fragmentManager, String title, String description, final IFingerprintActionHandler callback) {
        authenticateUsingFingerprint(context, fragmentManager, title, description, false, callback);
    }

    /**
     * Authenticate a client using fingerprint authentication. In case of the authentication is successful and 'onFingerprintDialogSuccess' callback is called,
     * you can use 'biometricKeyEncrypted' as a 'useBiometry' key on 'PowerAuthAuthentication' instance.
     *
     * Use this method in case of activation of the fingerprint scanner - pass 'true' as 'forceGenerateNewKey'.
     *
     * @param context Context.
     * @param fragmentManager Fragment manager for the dialog.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param forceGenerateNewKey Pass true to indicate that a new key should be generated in Keystore
     * @param callback Callback with the authentication result.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void authenticateUsingFingerprint(final @NonNull Context context, final @NonNull FragmentManager fragmentManager, final @NonNull String title, final @NonNull String description, final boolean forceGenerateNewKey, final IFingerprintActionHandler callback) {

        final byte[] biometryKey;
        if (forceGenerateNewKey) { // new key has to be generated
            biometryKey = mSession.generateSignatureUnlockKey();
        } else { // old key should be used, if present
            biometryKey = mBiometryKeychain.dataForKey(context, mKeychainConfiguration.getKeychainBiometryDefaultKey());
        }

        // Build a new authentication dialog fragment instance.
        FingerprintAuthenticationDialogFragment dialog = new FingerprintAuthenticationDialogFragment.DialogFragmentBuilder()
                .title(title)
                .description(description)
                .biometricKey(biometryKey)
                .forceGenerateNewKey(forceGenerateNewKey)
                .build();

        // Set the provided fragment manager
        dialog.setFragmentManager(fragmentManager);

        // Augment the provided callback so that the key can be normalized
        // in 'onFingerprintDialogSuccess' before returning, without the need to
        // "break" the encryption provided by the dialog fragment itself.
        dialog.setAuthenticationCallback(new IFingerprintActionHandler() {
            @Override
            public void onFingerprintDialogCancelled() {
                callback.onFingerprintDialogCancelled();
            }

            @Override
            public void onFingerprintDialogSuccess(@Nullable byte[] biometricKeyEncrypted) {
                // Store the new key, if a new key was generated
                if (forceGenerateNewKey) {
                    mBiometryKeychain.putDataForKey(context, biometryKey, mKeychainConfiguration.getKeychainBiometryDefaultKey());
                }
                byte[] normalizedEncryptionKey = mSession.normalizeSignatureUnlockKeyFromData(biometricKeyEncrypted);
                callback.onFingerprintDialogSuccess(normalizedEncryptionKey);
            }

            @Override
            public void onFingerprintInfoDialogClosed() {
                callback.onFingerprintInfoDialogClosed();
            }
        });

        // Show the dialog
        dialog.show();
    }

}
