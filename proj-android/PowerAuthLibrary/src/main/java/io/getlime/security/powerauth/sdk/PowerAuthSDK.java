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
import androidx.annotation.CheckResult;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.UiThread;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

import com.google.gson.reflect.TypeToken;

import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

import io.getlime.security.powerauth.biometry.BiometricAuthentication;
import io.getlime.security.powerauth.biometry.BiometricAuthenticationRequest;
import io.getlime.security.powerauth.biometry.BiometricKeyData;
import io.getlime.security.powerauth.biometry.IAddBiometryFactorListener;
import io.getlime.security.powerauth.biometry.IBiometricAuthenticationCallback;
import io.getlime.security.powerauth.biometry.IBiometricKeystore;
import io.getlime.security.powerauth.biometry.ICommitActivationWithBiometryListener;
import io.getlime.security.powerauth.core.ActivationCode;
import io.getlime.security.powerauth.core.ActivationCodeUtil;
import io.getlime.security.powerauth.core.ActivationStatus;
import io.getlime.security.powerauth.core.ActivationStep1Param;
import io.getlime.security.powerauth.core.ActivationStep1Result;
import io.getlime.security.powerauth.core.ActivationStep2Param;
import io.getlime.security.powerauth.core.ActivationStep2Result;
import io.getlime.security.powerauth.core.EciesEncryptor;
import io.getlime.security.powerauth.core.ErrorCode;
import io.getlime.security.powerauth.core.Password;
import io.getlime.security.powerauth.core.RecoveryData;
import io.getlime.security.powerauth.core.Session;
import io.getlime.security.powerauth.core.SessionSetup;
import io.getlime.security.powerauth.core.SignatureFactor;
import io.getlime.security.powerauth.core.SignatureRequest;
import io.getlime.security.powerauth.core.SignatureResult;
import io.getlime.security.powerauth.core.SignatureUnlockKeys;
import io.getlime.security.powerauth.core.SignedData;
import io.getlime.security.powerauth.ecies.EciesEncryptorFactory;
import io.getlime.security.powerauth.ecies.EciesEncryptorId;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.exception.PowerAuthMissingConfigException;
import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.keychain.KeychainFactory;
import io.getlime.security.powerauth.keychain.KeychainProtection;
import io.getlime.security.powerauth.networking.client.HttpClient;
import io.getlime.security.powerauth.networking.client.JsonSerialization;
import io.getlime.security.powerauth.networking.endpoints.ConfirmRecoveryCodeEndpoint;
import io.getlime.security.powerauth.networking.endpoints.CreateActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.GetUserInfoEndpoint;
import io.getlime.security.powerauth.networking.endpoints.RemoveActivationEndpoint;
import io.getlime.security.powerauth.networking.endpoints.ValidateSignatureEndpoint;
import io.getlime.security.powerauth.networking.endpoints.VaultUnlockEndpoint;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.model.entity.ActivationRecovery;
import io.getlime.security.powerauth.networking.model.request.ActivationLayer1Request;
import io.getlime.security.powerauth.networking.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.networking.model.request.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.networking.model.request.ValidateSignatureRequest;
import io.getlime.security.powerauth.networking.model.request.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.networking.model.response.ActivationLayer1Response;
import io.getlime.security.powerauth.networking.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.networking.model.response.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.networking.model.response.VaultUnlockResponsePayload;
import io.getlime.security.powerauth.networking.response.CreateActivationResult;
import io.getlime.security.powerauth.networking.response.IActivationRemoveListener;
import io.getlime.security.powerauth.networking.response.IActivationStatusListener;
import io.getlime.security.powerauth.networking.response.IChangePasswordListener;
import io.getlime.security.powerauth.networking.response.IConfirmRecoveryCodeListener;
import io.getlime.security.powerauth.networking.response.ICreateActivationListener;
import io.getlime.security.powerauth.networking.response.IDataSignatureListener;
import io.getlime.security.powerauth.networking.response.IFetchEncryptionKeyListener;
import io.getlime.security.powerauth.networking.response.IGetRecoveryDataListener;
import io.getlime.security.powerauth.networking.response.IUserInfoListener;
import io.getlime.security.powerauth.networking.response.IValidatePasswordListener;
import io.getlime.security.powerauth.networking.response.UserInfo;
import io.getlime.security.powerauth.sdk.impl.*;
import io.getlime.security.powerauth.system.PowerAuthLog;
import io.getlime.security.powerauth.system.PowerAuthSystem;

/**
 * Class used for the main interaction with the PowerAuth SDK components.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthSDK {

    private final @NonNull ReentrantLock mLock;
    private final @NonNull Session mSession;
    private final @NonNull PowerAuthConfiguration mConfiguration;
    private final @NonNull PowerAuthKeychainConfiguration mKeychainConfiguration;
    private final @NonNull IExecutorProvider mExecutorProvider;
    private final @NonNull HttpClient mClient;
    private final @NonNull ISavePowerAuthStateListener mStateListener;
    private final @NonNull IPossessionFactorEncryptionKeyProvider mPossessionFactorEncryptionKeyProvider;
    private final @NonNull Keychain mBiometryKeychain;
    private final @NonNull ICallbackDispatcher mCallbackDispatcher;
    private final @NonNull PowerAuthTokenStore mTokenStore;
    private final @NonNull BiometricDataMapper mBiometricDataMapper;

    /**
     * A builder that collects configurations and arguments for {@link PowerAuthSDK}.
     */
    public static class Builder {

        private final @NonNull PowerAuthConfiguration mConfiguration;
        private PowerAuthClientConfiguration mClientConfiguration;
        private PowerAuthKeychainConfiguration mKeychainConfiguration;
        private ISavePowerAuthStateListener mStateListener;
        private ICallbackDispatcher mCallbackDispatcher;

        /**
         * Creates a builder for {@link PowerAuthSDK}.
         *
         * @param configuration {@link PowerAuthConfiguration} object.
         */
        public Builder(@NonNull PowerAuthConfiguration configuration) {
            this.mConfiguration = configuration;
        }

        /**
         * Set custom configuration for RESTful API client.
         * @param configuration Configuration for RESTful API client.
         * @return {@link Builder}
         */
        public @NonNull Builder clientConfiguration(PowerAuthClientConfiguration configuration) {
            this.mClientConfiguration = configuration;
            return this;
        }

        /**
         * Set custom keychain configuration.
         * @param configuration Configuration for keychain.
         * @return {@link Builder}
         */
        public @NonNull Builder keychainConfiguration(PowerAuthKeychainConfiguration configuration) {
            this.mKeychainConfiguration = configuration;
            return this;
        }

        /**
         * Set custom state listener.
         * @param stateListener State listener that implements {@link ISavePowerAuthStateListener}.
         * @return {@link Builder}
         */
        public @NonNull Builder stateListener(ISavePowerAuthStateListener stateListener) {
            this.mStateListener = stateListener;
            return this;
        }

        /**
         * Set custom callback dispatcher that handle callbacks back to application. If not altered,
         * then all callbacks will be executed on the main thread.
         *
         * @param callbackDispatcher Dispatcher that handle callbacks back to application.
         * @return {@link Builder}
         */
        public @NonNull Builder callbackDispatcher(ICallbackDispatcher callbackDispatcher) {
            this.mCallbackDispatcher = callbackDispatcher;
            return this;
        }

        /**
         * Build instance of {@link PowerAuthSDK}.
         *
         * @param context Android context
         * @return Instance of {@link PowerAuthSDK} class.
         * @throws PowerAuthErrorException In case that builder cannot create an instance of {@link PowerAuthSDK}. This may happen for a several reasons:
         *                                 <ul>
         *                                     <li>
         *                                         You have provided {@link PowerAuthConfiguration} object with invalid configuration.
         *                                     </li>
         *                                     <li>
         *                                         Your {@link PowerAuthKeychainConfiguration} enforces a higher level
         *                                         of {@link KeychainProtection} than is supported on the current device. You should
         *                                         check {@link KeychainFactory#getKeychainProtectionSupportedOnDevice(Context)} before you instantiate
         *                                         {@link PowerAuthSDK} class.
         *                                      </li>
         *                                 </ul>
         *
         */
        public PowerAuthSDK build(@NonNull Context context) throws PowerAuthErrorException {
            final Context appContext = context.getApplicationContext();

            if (!mConfiguration.validateConfiguration()) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid PowerAuthConfiguration.");
            }

            // Create default configuration objects
            if (mKeychainConfiguration == null) {
                mKeychainConfiguration = new PowerAuthKeychainConfiguration.Builder().build();
            }
            final String defaultUserAgent = PowerAuthSystem.getDefaultUserAgent(context);
            if (mClientConfiguration == null) {
                mClientConfiguration = new PowerAuthClientConfiguration.Builder().userAgent(defaultUserAgent).build();
            } else {
                mClientConfiguration = mClientConfiguration.duplicateIfNoUserAgentIsSet(defaultUserAgent);
            }
            if (mCallbackDispatcher == null) {
                mCallbackDispatcher = MainThreadExecutor.getInstance();
            }

            // Prepare HTTP client
            final IExecutorProvider executorProvider = new DefaultExecutorProvider();
            final HttpClient httpClient = new HttpClient(mClientConfiguration, mConfiguration.getBaseEndpointUrl(), executorProvider);

            // Prepare keychains
            final @KeychainProtection int minRequiredKeychainProtection = mKeychainConfiguration.getMinimalRequiredKeychainProtection();
            final Keychain statusKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainStatusId(), minRequiredKeychainProtection);
            final Keychain biometryKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainBiometryId(), minRequiredKeychainProtection);
            final Keychain tokenStoreKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainTokenStoreId(), minRequiredKeychainProtection);

            // Prepare state listener
            final ISavePowerAuthStateListener stateListener = mStateListener != null ? mStateListener : new DefaultSavePowerAuthStateListener(statusKeychain);

            // Prepare possession factor encryption key provider
            final IPossessionFactorEncryptionKeyProvider possessionEncryptionKeyProvider;
            if (mConfiguration.getFetchKeysStrategy() == null) {
                possessionEncryptionKeyProvider = new DefaultPossessionFactorEncryptionKeyProvider();
            } else {
                possessionEncryptionKeyProvider = DefaultPossessionFactorEncryptionKeyProvider.createFromFetchKeyStrategy(mConfiguration.getFetchKeysStrategy());
            }

            // Prepare low-level Session object.
            final SessionSetup sessionSetup = new SessionSetup(
                    mConfiguration.getAppKey(),
                    mConfiguration.getAppSecret(),
                    mConfiguration.getMasterServerPublicKey(),
                    0,
                    mConfiguration.getExternalEncryptionKey()
            );
            final Session session = new Session(sessionSetup);

            // Biometric data mapper
            final ReentrantLock sharedLock = new ReentrantLock();
            final BiometricDataMapper biometricDataMapper = new BiometricDataMapper(sharedLock, session, mConfiguration, mKeychainConfiguration, biometryKeychain);

            // Create a final PowerAuthSDK instance
            final PowerAuthSDK instance = new PowerAuthSDK(
                    sharedLock,
                    session,
                    mConfiguration,
                    mKeychainConfiguration,
                    executorProvider,
                    httpClient,
                    stateListener,
                    possessionEncryptionKeyProvider,
                    biometryKeychain,
                    tokenStoreKeychain,
                    biometricDataMapper,
                    mCallbackDispatcher);

            // Restore state of this SDK instance.
            boolean b = instance.restoreState(instance.mStateListener.serializedState(mConfiguration.getInstanceId()));
            return instance;
        }
    }

    /**
     * Private class constructor. Use {@link Builder} to create an instance of this class.
     *
     * @param sharedLock                Reentrant lock shared between multiple SDK objects.
     * @param session                   Low-level {@link Session} instance.
     * @param configuration             Main {@link PowerAuthConfiguration}.
     * @param keychainConfiguration     Keychain configuration.
     * @param executorProvider          Thread executor provider.
     * @param client                    HTTP client implementation.
     * @param stateListener             State listener.
     * @param possessionKeyProvider     Possession factor encryption key provider.
     * @param biometryKeychain          Keychain that store biometry-related key.
     * @param tokenStoreKeychain        Keychain that store tokens.
     * @param biometricDataMapper       Object that helps to get biometric-related encryption key from keychain and keystore.
     * @param callbackDispatcher        Dispatcher that handle callbacks back to application.
     */
    private PowerAuthSDK(
            @NonNull ReentrantLock sharedLock,
            @NonNull Session session,
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthKeychainConfiguration keychainConfiguration,
            @NonNull IExecutorProvider executorProvider,
            @NonNull HttpClient client,
            @NonNull ISavePowerAuthStateListener stateListener,
            @NonNull IPossessionFactorEncryptionKeyProvider possessionKeyProvider,
            @NonNull Keychain biometryKeychain,
            @NonNull Keychain tokenStoreKeychain,
            @NonNull BiometricDataMapper biometricDataMapper,
            @NonNull ICallbackDispatcher callbackDispatcher) {
        this.mLock = sharedLock;
        this.mSession = session;
        this.mConfiguration = configuration;
        this.mKeychainConfiguration = keychainConfiguration;
        this.mExecutorProvider = executorProvider;
        this.mClient = client;
        this.mStateListener = stateListener;
        this.mPossessionFactorEncryptionKeyProvider = possessionKeyProvider;
        this.mBiometryKeychain = biometryKeychain;
        this.mBiometricDataMapper = biometricDataMapper;
        this.mCallbackDispatcher = callbackDispatcher;
        this.mTokenStore = new PowerAuthTokenStore(this, tokenStoreKeychain, client);
    }

    /**
     * Constructs a new private crypto helper object. The method is package-private.
     *
     * @param context android context, required for activation scope.
     * @return new instance of {@link IPrivateCryptoHelper}
     */
    @NonNull IPrivateCryptoHelper getCryptoHelper(@Nullable final Context context) {
        return new IPrivateCryptoHelper() {
            @NonNull
            @Override
            public EciesEncryptor getEciesEncryptor(@NonNull EciesEncryptorId identifier) throws PowerAuthErrorException {
                final byte[] deviceRelatedKey = context == null ? null : deviceRelatedKey(context);
                EciesEncryptorFactory factory = new EciesEncryptorFactory(mSession, deviceRelatedKey);
                return factory.getEncryptor(identifier);
            }

            @NonNull
            @Override
            public PowerAuthAuthorizationHttpHeader getAuthorizationHeader(boolean availableInProtocolUpgrade, @NonNull byte[] body, @NonNull String method, @NonNull String uriIdentifier, @NonNull PowerAuthAuthentication authentication) throws PowerAuthErrorException {
                if (context == null) {
                    // This is mostly internal error. We should not call this crypto helper's method, when the context is not available.
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Context object is not set.");
                }
                // Prepare request
                final SignatureRequest signatureRequest = new SignatureRequest(body, method, uriIdentifier, null, 0);
                // And calculate signature
                final SignatureResult signatureResult = calculatePowerAuthSignature(context, signatureRequest, authentication, availableInProtocolUpgrade);
                return PowerAuthAuthorizationHttpHeader.createAuthorizationHeader(signatureResult.getAuthHeaderValue());
            }

            @Nullable
            @Override
            public byte[] getDeviceRelatedKey() {
                return context == null ? null : deviceRelatedKey(context);
            }

        };
    }

    /**
     * @return Internal callback dispatcher.
     */
    @NonNull ICallbackDispatcher getCallbackDispatcher() {
        return mCallbackDispatcher;
    }

    /**
     * @return Internal reentrant lock that can be shared between multiple objects owned by SDK.
     */
    @NonNull ReentrantLock getSharedLock() {
        return mLock;
    }

    /**
     * Checks for valid SessionSetup and throws a PowerAuthMissingConfigException when the provided configuration
     * is not correct or is missing.
     *
     * @throws PowerAuthMissingConfigException if configuration is not valid or is missing.
     */
    private void checkForValidSetup() {
        // Check for the session setup
        if (!mSession.hasValidSetup()) {
            throw new PowerAuthMissingConfigException("Invalid PowerAuthSDK configuration. You must set a valid PowerAuthConfiguration to PowerAuthSDK instance using initializer.");
        }
    }

    /**
     * Return a default device related key used for computing the possession factor encryption key.
     * @param context Context.
     * @return Default device related key.
     */
    @NonNull
    private byte[] deviceRelatedKey(@NonNull Context context) {
        return mPossessionFactorEncryptionKeyProvider.getPossessionFactorEncryptionKey(context);
    }

    /**
     * Converts high level authentication object into low level {@link SignatureUnlockKeys} object.
     *
     * @param context android context object
     * @param authentication authentication object to be converted
     * @return {@link SignatureUnlockKeys} object with
     */
    private @NonNull SignatureUnlockKeys signatureKeysForAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication) {

        // Validate authentication usage for signature calculation.
        authentication.validateAuthenticationUsage(false);

        // Generate signature key encryption keys
        byte[] possessionKey;
        byte[] biometryKey = null;

        if (authentication.getOverriddenPossessionKey() != null) {
            possessionKey = authentication.getOverriddenPossessionKey();
        } else {
            possessionKey = deviceRelatedKey(context);
        }

        if (authentication.getBiometryFactorRelatedKey() != null) {
            biometryKey = authentication.getBiometryFactorRelatedKey();
        }

        // Prepare signature unlock keys structure
        return new SignatureUnlockKeys(possessionKey, biometryKey, authentication.getPassword());
    }

    /**
     * Converts signature factors from {@link PowerAuthAuthentication} into numeric constant
     * usable in low level signature calculation routines.
     *
     * @param authentication {@link PowerAuthAuthentication} object with signature factors set.
     * @return Integer with an appropriate bits set. Each bit represents one signature factor.
     */
    @SignatureFactor
    private int determineSignatureFactorForAuthentication(@NonNull PowerAuthAuthentication authentication) {
        @SignatureFactor int factor = SignatureFactor.Possession;
        if (authentication.getPassword() != null) {
            factor |= SignatureFactor.Knowledge;
        }
        if (authentication.getBiometryFactorRelatedKey() != null) {
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
        @MainThread
        void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey);

        /**
         * Called after the vault key was not acquired from the server.
         *
         * @param throwable Cause of the failure
         */
        @MainThread
        void onFetchEncryptedVaultUnlockKeyFailed(Throwable throwable);
    }

    /**
     * Private method receives an encrypted vault unlock key from the server.
     *
     * @param context android context object
     * @param authentication authentication object, with at least 2 factors defined.
     * @param reason reason for vault unlock operation (See {@link VaultUnlockReason})
     * @param listener private listener called with the operation result.
     * @return {@link ICancelable} object with asynchronous operation.
     */
    private @Nullable
    ICancelable fetchEncryptedVaultUnlockKey(@NonNull final Context context, @NonNull final PowerAuthAuthentication authentication, @NonNull @VaultUnlockReason final String reason, @NonNull final IFetchEncryptedVaultUnlockKeyListener listener) {
        // Input validations
        checkForValidSetup();
        if (!mSession.hasValidActivation()) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onFetchEncryptedVaultUnlockKeyFailed(new PowerAuthErrorException(PowerAuthErrorCodes.MISSING_ACTIVATION));
                }
            });
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
                    public void onNetworkResponse(@NonNull VaultUnlockResponsePayload response) {
                        listener.onFetchEncryptedVaultUnlockKeySucceed(response.getEncryptedVaultEncryptionKey());
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable t) {
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
    public @NonNull PowerAuthTokenStore getTokenStore() {
        return mTokenStore;
    }

    /**
     * Reference to the low-level Session class.
     * <p>
     * <b>WARNING:</b> This property is exposed only for the purpose of giving developers full low-level control over the cryptographic algorithm and managed activation state.
     * For example, you can call a direct password change method without prior check of the password correctness in cooperation with the server API. Be extremely careful when
     * calling any methods of this instance directly. There are very few protective mechanisms for keeping the session state actually consistent in the functional (not low level)
     * sense. As a result, you may break your activation state (for example, by changing password from incorrect value to some other value).
     *
     * @return low level {@link Session} object
     */
    public @NonNull Session getSession() {
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
        try {
            mLock.lock();
            final byte[] state = mSession.serializedState();
            mStateListener.onPowerAuthStateChanged(mConfiguration.getInstanceId(), state);
        } finally {
            mLock.unlock();
        }
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
        // After this call, Session.hasValidSetup() no longer return true, because handle is
        // no longer set to a valid C++ Session instance.
        mSession.destroy();
    }

    /**
     * Create a new activation by calling a PowerAuth Standard RESTful API.
     *
     * @param activation {@link PowerAuthActivation} object containing all information required for the activation creation.
     * @param listener   A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable ICancelable createActivation(@NonNull final PowerAuthActivation activation, @NonNull final ICreateActivationListener listener) {

        // Initial validation
        checkForValidSetup();

        // Check if activation may be started
        if (!canStartActivation()) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationCreateFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
                }
            });
            return null;
        }

        final IPrivateCryptoHelper cryptoHelper = getCryptoHelper(null);
        final JsonSerialization serialization = new JsonSerialization();
        final EciesEncryptor encryptor;

        try {
            // Prepare cryptographic helper & Layer2 ECIES encryptor
            encryptor = cryptoHelper.getEciesEncryptor(EciesEncryptorId.ACTIVATION_PAYLOAD);

            // Prepare low level activation parameters
            final ActivationStep1Param step1Param;
            if (activation.activationCode != null) {
                step1Param = new ActivationStep1Param(activation.activationCode.activationCode, activation.activationCode.activationSignature);
            } else {
                step1Param = null;
            }

            // Start the activation
            final ActivationStep1Result step1Result = mSession.startActivation(step1Param);
            if (step1Result.errorCode != ErrorCode.OK) {
                // Looks like create activation failed
                final int errorCode = step1Result.errorCode == ErrorCode.Encryption
                        ? PowerAuthErrorCodes.SIGNATURE_ERROR
                        : PowerAuthErrorCodes.INVALID_ACTIVATION_DATA;
                dispatchCallback(new Runnable() {
                    @Override
                    public void run() {
                        listener.onActivationCreateFailed(new PowerAuthErrorException(errorCode));
                    }
                });
                return null;
            }

            // Prepare level 2 payload
            final ActivationLayer2Request privateData = new ActivationLayer2Request();
            privateData.setActivationName(activation.activationName);
            privateData.setExtras(activation.extras);
            privateData.setActivationOtp(activation.additionalActivationOtp);
            privateData.setDevicePublicKey(step1Result.devicePublicKey);
            privateData.setPlatform(PowerAuthSystem.getPlatform());
            privateData.setDeviceInfo(PowerAuthSystem.getDeviceInfo());

            // Prepare level 1 payload
            final ActivationLayer1Request request = new ActivationLayer1Request();
            request.setType(activation.activationType);
            request.setIdentityAttributes(activation.identityAttributes);
            request.setCustomAttributes(activation.customAttributes);
            // Set encrypted level 2 activation data to the request.
            request.setActivationData(serialization.encryptObjectToRequest(privateData, encryptor));

            // Fire HTTP request
            return mClient.post(
                    request,
                    new CreateActivationEndpoint(),
                    cryptoHelper,
                    new INetworkResponseListener<ActivationLayer1Response>() {
                        @Override
                        public void onNetworkResponse(@NonNull ActivationLayer1Response response) {
                            // Process response from the server
                            try {
                                // Try to decrypt Layer2 object from response
                                final ActivationLayer2Response layer2Response = serialization.decryptObjectFromResponse(response.getActivationData(), encryptor, TypeToken.get(ActivationLayer2Response.class));
                                // Prepare Step2 param for low level session
                                final RecoveryData recoveryData;
                                if (layer2Response.getActivationRecovery() != null) {
                                    final ActivationRecovery rd = layer2Response.getActivationRecovery();
                                    recoveryData = new RecoveryData(rd.getRecoveryCode(), rd.getPuk());
                                } else {
                                    recoveryData = null;
                                }
                                final ActivationStep2Param step2Param = new ActivationStep2Param(layer2Response.getActivationId(), layer2Response.getServerPublicKey(), layer2Response.getCtrData(), recoveryData);
                                // Validate the response
                                final ActivationStep2Result step2Result = mSession.validateActivationResponse(step2Param);
                                //
                                if (step2Result.errorCode == ErrorCode.OK) {
                                    final UserInfo userInfo = response.getUserInfo() != null ? new UserInfo(response.getUserInfo()) : null;
                                    final CreateActivationResult result = new CreateActivationResult(step2Result.activationFingerprint, response.getCustomAttributes(), recoveryData, userInfo);
                                    setLastFetchedUserInfo(userInfo);
                                    listener.onActivationCreateSucceed(result);
                                    return;
                                }
                                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA, "Invalid activation data received from the server.");

                            } catch (PowerAuthErrorException e) {
                                // In case of error, reset the session & report that exception
                                mSession.resetSession();
                                listener.onActivationCreateFailed(e);
                            }
                        }

                        @Override
                        public void onNetworkError(@NonNull Throwable throwable) {
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

        } catch (final PowerAuthErrorException e) {
            mSession.resetSession();
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationCreateFailed(e);
                }
            });
            return null;
        }
    }


    /**
     * Create a new standard activation with given name and activation code by calling a PowerAuth Standard RESTful API.
     *
     * @param name           Activation name, for example "John's phone".
     * @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
     * @param listener       A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable createActivation(@Nullable String name, @NonNull String activationCode, @NonNull ICreateActivationListener listener) {
        return createActivation(name, activationCode, null, null, listener);
    }


    /**
     * Create a new standard activation with given name and activation code by calling a PowerAuth Standard RESTful API.
     *
     * @param name              Activation name, for example "John's iPhone".
     * @param activationCode    Activation code, obtained either via QR code scanning or by manual entry.
     * @param extras            Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param listener          A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable createActivation(@Nullable String name, @NonNull String activationCode, @Nullable String extras, @NonNull final ICreateActivationListener listener) {
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
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable createActivation(@Nullable String name, @NonNull String activationCode, @Nullable String extras, @Nullable Map<String, Object> customAttributes, @NonNull final ICreateActivationListener listener) {
        try {
            final PowerAuthActivation activation = PowerAuthActivation.Builder.activation(activationCode, name)
                    .setCustomAttributes(customAttributes)
                    .setExtras(extras)
                    .build();
            return createActivation(activation, listener);

        } catch (final PowerAuthErrorException e) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationCreateFailed(e);
                }
            });
            return null;
        }
    }


    /**
     * Create a new custom activation with given name and identity attributes by calling a PowerAuth Standard RESTful API.
     *
     * @param name                  Activation name, for example "John's iPhone".
     * @param identityAttributes    Attributes identifying user on the Application Server.
     * @param extras                Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param customAttributes      Extra attributes of the activation, used for application specific purposes. Unlike the {code extras} parameter, this dictionary is visible for the Application Server.
     * @param listener              A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable createCustomActivation(@Nullable String name, @NonNull Map<String,String> identityAttributes, @Nullable String extras, @Nullable Map<String, Object> customAttributes, @NonNull final ICreateActivationListener listener) {
        try {
            final PowerAuthActivation activation = PowerAuthActivation.Builder.customActivation(identityAttributes, name)
                    .setCustomAttributes(customAttributes)
                    .setExtras(extras)
                    .build();
            return createActivation(activation, listener);

        } catch (final PowerAuthErrorException e) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationCreateFailed(e);
                }
            });
            return null;
        }
    }


    /**
     * Create a new recovery activation with given name, recovery code and puk, by calling a PowerAuth Standard RESTful API.
     *
     * @param name Activation name, for example "John's iPhone".
     * @param recoveryCode Recovery code, obtained either via QR code scanning or by manual entry.
     * @param puk Recovery PUK, obtained by manual entry
     * @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system). The attribute is visible only for PowerAuth Server.
     * @param customAttributes Extra attributes of the activation, used for application specific purposes. Unlike the {code extras} parameter, this dictionary is visible for the Application Server.
     * @param listener A callback listener called when the process finishes - it contains an activation fingerprint in case of success or error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable createRecoveryActivation(@Nullable String name, @NonNull String recoveryCode, @NonNull String puk, @Nullable String extras, @Nullable Map<String, Object> customAttributes, @NonNull final ICreateActivationListener listener) {
        try {
            final PowerAuthActivation activation = PowerAuthActivation.Builder.recoveryActivation(recoveryCode, puk, name)
                    .setExtras(extras)
                    .setCustomAttributes(customAttributes)
                    .build();
            return createActivation(activation, listener);

        } catch (final PowerAuthErrorException e) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationCreateFailed(e);
                }
            });
            return null;
        }
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
    @PowerAuthErrorCodes
    public int commitActivationWithPassword(@NonNull Context context, @NonNull String password) {
        return commitActivationWithAuthentication(context, PowerAuthAuthentication.commitWithPassword(password));
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
    @PowerAuthErrorCodes
    public int commitActivationWithPassword(@NonNull Context context, @NonNull Password password) {
        return commitActivationWithAuthentication(context, PowerAuthAuthentication.commitWithPassword(password));
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentActivity Activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable commitActivation(
            final @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            @NonNull final String password,
            final @NonNull ICommitActivationWithBiometryListener callback) {
        return commitActivationWithBiometryImpl(context, FragmentHelper.from(fragmentActivity), title, description, new Password(password), callback);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentActivity Activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable commitActivation(
            final @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            @NonNull final Password password,
            final @NonNull ICommitActivationWithBiometryListener callback) {
        return commitActivationWithBiometryImpl(context, FragmentHelper.from(fragmentActivity), title, description, password, callback);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragment Fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable commitActivation(
            final @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            @NonNull final String password,
            final @NonNull ICommitActivationWithBiometryListener callback) {
        return commitActivationWithBiometryImpl(context, FragmentHelper.from(fragment), title, description, new Password(password), callback);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragment Fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable commitActivation(
            final @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            @NonNull final Password password,
            final @NonNull ICommitActivationWithBiometryListener callback) {
        return commitActivationWithBiometryImpl(context, FragmentHelper.from(fragment), title, description, password, callback);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentHelper Fragment helper for the dialog.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used for activation commit.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    private ICancelable commitActivationWithBiometryImpl(
            final @NonNull Context context,
            @NonNull FragmentHelper fragmentHelper,
            @NonNull String title,
            @NonNull String description,
            @NonNull final Password password,
            final @NonNull ICommitActivationWithBiometryListener callback) {
        return authenticateUsingBiometry(context, fragmentHelper, title, description, true, new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                if (userCancel) {
                    callback.onBiometricDialogCancelled();
                }
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                final PowerAuthAuthentication authentication = PowerAuthAuthentication.commitWithPasswordAndBiometry(password, biometricKeyData.getDerivedData());
                final int errorCode = commitActivationWithAuthentication(context, authentication);
                if (errorCode == PowerAuthErrorCodes.SUCCEED) {
                    callback.onBiometricDialogSuccess();
                } else {
                    callback.onBiometricDialogFailed(new PowerAuthErrorException(errorCode));
                }
            }

            @Override
            public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                callback.onBiometricDialogFailed(error);
            }
        });
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password.
     * <p>
     * Calling this method is equivalent to {@link #commitActivationWithAuthentication(Context, PowerAuthAuthentication)}  with authentication object set to use all factors and provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @param encryptedBiometryKey Optional biometry related factor key.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    @CheckResult
    @PowerAuthErrorCodes
    public int commitActivationWithPassword(@NonNull Context context, @NonNull String password, @Nullable byte[] encryptedBiometryKey) {
        return commitActivationWithPassword(context, new Password(password), encryptedBiometryKey);
    }

    /**
     * Commit activation that was created and store related data using default authentication instance setup with provided password.
     * <p>
     * Calling this method is equivalent to {@link #commitActivationWithAuthentication(Context, PowerAuthAuthentication)} with authentication object set to use all factors and provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @param encryptedBiometryKey Optional biometry related factor key.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    @CheckResult
    @PowerAuthErrorCodes
    public int commitActivationWithPassword(@NonNull Context context, @NonNull Password password, @Nullable byte[] encryptedBiometryKey) {
        return commitActivationWithAuthentication(context, new PowerAuthAuthentication(true, password, encryptedBiometryKey, null));
    }

    /**
     * Commit activation that was created and store related data using provided authentication instance.
     *
     * @param context android context object
     * @param authentication An authentication instance specifying what factors should be stored.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @CheckResult
    @PowerAuthErrorCodes
    public int commitActivationWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication) {
        // Input validations
        checkForValidSetup();
        // Check if there is a pending activation present and not an already existing valid activation
        if (!mSession.hasPendingActivation()) {
            return PowerAuthErrorCodes.INVALID_ACTIVATION_STATE;
        }
        if (authentication.getPassword() == null) {
            PowerAuthLog.e("Password is required for activation commit");
            return PowerAuthErrorCodes.WRONG_PARAMETER;
        }

        // Validate authentication usage for commit.
        authentication.validateAuthenticationUsage(true);

        // Prepare key encryption keys
        final byte[] possessionKey = deviceRelatedKey(context);
        final byte[] biometryKey = authentication.getBiometryFactorRelatedKey();

        // Prepare signature unlock keys structure
        final SignatureUnlockKeys keys = new SignatureUnlockKeys(possessionKey, biometryKey, authentication.getPassword());

        // Complete the activation
        final int result = mSession.completeActivation(keys);

        if (result == ErrorCode.OK) {
            // Save activation state and clear TokenStore
            saveSerializedState();
            getTokenStore().removeAllLocalTokens(context);

            return PowerAuthErrorCodes.SUCCEED;
        } else {
            return PowerAuthErrorCodes.INVALID_ACTIVATION_STATE;
        }
    }

    //
    // User Info
    //

    /**
     * Variable keeping last fetched information about user.
     */
    private UserInfo mLastFetchedUserInfo = null;

    /**
     * Return last fetched information about the user. The information about user is optional and
     * must be supported by the server. The value is updated during the activation process or by
     * calling {@link #fetchUserInfo(Context, IUserInfoListener)}.
     *
     * @return {@link UserInfo} object or {@code null} if information is not retrieved yet.
     */
    public @Nullable UserInfo getLastFetchedUserInfo() {
        try {
            mLock.lock();
            return mLastFetchedUserInfo;
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Store retrieved information about the user.
     * @param userInfo New instance of {@link UserInfo} object to keep.
     */
    private void setLastFetchedUserInfo(@Nullable UserInfo userInfo) {
        try {
            mLock.lock();
            mLastFetchedUserInfo = userInfo;
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Fetch information about the user from the server. If operation succeed, then the user
     * information object is also internally stored and available in {@link #getLastFetchedUserInfo()}
     * method.
     *
     * @param context Android context.
     * @param listener A callback called once the user info is retrieved from the server.
     * @return {@link ICancelable} object associated with the pending HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    @Nullable
    public ICancelable fetchUserInfo(@NonNull Context context, @NonNull IUserInfoListener listener) {
        // State validations
        checkForValidSetup();
        // Execute HTTP request.
        return mClient.post(
                null,
                new GetUserInfoEndpoint(),
                getCryptoHelper(context),
                new INetworkResponseListener<Map<String, Object>>() {
                    @Override
                    public void onNetworkResponse(@NonNull Map<String, Object> response) {
                        final UserInfo userInfo = new UserInfo(response);
                        setLastFetchedUserInfo(userInfo);
                        listener.onUserInfoSucceed(userInfo);
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        listener.onUserInfoFailed(throwable);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    //
    // Activation Status
    //

    /**
     * Contains {@link GetActivationStatusTask} object when there's a pending fetch for an
     * activation status.
     */
    private GetActivationStatusTask mGetActivationStatusTask;

    /**
     * Contains last fetched {@link ActivationStatus} object.
     */
    private ActivationStatus mLastFetchedActivationStatus;

    /**
     * Return {@link ActivationStatus} recently received from the server. You need to call
     * {@link #fetchActivationStatusWithCallback(Context, IActivationStatusListener)} method to
     * update result from this method.
     *
     * @return {@link ActivationStatus} object recently received from the server or null, if
     *         there's no activation, or status was not received yet.
     */
    public @Nullable ActivationStatus getLastFetchedActivationStatus() {
        try {
            mLock.lock();
            return mLastFetchedActivationStatus;
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Fetch the activation status for current activation.
     * <p>
     * If server returns custom object, it is returned in the callback as NSDictionary.
     *
     * @param context  Context
     * @param listener A callback listener with activation status result - it contains status information in case of success and error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable fetchActivationStatusWithCallback(@NonNull final Context context, @NonNull final IActivationStatusListener listener) {

        // Input validations
        checkForValidSetup();

        // Check if there is an activation present, valid or pending
        if (!mSession.hasValidActivation()) {
            final int errorCode = mSession.hasPendingActivation()
                                    ? PowerAuthErrorCodes.PENDING_ACTIVATION
                                    : PowerAuthErrorCodes.MISSING_ACTIVATION;
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationStatusFailed(new PowerAuthErrorException(errorCode));
                }
            });
            return null;
        }

        // Cancelable object returned to the application
        ICancelable task = null;

        final ITaskCompletion<ActivationStatus> completion = new ITaskCompletion<ActivationStatus>() {
            @Override
            public void onSuccess(@NonNull ActivationStatus activationStatus) {
                listener.onActivationStatusSucceed(activationStatus);
            }

            @Override
            public void onFailure(@NonNull Throwable failure) {
                listener.onActivationStatusFailed(failure);
            }
        };

        try {
            mLock.lock();
            if (mGetActivationStatusTask != null) {
                // There's already some pending task, try to add this listener to it.
                task = mGetActivationStatusTask.createChildTask(completion);
            }
            if (task == null) {
                mGetActivationStatusTask = new GetActivationStatusTask(mClient, getCryptoHelper(context), mSession, mLock, mCallbackDispatcher, mConfiguration.isAutomaticProtocolUpgradeDisabled(), new GetActivationStatusTask.ICompletionListener() {
                    @Override
                    public void onSessionStateChange() {
                        saveSerializedState();
                    }

                    @Override
                    public void onTaskCompletion(@NonNull GetActivationStatusTask task, @Nullable ActivationStatus status) {
                        // The mLock is already locked, because GetActivationStatusTask uses shared lock.
                        if (task == mGetActivationStatusTask) {
                            if (status != null) {
                                mLastFetchedActivationStatus = status;
                            }
                            mGetActivationStatusTask = null;
                        }
                    }
                });
                task = mGetActivationStatusTask.createChildTask(completion);
            }
        } finally {
            mLock.unlock();
        }

        return task;
    }

    /**
     * Cancels possible pending {@link GetActivationStatusTask}. The method should be called
     * only in rare cases, like when SDK object is going to reset its local state.
     */
    private void cancelGetActivationStatusTask() {
        try {
            mLock.lock();
            if (mGetActivationStatusTask != null) {
                mGetActivationStatusTask.cancel();
            }
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Remove current activation by calling a PowerAuth REST API endpoint.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param listener       A callback with activation removal result - in case of an error, an error instance is not 'nil'.
     * @return ICancelable associated with the running request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable removeActivationWithAuthentication(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final IActivationRemoveListener listener) {

        // Input validations
        checkForValidSetup();

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onActivationRemoveFailed(new PowerAuthErrorException(PowerAuthErrorCodes.MISSING_ACTIVATION));
                }
            });
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
                    public void onNetworkResponse(@NonNull Void aVoid) {
                        removeActivationLocal(context);
                        listener.onActivationRemoveSucceed();
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable t) {
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
     * shared biometry key intact if it's still used in another SDK instance. For this kind of situation, it's recommended to use
     * another form of this method, where you can decide whether the key should be removed.
     *
     * @param context  Context
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public void removeActivationLocal(@NonNull Context context) {
        checkForValidSetup();

        final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(null, context, BiometricDataMapper.BIO_MAPPING_REMOVE_KEY);
        if (mSession.hasBiometryFactor()) {
            mBiometryKeychain.remove(biometricDataMapping.keychainKey);
        }
        BiometricAuthentication.getBiometricKeystore().removeBiometricKeyEncryptor(biometricDataMapping.keystoreId);

        // Remove all tokens from token store
        getTokenStore().cancelAllRequests();
        getTokenStore().removeAllLocalTokens(context);

        // Reset C++ session
        mSession.resetSession();
        // Serialize will notify state listener
        saveSerializedState();
        // Cancel possible pending activation status task
        cancelGetActivationStatusTask();
        // Clear possible cached data
        clearCachedData();
    }

    /**
     * Removes existing activation from the device.
     * <p>
     * This method removes the activation session state and optionally also shared biometry factor key. Cached possession related
     * key remains intact. Unlike the `removeActivationWithAuthentication`, this method doesn't inform server about activation removal.
     * In this case user has to remove the activation by using another channel (typically internet banking, or similar web management console)
     * <p>
     * <b>NOTE:</b>The removeSharedBiometryKey parameter is now ignored, because PowerAuthSDK no longer use the shared key for a newly created
     * biometry factors.
     *
     * @param context                   Android context.
     * @param removeSharedBiometryKey   This parameter is ignored.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     * @deprecated Use {@link #removeActivationLocal(Context)} as a replacement.
     */
    @Deprecated // 1.7.10 - remove in 1.10.0
    public void removeActivationLocal(@NonNull Context context, boolean removeSharedBiometryKey) {
        removeActivationLocal(context);
    }

    /**
     * Clear in-memory cached data.
     */
    private void clearCachedData() {
        try {
            mLock.lock();
            mLastFetchedActivationStatus = null;
            mLastFetchedUserInfo = null;
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Compute the HTTP signature header for given GET request, URI identifier and query parameters using provided authentication information.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param uriId          URI identifier.
     * @param params         GET request query parameters
     * @return HTTP header with PowerAuth authorization signature when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @NonNull PowerAuthAuthorizationHttpHeader requestGetSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, Map<String, String> params) {
        byte[] body = this.mSession.prepareKeyValueDictionaryForDataSigning(params);
        return requestSignatureWithAuthentication(context, authentication, "GET", uriId, body);
    }

    /**
     * Compute the HTTP signature header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param method         HTTP method used for the signature computation.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @return HTTP header with PowerAuth authorization signature when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @NonNull PowerAuthAuthorizationHttpHeader requestSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String method, String uriId, byte[] body) {

        checkForValidSetup();

        try {
            final SignatureRequest signatureRequest = new SignatureRequest(body, method, uriId, null, 0);
            final SignatureResult signatureResult = calculatePowerAuthSignature(context, signatureRequest, authentication, false);
            return PowerAuthAuthorizationHttpHeader.createAuthorizationHeader(signatureResult.getAuthHeaderValue());

        } catch (PowerAuthErrorException e) {
            return PowerAuthAuthorizationHttpHeader.createError(e.getPowerAuthErrorCode());
        }
    }

    /**
     * Compute the offline signature for given HTTP method, URI identifier and HTTP request body using provided authentication information.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @param nonce          NONCE in Base64 format
     * @return String representing a calculated signature for all involved factors. In case of error, this method returns null.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable String offlineSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, byte[] body, String nonce) {

        checkForValidSetup();

        if (nonce == null) {
            PowerAuthLog.e("offlineSignatureWithAuthentication: 'nonce' parameter is required.");
            return null;
        }

        try {
            final SignatureRequest signatureRequest = new SignatureRequest(body, "POST", uriId, nonce, mConfiguration.getOfflineSignatureComponentLength());
            final SignatureResult signatureResult = calculatePowerAuthSignature(context, signatureRequest, authentication, false);
            // In case of success, just return the signature code.
            return signatureResult.signatureCode;

        } catch (PowerAuthErrorException e) {
            PowerAuthLog.e("offlineSignatureWithAuthentication: Failed at: " + e.getMessage());
            return null;
        }
    }

    /**
     * Compute PowerAuth signature for given signature request object and authentication.
     * <p>
     * This private method checks most of the session states (except invalid setup) and then performs
     * the signature calculation. The {@link SignatureRequest} object has to be properly configured,
     * before the operation. Method always returns a {@link SignatureResult} object or throws
     * an exception in case of failure.
     *
     * @param context android context object
     * @param signatureRequest data for signature calculation
     * @param authentication authentication object
     * @param allowInUpgrade if true, then the signature calculation can be performed during the protocol upgrade.
     * @return {@link SignatureResult}
     * @throws PowerAuthErrorException if calculation fails.
     */
    private @NonNull SignatureResult calculatePowerAuthSignature(@NonNull Context context, @NonNull SignatureRequest signatureRequest, @NonNull PowerAuthAuthentication authentication, boolean allowInUpgrade) throws PowerAuthErrorException {

        // Check if there is an activation present
        if (!mSession.hasValidActivation()) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.MISSING_ACTIVATION, "Missing activation.");
        }

        // Check protocol upgrade
        if (mSession.hasPendingProtocolUpgrade() || mSession.hasProtocolUpgradeAvailable()) {
            if (!allowInUpgrade) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE, "Data signing is temporarily unavailable, due to required or pending protocol upgrade.");
            }
        }

        // Determine authentication factor type
        @SignatureFactor final int signatureFactor = determineSignatureFactorForAuthentication(authentication);
        // @Deprecated // 1.7.0 - the next test is no longer required once we migrate to immutable authentication object
        if (signatureFactor == 0) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid combination of signature factors.");
        }

        // Generate signature key encryption keys
        final SignatureUnlockKeys keys = signatureKeysForAuthentication(context, authentication);

        // Calculate signature
        final SignatureResult signatureResult = mSession.signHTTPRequest(signatureRequest, keys, signatureFactor);
        if (signatureResult == null) {
            // Should never happen, except that Session was just recently destroyed.
            throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Session is no longer valid.");
        }

        // Update state after each successful calculation
        saveSerializedState();

        // Check the result
        if (signatureResult.errorCode != ErrorCode.OK) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.SIGNATURE_ERROR, "Signature calculation failed on error " +  signatureResult.errorCode);
        }

        return signatureResult;
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
    public @Nullable
    ICancelable signDataWithDevicePrivateKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final byte[] data, @NonNull final IDataSignatureListener listener) {

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
                        listener.onDataSignedFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA));
                    }
                } else {
                    listener.onDataSignedFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
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
        return changePasswordUnsafe(new Password(oldPassword), new Password(newPassword));
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
    public boolean changePasswordUnsafe(@NonNull final Password oldPassword, @NonNull final Password newPassword) {
        final int result = mSession.changeUserPassword(oldPassword, newPassword);
        if (result == ErrorCode.OK) {
            saveSerializedState();
            return true;
        }
        return false;
    }

    /**
     * Validate old password by calling a PowerAuth REST API and if it's correct, then change the password to new one.
     *
     * @param context     Context.
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password, to be set in case authentication with old password passes.
     * @param listener    The callback method with the password change result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable changePassword(@NonNull Context context, @NonNull final String oldPassword, @NonNull final String newPassword, @NonNull final IChangePasswordListener listener) {
        return changePassword(context, new Password(oldPassword), new Password(newPassword), listener);
    }

    /**
     * Validate old password by calling a PowerAuth REST API and if it's correct, then change the password to new one.
     *
     * @param context     Context.
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password, to be set in case authentication with old password passes.
     * @param listener    The callback method with the password change result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable changePassword(@NonNull Context context, @NonNull final Password oldPassword, @NonNull final Password newPassword, @NonNull final IChangePasswordListener listener) {
        // At first, validate the old password
        return validatePassword(context, oldPassword, new IValidatePasswordListener() {
            @Override
            public void onPasswordValid() {
                // Old password is valid, so let's change it to new one
                final int result = mSession.changeUserPassword(oldPassword, newPassword);
                if (result == ErrorCode.OK) {
                    // Update state
                    saveSerializedState();
                    listener.onPasswordChangeSucceed();
                } else {
                    listener.onPasswordChangeFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
                }
            }

            @Override
            public void onPasswordValidationFailed(@NonNull Throwable t) {
                listener.onPasswordChangeFailed(t);
            }
        });
    }

    /**
     * Check if the current PowerAuth instance has biometry factor in place.
     *
     * @param context Android context object
     * @return True in case biometry factor is present, false otherwise.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean hasBiometryFactor(@NonNull Context context) {

        checkForValidSetup();

        // Initialize keystore
        final IBiometricKeystore keyStore = BiometricAuthentication.getBiometricKeystore();
        final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(keyStore, context, BiometricDataMapper.BIO_MAPPING_NOOP);

        // Check if there is biometry factor in session, key in PA2Keychain and key in keystore.
        return mSession.hasBiometryFactor() && keyStore.containsBiometricKeyEncryptor(biometricDataMapping.keystoreId) &&
                mBiometryKeychain.contains(biometricDataMapping.keychainKey);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param fragment The fragment of the application that will host the prompt.
     * @param title Title for the biometry alert
     * @param description Description displayed in the biometry alert
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull Fragment fragment,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull String password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, FragmentHelper.from(fragment), title, description, new Password(password), listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param fragment The fragment of the application that will host the prompt.
     * @param title Title for the biometry alert
     * @param description Description displayed in the biometry alert
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull Fragment fragment,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, FragmentHelper.from(fragment), title, description, password, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param fragmentActivity The activity of the client application that will host the prompt.
     * @param title Title for the biometry alert
     * @param description Description displayed in the biometry alert
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull FragmentActivity fragmentActivity,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull String password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, FragmentHelper.from(fragmentActivity), title, description, new Password(password), listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param fragmentActivity The activity of the client application that will host the prompt.
     * @param title Title for the biometry alert
     * @param description Description displayed in the biometry alert
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull FragmentActivity fragmentActivity,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, FragmentHelper.from(fragmentActivity), title, description, password, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param fragmentHelper Fragment helper for the dialog.
     * @param title Title for the biometry alert
     * @param description Description displayed in the biometry alert
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Nullable
    private ICancelable addBiometryFactorImpl(
            @NonNull final Context context,
            final @NonNull FragmentHelper fragmentHelper,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {

        // Initial authentication object, used for vault unlock call on server
        final PowerAuthAuthentication authAuthentication = PowerAuthAuthentication.possessionWithPassword(password);

        // Fetch vault unlock key
        final CompositeCancelableTask compositeCancelableTask = new CompositeCancelableTask(true);
        final ICancelable httpRequest = fetchEncryptedVaultUnlockKey(context, authAuthentication, VaultUnlockReason.ADD_BIOMETRY, new IFetchEncryptedVaultUnlockKeyListener() {

            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(final String encryptedEncryptionKey) {
                if (encryptedEncryptionKey != null) {
                    // Authenticate using biometry to generate a key
                    final ICancelable biometricAuthentication = authenticateUsingBiometry(context, fragmentHelper, title, description, true, new IBiometricAuthenticationCallback() {
                        @Override
                        public void onBiometricDialogCancelled(boolean userCancel) {
                            if (userCancel) {
                                listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_CANCEL));
                            }
                        }

                        @Override
                        public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                            // Let's add the biometry key
                            SignatureUnlockKeys keys = new SignatureUnlockKeys(deviceRelatedKey(context), biometricKeyData.getDerivedData(), null);
                            final int result = mSession.addBiometryFactor(encryptedEncryptionKey, keys);
                            if (result == ErrorCode.OK) {
                                // Update state after each successful calculations
                                saveSerializedState();
                                listener.onAddBiometryFactorSucceed();
                            } else {
                                listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
                            }
                        }

                        @Override
                        public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                            listener.onAddBiometryFactorFailed(error);
                        }
                    });
                    compositeCancelableTask.addCancelable(biometricAuthentication);
                } else {
                    listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onAddBiometryFactorFailed(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, t));
            }
        });
        if (httpRequest != null) {
            compositeCancelableTask.addCancelable(httpRequest);
            return compositeCancelableTask;
        }
        return null;
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable addBiometryFactor(
            final @NonNull Context context,
            @NonNull String password,
            final @NonNull byte[] encryptedBiometryKey,
            final @NonNull IAddBiometryFactorListener listener) {
        return addBiometryFactor(context, new Password(password), encryptedBiometryKey, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the encrypted key.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable addBiometryFactor(
            final @NonNull Context context,
            @NonNull Password password,
            final @NonNull byte[] encryptedBiometryKey,
            final @NonNull IAddBiometryFactorListener listener) {
        final PowerAuthAuthentication authAuthentication = PowerAuthAuthentication.possessionWithPassword(password);

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
                        listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
                    }
                } else {
                    listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onAddBiometryFactorFailed(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, t));
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
            final IBiometricKeystore keystore = BiometricAuthentication.getBiometricKeystore();
            final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(keystore, context, BiometricDataMapper.BIO_MAPPING_REMOVE_KEY);
            saveSerializedState();
            mBiometryKeychain.remove(biometricDataMapping.keychainKey);
            keystore.removeBiometricKeyEncryptor(biometricDataMapping.keystoreId);
        }
        return result == ErrorCode.OK;
    }

    /**
     * Generate an derived encryption key with given index.
     * <p>
     * This method calls PowerAuth Standard REST API endpoint to obtain the vault encryption key used for subsequent key derivation using given index.
     *
     * @param context        Context.
     * @param authentication Authentication used for vault unlocking call.
     * @param index          Index of the derived key using KDF.
     * @param listener       The callback method with the derived encryption key.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable fetchEncryptionKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, final long index, @NonNull final IFetchEncryptionKeyListener listener) {
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
                    listener.onFetchEncryptionKeyFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_DATA));
                }

            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable t) {
                listener.onFetchEncryptionKeyFailed(t);
            }
        });
    }

    /**
     * Validate a user password. This method calls PowerAuth REST API endpoint to validate the password on the server.
     * This method is deprecated and you can use {@link #validatePassword(Context, String, IValidatePasswordListener)}
     * as a replacement.
     *
     * @param context  Context.
     * @param password Password to be verified.
     * @param listener The callback method with error associated with the password validation.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    @Deprecated // 1.7.2
    public @Nullable
    ICancelable validatePasswordCorrect(@NonNull Context context, @NonNull String password, @NonNull final IValidatePasswordListener listener) {
        return validatePassword(context, new Password(password), listener);
    }

    /**
     * Validate a user password. This method calls PowerAuth REST API endpoint to validate the password on the server.
     *
     * @param context  Context.
     * @param password Password to be verified.
     * @param listener The callback method with error associated with the password validation.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable validatePassword(@NonNull Context context, @NonNull String password, @NonNull final IValidatePasswordListener listener) {
        return validatePassword(context, new Password(password), listener);
    }

    /**
     * Validate a user password. This method calls PowerAuth REST API endpoint to validate the password on the server.
     *
     * @param context  Context.
     * @param password Password to be verified.
     * @param listener The callback method with error associated with the password validation.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable validatePassword(@NonNull Context context, @NonNull Password password, @NonNull final IValidatePasswordListener listener) {

        // Prepare authentication object
        PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword(password);
        // Prepare request object
        final ValidateSignatureRequest request = new ValidateSignatureRequest();
        request.setReason("VALIDATE_PASSWORD");

        // Execute HTTP request
        return mClient.post(
                request,
                new ValidateSignatureEndpoint(),
                getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<Void>() {
                    @Override
                    public void onNetworkResponse(@NonNull Void aVoid) {
                        listener.onPasswordValid();
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable t) {
                        listener.onPasswordValidationFailed(t);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and {@link IBiometricAuthenticationCallback#onBiometricDialogSuccess(BiometricKeyData)} callback is called,
     * you can use {@code biometricKeyEncrypted} as a parameter to {@link PowerAuthAuthentication#useBiometry} property.
     *
     * @param context Context.
     * @param fragment The fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable authenticateUsingBiometry(
            @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            final @NonNull IBiometricAuthenticationCallback callback) {
        return authenticateUsingBiometry(context, FragmentHelper.from(fragment), title, description, false, callback);
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and {@link IBiometricAuthenticationCallback#onBiometricDialogSuccess(BiometricKeyData)} callback is called,
     * you can use {@code biometricKeyEncrypted} as a parameter to {@link PowerAuthAuthentication#useBiometry} property.
     *
     * @param context Context.
     * @param fragmentActivity The activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    public ICancelable authenticateUsingBiometry(
            @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            final @NonNull IBiometricAuthenticationCallback callback) {
        return authenticateUsingBiometry(context, FragmentHelper.from(fragmentActivity), title, description, false, callback);
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and {@link IBiometricAuthenticationCallback#onBiometricDialogSuccess(BiometricKeyData)} callback is called,
     * you can use {@code biometricKeyEncrypted} as a parameter to {@link PowerAuthAuthentication#useBiometry} property.
     *
     * @param context Context.
     * @param fragmentHelper Fragment helper for the dialog.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param forceGenerateNewKey Pass true to indicate that a new key should be generated in Keystore
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @RequiresApi(api = Build.VERSION_CODES.M)
    @NonNull
    private ICancelable authenticateUsingBiometry(
            final @NonNull Context context,
            final @NonNull FragmentHelper fragmentHelper,
            final @NonNull String title,
            final @NonNull String description,
            final boolean forceGenerateNewKey,
            final @NonNull IBiometricAuthenticationCallback callback) {

        final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(null, context, forceGenerateNewKey ? BiometricDataMapper.BIO_MAPPING_CREATE_KEY : BiometricDataMapper.BIO_MAPPING_NOOP);
        final byte[] rawKeyData;
        if (forceGenerateNewKey) {
            // new key has to be generated
            rawKeyData = mSession.generateSignatureUnlockKey();
        } else {
            // old key should be used, if present
            rawKeyData = mBiometryKeychain.getData(biometricDataMapping.keychainKey);
        }

        if (rawKeyData == null) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    callback.onBiometricDialogFailed(new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Biometric authentication failed due to missing biometric key."));
                }
            });
            // Return dummy cancelable object.
            return new DummyCancelable();
        }

        // Build a new authentication request.
        final BiometricAuthenticationRequest.Builder authenticationRequestBuilder = new BiometricAuthenticationRequest.Builder(context)
                .setTitle(title)
                .setDescription(description)
                .setRawKeyData(rawKeyData)
                .setKeystoreAlias(biometricDataMapping.keystoreId)
                .setForceGenerateNewKey(forceGenerateNewKey, mKeychainConfiguration.isLinkBiometricItemsToCurrentSet(), mKeychainConfiguration.isAuthenticateOnBiometricKeySetup())
                .setUserConfirmationRequired(mKeychainConfiguration.isConfirmBiometricAuthentication())
                .setBackgroundTaskExecutor(mExecutorProvider.getConcurrentExecutor());
        if (fragmentHelper.getFragment() != null) {
            authenticationRequestBuilder.setFragment(fragmentHelper.getFragment());
        } else if (fragmentHelper.getFragmentActivity() != null) {
            authenticationRequestBuilder.setFragmentActivity(fragmentHelper.getFragmentActivity());
        }
        final BiometricAuthenticationRequest request = authenticationRequestBuilder.build();

        return BiometricAuthentication.authenticate(context, request, new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                callback.onBiometricDialogCancelled(userCancel);
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                // Store the new key, if a new key was generated
                if (biometricKeyData.isNewKey()) {
                    mBiometryKeychain.putData(biometricKeyData.getDataToSave(), biometricDataMapping.keychainKey);
                }
                byte[] normalizedEncryptionKey = mSession.normalizeSignatureUnlockKeyFromData(biometricKeyData.getDerivedData());
                callback.onBiometricDialogSuccess(new BiometricKeyData(biometricKeyData.getDataToSave(), normalizedEncryptionKey, biometricKeyData.isNewKey()));
            }

            @Override
            public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                final @PowerAuthErrorCodes int errorCode = error.getPowerAuthErrorCode();
                if (!forceGenerateNewKey && errorCode == PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED) {
                    // The "PA2ErrorCodeBiometryNotRecognized" code is reported in case that biometry
                    // failed at lockout (e.g. too many failed attempts). In this case, we should
                    // generate a fake signature unlock key and pretend that everything's OK.
                    // That will lead to unsuccessful authentication on the server and increased
                    // counter of failed attempts.
                    final byte[] randomData =  mSession.generateSignatureUnlockKey();
                    callback.onBiometricDialogSuccess(new BiometricKeyData(randomData, randomData, false));
                } else {
                    // Otherwise just report the failure.
                    callback.onBiometricDialogFailed(error);
                }
            }
        });
    }

    // E2EE

    /**
     * Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes.
     * The returned encryptor is cryptographically bounded to the PowerAuth configuration, so it can be used
     * with or without a valid activation. The encryptor also contains an associated {@link io.getlime.security.powerauth.ecies.EciesMetadata}
     * object, allowing you to properly setup HTTP header for the request.
     *
     * @return New instance of {@link EciesEncryptor} object with an associated {@link io.getlime.security.powerauth.ecies.EciesMetadata}.
     * @throws PowerAuthErrorException if {@link PowerAuthConfiguration} contains an invalid configuration.
     *         You can call {@link PowerAuthErrorException#getPowerAuthErrorCode()} to get a more
     *         detailed information about the failure.
     */
    public @Nullable EciesEncryptor getEciesEncryptorForApplicationScope() throws PowerAuthErrorException {
        final IPrivateCryptoHelper helper = getCryptoHelper(null);
        return helper.getEciesEncryptor(EciesEncryptorId.GENERIC_APPLICATION_SCOPE);
    }

    /**
     * Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes.
     * The returned encryptor is cryptographically bounded to a device's activation, so it can be used only
     * when this instance has a valid activation. The encryptor also contains an associated {@link io.getlime.security.powerauth.ecies.EciesMetadata}
     * object, allowing you to properly setup HTTP header for the request.
     * <p>
     * Note that the created encryptor has no reference to this instance of {@link PowerAuthSDK}. This means
     * that if the instance will loose its activation in the future, then the encryptor will still be capable
     * to encrypt, or decrypt the data. This is an expected behavior, so if you plan to keep the encryptor for
     * multiple requests, then it's up to you to release its instance after you change the state of {@code PowerAuthSDK}.
     *
     * @param context Android {@link Context} object
     * @return New instance of {@link EciesEncryptor} object with an associated {@link io.getlime.security.powerauth.ecies.EciesMetadata}.
     * @throws PowerAuthErrorException if {@link PowerAuthConfiguration} contains an invalid configuration or there's
     *         no activation. You can call {@link PowerAuthErrorException#getPowerAuthErrorCode()} to get a more
     *         detailed information about the failure.
     */
    public @Nullable EciesEncryptor getEciesEncryptorForActivationScope(@NonNull final Context context) throws PowerAuthErrorException {
        final IPrivateCryptoHelper helper = getCryptoHelper(context);
        return helper.getEciesEncryptor(EciesEncryptorId.GENERIC_ACTIVATION_SCOPE);
    }

    // Request synchronization

    /**
     * Method returns internal serial {@link Executor} allowing only one background {@link Runnable}
     * task to be executed at the same time. An application can use this executor to synchronize its
     * own signed HTTP requests, with requests created internally in the PowerAuth SDK.
     *
     * <h3>Why this matters</h3>
     *
     * The PowerAuth SDK is using that executor for serialization of signed HTTP requests, to guarantee, that only one request is processed
     * at the time. The PowerAuth signatures are based on a logical counter, so this technique makes that all requests are delivered
     * to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
     * them with the SDK.
     *
     * <h3>Recommended practices</h3>
     * <ul>
     *     <li>You should calculate PowerAuth signature from the {@link Runnable#run()} method.
     *     <li>{@link Runnable#run()} should return from its execution after the HTTP request is fully processed, or at least after
     *         the response headers are received (e.g. you know that the server already did process the request)
     * </ul>
     *
     * @return {@link Executor} allowing only one operation to be executed at the same time.
     * @throws PowerAuthErrorException if there's not a valid activation.
     */
    public @NonNull Executor getSerialExecutor() throws PowerAuthErrorException {
        if (!hasValidActivation()) {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Missing activation");
        }
        return mClient.getExecutorProvider().getSerialExecutor();
    }

    /**
     * Dispatch callback via {@link ICallbackDispatcher}.
     *
     * @param runnable Runnable wrapping a callback that's supposed to be dispatched.
     */
    void dispatchCallback(@NonNull Runnable runnable) {
        mCallbackDispatcher.dispatchCallback(runnable);
    }


    // Recovery codes

    /**
     * @return true if underlying session contains an activation recovery data.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public boolean hasActivationRecoveryData() {
        checkForValidSetup();
        return mSession.hasActivationRecoveryData();
    }

    /**
     * Get an activation recovery data. This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault
     * encryption key used for private recovery data decryption.
     *
     * @param context Android {@link Context} object
     * @param authentication Authentication used for vault unlocking call.
     * @param listener The callback called when operation succeeds or fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable getActivationRecoveryData(@NonNull final Context context, @NonNull final PowerAuthAuthentication authentication, @NonNull final IGetRecoveryDataListener listener) {

        if (!mSession.hasActivationRecoveryData()) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onGetRecoveryDataFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Session has no recovery data available."));
                }
            });
            return null;
        }

        return fetchEncryptedVaultUnlockKey(context, authentication, VaultUnlockReason.RECOVERY_CODE, new IFetchEncryptedVaultUnlockKeyListener() {
            @Override
            public void onFetchEncryptedVaultUnlockKeySucceed(String encryptedEncryptionKey) {
                final SignatureUnlockKeys keys = signatureKeysForAuthentication(context, authentication);
                final RecoveryData recoveryData = mSession.getActivationRecoveryData(encryptedEncryptionKey, keys);
                if (recoveryData != null) {
                    listener.onGetRecoveryDataSucceeded(recoveryData);
                } else {
                    listener.onGetRecoveryDataFailed(new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Cannot decrypt recovery data."));
                }
            }

            @Override
            public void onFetchEncryptedVaultUnlockKeyFailed(Throwable throwable) {
                listener.onGetRecoveryDataFailed(throwable);
            }
        });
    }

    /**
     * Confirm given recovery code on the server.
     *
     * The method is useful for situations when user receives a recovery information via OOB channel (for example via postcard). Such
     * recovery codes cannot be used without a proper confirmation on the server. To confirm codes, user has to authenticate himself
     * with a knowledge factor.
     *
     * Note that the provided recovery code can contain a `"R:"` prefix, if it's scanned from QR code.
     *
     * @param context Android {@link Context} object
     * @param authentication Authentication used for recovery code confirmation. The knowledge factor is required.
     * @param recoveryCode Recovery code, obtained either via QR code scanning or by manual entry.
     * @param listener The callback called when operation succeeds or fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @throws PowerAuthMissingConfigException thrown in case configuration is not present.
     */
    public @Nullable
    ICancelable confirmRecoveryCode(@NonNull final Context context, @NonNull final PowerAuthAuthentication authentication, @NonNull String recoveryCode, @NonNull final IConfirmRecoveryCodeListener listener) {

        // Validate recovery code
        final ActivationCode code = ActivationCodeUtil.parseFromRecoveryCode(recoveryCode);
        if (code == null) {
            dispatchCallback(new Runnable() {
                @Override
                public void run() {
                    listener.onRecoveryCodeConfirmFailed(new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_CODE));
                }
            });
            return null;
        }

        // Execute HTTP request
        final ConfirmRecoveryRequestPayload request = new ConfirmRecoveryRequestPayload();
        request.setRecoveryCode(code.activationCode);
        return mClient.post(
                request,
                new ConfirmRecoveryCodeEndpoint(),
                getCryptoHelper(context),
                authentication,
                new INetworkResponseListener<ConfirmRecoveryResponsePayload>() {
                    @Override
                    public void onNetworkResponse(@NonNull ConfirmRecoveryResponsePayload confirmRecoveryResponsePayload) {
                        listener.onRecoveryCodeConfirmed(confirmRecoveryResponsePayload.getAlreadyConfirmed());
                    }

                    @Override
                    public void onNetworkError(@NonNull Throwable throwable) {
                        listener.onRecoveryCodeConfirmFailed(throwable);
                    }

                    @Override
                    public void onCancel() {
                    }
                });
    }

    // External Encryption key

    /**
     * @return true if EEK (external encryption key) is set.
     */
    public boolean hasExternalEncryptionKey() {
        return mSession.hasExternalEncryptionKey();
    }

    /**
     * Sets a known external encryption key to the internal configuration. This method
     * is useful, when the activation is using EEK, but the key was not known during the PowerAuthSDK
     * creation. You can restore the activation without the EEK and use it for a very limited set of
     * operations, like the getting activation status. The data signing will also work correctly,
     * but only for a possession factor, which is by design not protected with EEK.
     *
     * @param externalEncryptionKey EEK to be set to the internal configuration.
     * @throws PowerAuthErrorException In case of failure.
     */
    public void setExternalEncryptionKey(@NonNull byte[] externalEncryptionKey) throws PowerAuthErrorException {
        switch (mSession.setExternalEncryptionKey(externalEncryptionKey)) {
            case ErrorCode.OK:
                break;
            case ErrorCode.WrongParam:
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid key size");
            case ErrorCode.WrongState:
                throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Activation is not using EEK");
            case ErrorCode.Encryption:
                throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to set EEK");
        }
    }

    /**
     * Add a new external encryption key permanently to the activated PowerAuthSDK and to the internal configuration.
     * The method is is useful for scenarios, when you need to add the EEK additionally, after the activation.
     * @param externalEncryptionKey External Encryption key to add.
     * @throws PowerAuthErrorException In case of failure.
     */
    public void addExternalEncryptionKey(@NonNull byte[] externalEncryptionKey) throws PowerAuthErrorException {
        switch (mSession.addExternalEncryptionKey(externalEncryptionKey)) {
            case ErrorCode.OK:
                saveSerializedState();
                break;
            case ErrorCode.WrongParam:
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Invalid key size");
            case ErrorCode.WrongState:
                if (mSession.hasExternalEncryptionKey()) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "EEK is already set");
                } else {
                    int paCode = mSession.hasValidActivation() ? PowerAuthErrorCodes.INVALID_ACTIVATION_STATE : PowerAuthErrorCodes.MISSING_ACTIVATION;
                    throw new PowerAuthErrorException(paCode);
                }
            case ErrorCode.Encryption:
                throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to add EEK");
        }
    }

    /**
     * Remove existing external encryption key from the activated PowerAuthSDK and from the configuration object. The valid
     * activation must be present and EEK must be set at the time of call (e.g. {@link #hasExternalEncryptionKey()} returns true).
     * @throws PowerAuthErrorException In case of failure.
     */
    public void removeExternalEncryptionKey() throws PowerAuthErrorException {
        switch (mSession.removeExternalEncryptionKey()) {
            case ErrorCode.OK:
                saveSerializedState();
                break;
            case ErrorCode.WrongState:
                if (!mSession.hasExternalEncryptionKey()) {
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "EEK is not set");
                } else {
                    int paCode = mSession.hasValidActivation() ? PowerAuthErrorCodes.INVALID_ACTIVATION_STATE : PowerAuthErrorCodes.MISSING_ACTIVATION;
                    throw new PowerAuthErrorException(paCode);
                }
            case ErrorCode.Encryption:
            case ErrorCode.WrongParam:
                // mSession.removeExternalEncryptionKey() never return WrongParam. The default case for switch still produce "SwitchIntDef" warning,
                // so we have to enumerate all cases for ErrorCode IntDef.
                throw new PowerAuthErrorException(PowerAuthErrorCodes.ENCRYPTION_ERROR, "Failed to remove EEK");
        }
    }
}
