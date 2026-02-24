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

import android.annotation.SuppressLint;
import android.content.Context;

import androidx.annotation.*;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;

import io.getlime.security.powerauth.BuildConfig;
import io.getlime.security.powerauth.biometry.*;
import io.getlime.security.powerauth.core.*;
import io.getlime.security.powerauth.core.response.CoreActivationResult;
import io.getlime.security.powerauth.core.response.CoreActivationStatus;
import io.getlime.security.powerauth.core.response.CoreProtocolUpgradeResult;
import io.getlime.security.powerauth.exception.PowerAuthErrorCodes;
import io.getlime.security.powerauth.exception.PowerAuthErrorException;
import io.getlime.security.powerauth.keychain.Keychain;
import io.getlime.security.powerauth.keychain.KeychainFactory;
import io.getlime.security.powerauth.keychain.KeychainProtection;
import io.getlime.security.powerauth.networking.interfaces.ICancelable;
import io.getlime.security.powerauth.networking.interfaces.IExecutorProvider;
import io.getlime.security.powerauth.networking.interfaces.INetworkResponseListener;
import io.getlime.security.powerauth.networking.response.*;
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
    private final @NonNull CoreSession mSession;
    private final @NonNull PowerAuthConfiguration mConfiguration;
    private final @NonNull PowerAuthBiometricConfiguration mBiometricConfiguration;
    private final @NonNull PowerAuthKeychainConfiguration mKeychainConfiguration;
    private final @NonNull IExecutorProvider mExecutorProvider;
    private final @NonNull CoreHttpClient mClient;
    private final @NonNull ISavePowerAuthStateListener mStateListener;
    private final @NonNull Keychain mBiometryKeychain;
    private final @NonNull ICallbackDispatcher mCallbackDispatcher;
    private final @NonNull PowerAuthTokenStore mTokenStore;
    private final @NonNull IPowerAuthTimeSynchronizationService mTimeSynchronizationService;
    private final @NonNull IServerStatusProvider mServerStatusProvider;
    private final @NonNull IKeystoreService mKeystoreService;
    private final @NonNull BiometricDataMapper mBiometricDataMapper;

    /**
     * A builder that collects configurations and arguments for {@link PowerAuthSDK}.
     */
    public static class Builder {

        private final @NonNull PowerAuthConfiguration mConfiguration;
        private PowerAuthBiometricConfiguration mBiometricConfiguration;
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
         * Set custom biometric configuration.
         * @param biometricConfiguration Biometric configuration.
         * @return {@link Builder}
         */
        public @NonNull Builder biometricConfiguration(@NonNull PowerAuthBiometricConfiguration biometricConfiguration) {
            this.mBiometricConfiguration = biometricConfiguration;
            return this;
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
         * @param context Android context.
         *                <p>
         *                It's recommended to provide instance of {@link android.app.Application} as a context to this
         *                function to allow PowerAuth mobile SDK to properly register itself as a listener for application
         *                lifecycle transitions. If you provide other context, then you should use {@link PowerAuthAppLifecycleListener}
         *                class to register for callbacks.
         *                </p>
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
            // Create default configuration objects
            if (mBiometricConfiguration == null) {
                if (mKeychainConfiguration == null) {
                    // No config object provided, use default biometric configuration.
                    mBiometricConfiguration = new PowerAuthBiometricConfiguration.Builder().build();
                } else {
                    // As fallback, construct biometric configuration from the keychain configuration.
                    // @Deprecated // 2.0.0
                    mBiometricConfiguration = new PowerAuthBiometricConfiguration(mKeychainConfiguration);
                }
            }
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

            // Prepare low-level Session object.
            final CoreSession session = buildCoreSession(context);

            // Shared lock
            final ReentrantLock sharedLock = new ReentrantLock();

            // Prepare HTTP client
            final IExecutorProvider executorProvider = new DefaultExecutorProvider();
            final CoreHttpClient httpClient = new CoreHttpClient(mClientConfiguration, mConfiguration.getBaseEndpointUrl(), executorProvider, mCallbackDispatcher);

            // Prepare keychains
            final @KeychainProtection int minRequiredKeychainProtection = mKeychainConfiguration.getMinimalRequiredKeychainProtection();
            final Keychain statusKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainStatusId(), minRequiredKeychainProtection);
            final Keychain biometryKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainBiometryId(), minRequiredKeychainProtection);
            final Keychain tokenStoreKeychain = KeychainFactory.getKeychain(appContext, mKeychainConfiguration.getKeychainTokenStoreId(), minRequiredKeychainProtection);

            // Prepare state listener
            final ISavePowerAuthStateListener stateListener = mStateListener != null ? mStateListener : new DefaultSavePowerAuthStateListener(statusKeychain);

            // Prepare time synchronization service and connect it with HTTP client.
            final TimeSynchronizationService timeSynchronizationService = new TimeSynchronizationService(sharedLock, session.getTimeService(), httpClient, mCallbackDispatcher);
            httpClient.setTimeSynchronizationService(timeSynchronizationService);

            // Prepare biometric data mapping provider
            final BiometricDataMapper biometricDataMapper = new BiometricDataMapper(sharedLock, session, mConfiguration, mKeychainConfiguration, biometryKeychain);

            // Prepare keystore service and conned it with HTTP client
            final DefaultKeystoreService keystoreService = new DefaultKeystoreService(session, mCallbackDispatcher, sharedLock, httpClient);
            httpClient.setKeystoreService(keystoreService);

            // Create a final PowerAuthSDK instance
            final PowerAuthSDK instance = new PowerAuthSDK(
                    sharedLock,
                    session,
                    mConfiguration,
                    mBiometricConfiguration,
                    mKeychainConfiguration,
                    executorProvider,
                    httpClient,
                    stateListener,
                    biometryKeychain,
                    tokenStoreKeychain,
                    biometricDataMapper,
                    mCallbackDispatcher,
                    timeSynchronizationService,
                    timeSynchronizationService,
                    keystoreService);

            // Connect HTTP client with function for save the session's state.
            httpClient.setSaveStateCallback(instance::saveSerializedState);

            // Register time service for automatic reset.
            PowerAuthAppLifecycleListener.getInstance().registerTimeSynchronizationService(context, timeSynchronizationService);
            // Restore state of this SDK instance.
            instance.restoreState(instance.mStateListener.serializedState(mConfiguration.getInstanceId()));
            return instance;
        }

        /**
         * Build instance of {@link CoreSession} object with using information from
         * {@link PowerAuthConfiguration}.
         *
         * @param context Android context.
         * @return Instance of low-level {@link CoreSession} object.
         * @throws PowerAuthErrorException In case of initialization failure.
         */
        private CoreSession buildCoreSession(@NonNull Context context) throws PowerAuthErrorException {
            try {
                final CoreConfig configuration = mConfiguration.getCoreConfiguration(new DefaultDeviceSpecificDataProvider().getDeviceSpecificData(context));
                return CoreSession.createSession(configuration);
            } catch (CoreException exception) {
                throw PowerAuthErrorException.wrapException(exception);
            }
        }
    }

    /**
     * Private class constructor. Use {@link Builder} to create an instance of this class.
     *
     * @param sharedLock                Reentrant lock shared between various internal classes.
     * @param session                   Low-level {@link CoreSession} instance.
     * @param configuration             Main {@link PowerAuthConfiguration}.
     * @param biometricConfiguration    Biometric configuration.
     * @param keychainConfiguration     Keychain configuration.
     * @param executorProvider          Thread executor provider.
     * @param client                    HTTP client implementation.
     * @param stateListener             State listener.
     * @param biometryKeychain          Keychain that store biometry-related key.
     * @param tokenStoreKeychain        Keychain that store tokens.
     * @param biometricDataMapper       Instance of {@link BiometricDataMapper}.
     * @param callbackDispatcher        Dispatcher that handle callbacks back to application.
     * @param timeSynchronizationService Implementation of {@link IPowerAuthTimeSynchronizationService}.
     * @param serverStatusProvider      Implementation of {@link IServerStatusProvider}.
     * @param keystoreService           Implementation of {@link IKeystoreService}.
     */
    private PowerAuthSDK(
            @NonNull ReentrantLock sharedLock,
            @NonNull CoreSession session,
            @NonNull PowerAuthConfiguration configuration,
            @NonNull PowerAuthBiometricConfiguration biometricConfiguration,
            @NonNull PowerAuthKeychainConfiguration keychainConfiguration,
            @NonNull IExecutorProvider executorProvider,
            @NonNull CoreHttpClient client,
            @NonNull ISavePowerAuthStateListener stateListener,
            @NonNull Keychain biometryKeychain,
            @NonNull Keychain tokenStoreKeychain,
            @NonNull BiometricDataMapper biometricDataMapper,
            @NonNull ICallbackDispatcher callbackDispatcher,
            @NonNull IPowerAuthTimeSynchronizationService timeSynchronizationService,
            @NonNull IServerStatusProvider serverStatusProvider,
            @NonNull IKeystoreService keystoreService) {
        this.mLock = sharedLock;
        this.mSession = session;
        this.mConfiguration = configuration;
        this.mBiometricConfiguration = biometricConfiguration;
        this.mKeychainConfiguration = keychainConfiguration;
        this.mExecutorProvider = executorProvider;
        this.mClient = client;
        this.mStateListener = stateListener;
        this.mBiometryKeychain = biometryKeychain;
        this.mBiometricDataMapper = biometricDataMapper;
        this.mCallbackDispatcher = callbackDispatcher;
        this.mTokenStore = new PowerAuthTokenStore(this, tokenStoreKeychain, session, client, this::resolveCredentialsWithAuthentication);
        this.mTimeSynchronizationService = timeSynchronizationService;
        this.mServerStatusProvider = serverStatusProvider;
        this.mKeystoreService = keystoreService;
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
     * Converts high level authentication object into low level {@link CoreCredentials} object.
     *
     * @param authentication authentication object to be converted
     * @return {@link CoreCredentials} object
     */
    private @NonNull CoreCredentials resolveCredentialsWithAuthentication(@NonNull PowerAuthAuthentication authentication) throws PowerAuthErrorException {

        // Validate authentication usage for authentication code calculation.
        authentication.validateAuthenticationUsage(false);

        if (authentication.useBiometricFactor()) {
            // Biometry
            final SecureData biometricKek = authentication.getBiometryFactorRelatedKey();
            if (biometricKek == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Biometric factor key is not fetched in advance.");
            }
            return CoreCredentials.biometry(biometricKek);
        }
        final Password password = authentication.getPassword();
        if (password != null) {
            // Knowledge
            return CoreCredentials.knowledge(password);
        }
        // Possession only
        return CoreCredentials.possession();
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
     * Return object providing time synchronized with the server and allows you initiate such synchronization.
     * @return Object implementing {@link IPowerAuthTimeSynchronizationService} ingerface.
     */
    public @NonNull IPowerAuthTimeSynchronizationService getTimeSynchronizationService() {
        return mTimeSynchronizationService;
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
     * Get current {@link PowerAuthAlgorithm}. If PowerAuthSDK has no activation, then algorithm is
     * equal to algorithm provided in the configuration.
     * @return Current {@link PowerAuthAlgorithm}.
     */
    @SuppressLint("WrongConstant")
    @PowerAuthAlgorithm
    public int getCurrentAlgorithm() {
        return mSession.getCurrentAlgorithm();
    }

    /**
     * @return Configuration provided during the SDK object construction.
     */
    public @NonNull PowerAuthConfiguration getConfiguration() {
        return mConfiguration;
    }

    /**
     * @return Biometric configuration provided during the SDK object construction.
     */
    public @NonNull PowerAuthBiometricConfiguration getBiometricConfiguration() {
        return mBiometricConfiguration;
    }

    /**
     * @return Client configuration provided during the SDK object construction.
     */
    public @NonNull PowerAuthClientConfiguration getClientConfiguration() {
        return mClient.getConfiguration();
    }

    /**
     * @return Keychain configuration provided during the SDK object construction.
     */
    public @NonNull PowerAuthKeychainConfiguration getKeychainConfiguration() {
        return mKeychainConfiguration;
    }

    /**
     * Get low-level {@link CoreSession} object.
     * <p>
     * Be aware that this method should be used only for the testing or debugging purposes. If you
     * call this method in RELEASE build, then {@link IllegalStateException} is raised.
     *
     * @return Instance of {@link CoreSession}.
     */
    @NonNull
    public CoreSession getCoreSession() {
        if (!BuildConfig.DEBUG) {
            throw new IllegalStateException("Getting CoreSession is not allowed");
        }
        return mSession;
    }

    /**
     * The method is used for saving serialized state of CoreSession.
     */
    private void saveSerializedState() {
        try {
            mLock.lock();
            final byte[] state = mSession.getSerializedState();
            mStateListener.onPowerAuthStateChanged(mConfiguration.getInstanceId(), state);
        } catch (CoreException exception) {
            PowerAuthLog.e("Session serialization failed: " + exception.getMessage());
        } finally {
            mLock.unlock();
        }
    }

    /**
     * Restores previously saved PA state.
     * @param state saved CoreSession state.
     */
    private void restoreState(@Nullable byte[] state) throws PowerAuthErrorException {
        try {
            mSession.resetSession();
            if (state != null) {
                mSession.deserializeState(state);
            }
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Checks if the PA library has not been compiled with debug parameters
     *
     * @return Returns true if dynamic library was compiled with a debug features. It is highly recommended
     * to check this boolean and force application to crash, if the production, final app
     * is running against a debug featured library.
     */
    @CheckResult
    public boolean hasDebugFeatures() {
        return BuildConfig.DEBUG || NativeModule.hasDebugFeatures();
    }

    /**
     * Check if it is possible to start an activation process.
     *
     * @return true if activation process can be started, FALSE otherwise.
     */
    @CheckResult
    public boolean canStartActivation() {
        return mSession.canCreateActivation();
    }

    /**
     * Checks if there is a pending activation (activation in progress).
     *
     * @return TRUE if there is a pending activation, FALSE otherwise.
     */
    @CheckResult
    public boolean hasPendingActivation() {
        return mSession.hasPendingCreateActivation();
    }

    /**
     * Checks if there is a valid activation.
     *
     * @return TRUE if there is a valid activation, FALSE otherwise.
     */
    @CheckResult
    public boolean hasValidActivation() {
        return mSession.hasValidActivationData();
    }

    /**
     * Destroy the PowerAuthSDK instance. Internal objects will be securely destroyed and PowerAuthSDK instance
     * can't be more used after this call.
     * <p>
     * Be aware that after this call, any usage of this instance may lead to {@link IllegalStateException}.
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
     */
    public @Nullable ICancelable createActivation(@NonNull final PowerAuthActivation activation, @NonNull final ICreateActivationListener listener) {
        try {
            // Prepare both layers of activation data
            Map<String, Object> L1Data = new HashMap<>(3);
            L1Data.put("type", activation.activationType);
            L1Data.put("identityAttributes", activation.identityAttributes);
            if (activation.customAttributes != null) {
                L1Data.put("customAttributes", activation.customAttributes);
            }

            Map<String, Object> L2Data = new HashMap<>(5);
            if (activation.activationName != null) {
                L2Data.put("activationName", activation.activationName);
            }
            if (activation.extras != null) {
                L2Data.put("extras", activation.extras);
            }
            if (activation.additionalActivationOtp != null) {
                L2Data.put("activationOtp", activation.additionalActivationOtp);
            }
            L2Data.put("platform", PowerAuthSystem.getPlatform());
            L2Data.put("deviceInfo", PowerAuthSystem.getDeviceInfo());

            // Create HTTP request
            final CoreRequest<CoreActivationResult> request = mSession.createActivation(L1Data, L2Data);

            // Post request.
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable CoreActivationResult coreActivationResult) {
                    CoreActivationResult coreResult = Objects.requireNonNull(coreActivationResult);
                    listener.onActivationCreateSucceed(
                            new CreateActivationResult(
                                    coreResult.getActivationFingerprint(),
                                    coreResult.getCustomAttributes(),
                                    new UserInfo(coreResult.getUserInfo())
                            )
                    );
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onActivationCreateFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });

        } catch (CoreException exception) {
            dispatchCallback(() -> listener.onActivationCreateFailed(PowerAuthErrorException.wrapException(exception)));
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

    //
    // Persist activation
    //

    /**
     * Persist activation that was created and store related data using provided authentication object instance.
     *
     * @param context android context object
     * @param authentication An authentication instance specifying what factors should be stored.
     * @param listener A callback listener called when the process finishes or fails.
     * @return {@link ICancelable} object associated with the running HTTP request or with the biometric authentication.
     *         If {@code null} is returned, then the operation failed or completed immediately.
     */
    public @Nullable ICancelable persistActivationWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, @NonNull IPersistActivationListener listener) {
        final Password password = authentication.getPassword();
        final PowerAuthBiometricPrompt biometricPrompt = authentication.getBiometricPrompt();
        if (biometricPrompt == null || password == null) {
            // Persist operation doesn't require biometric dialog to display, so no composite cancelable
            // operation is required.
            //
            // If password is null, then "persistActivationImpl()" will fail at input validation.
            try {
                return persistActivationImpl(authentication, listener);
            } catch (PowerAuthErrorException e) {
                dispatchCallback(() -> listener.onPersistActivationFailed(e));
                return null;
            }
        }
        // It seems that we have to resolve biometric key before we persist. In this case, the
        // cancelable composite operation is required.
        final CompositeCancelableTask composite = new CompositeCancelableTask(true);
        composite.setCancelCallback(() -> {
            // Application canceled the task
            dispatchCallback(() -> listener.onPersistActivationCancelled(false));
        });
        ICancelable resolveTask = authenticateUsingBiometrics(context, biometricPrompt, true, new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                if (composite.setCompleted()) {
                    listener.onPersistActivationCancelled(userCancel);
                }
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                try {
                    final PowerAuthAuthentication resolvedAuthentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(password, biometricKeyData.getDerivedData());
                    ICancelable persistTask = persistActivationImpl(resolvedAuthentication, new IPersistActivationListener() {
                        @Override
                        public void onPersistActivationSucceeded() {
                            if (composite.setCompleted()) {
                                listener.onPersistActivationSucceeded();
                            }
                        }

                        @Override
                        public void onPersistActivationFailed(@NonNull Throwable throwable) {
                            if (composite.setCompleted()) {
                                listener.onPersistActivationFailed(throwable);
                            }
                        }

                        @Override
                        public void onPersistActivationCancelled(boolean userCancel) {
                            // cancel is already handled in composite's cancel callback
                        }
                    });
                    if (persistTask != null) {
                        // V4, asynchronous operation
                        composite.addCancelable(persistTask);
                    } else {
                        // V3, synchronous, report success
                        if (composite.setCompleted()) {
                            listener.onPersistActivationSucceeded();
                        }
                    }

                } catch (PowerAuthErrorException e) {
                    listener.onPersistActivationFailed(e);
                }
            }

            @Override
            public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                listener.onPersistActivationFailed(error);
            }
        });
        composite.addCancelable(resolveTask);
        return composite;
    }

    /**
     * Persist activation that was created and store related data using provided password object instance.
     *
     * @param context Android context object.
     * @param password Password to be used for the knowledge related authentication factor.
     * @param listener A callback listener called when the process finishes or fails.
     * @return {@link ICancelable} object associated with the running HTTP request If {@code null} is returned, then the
     *         operation failed or completed immediately.
     */
    public @Nullable ICancelable persistActivationWithPassword(@NonNull Context context, @NonNull Password password, @NonNull IPersistActivationListener listener) {
        return persistActivationWithAuthentication(context, PowerAuthAuthentication.persistWithPassword(password), listener);
    }

    /**
     * Persist activation that was created and store related data using provided password.
     *
     * @param context Android context object.
     * @param password Password to be used for the knowledge related authentication factor.
     * @param listener A callback listener called when the process finishes or fails.
     * @return {@link ICancelable} object associated with the running HTTP request If {@code null} is returned, then the
     *         operation failed or completed immediately.
     */
    public @Nullable ICancelable persistActivationWithPassword(@NonNull Context context, @NonNull String password, @NonNull IPersistActivationListener listener) {
        return persistActivationWithAuthentication(context, PowerAuthAuthentication.persistWithPassword(password), listener);
    }

    /**
     * Persist activation in the low level Session object with provided authentication object. Note that the authentication object
     * must have biometric factor key already resolved.
     * @param authentication Instance of authentication object with required password and optional key for biometric factor.
     * @param listener Callback to
     * @return Asynchronous operation in case persist is asynchronous, otherwise null.
     * @throws PowerAuthErrorException Thrown in case of failure.
     */
    @Nullable
    private ICancelable persistActivationImpl(@NonNull PowerAuthAuthentication authentication, @Nullable IPersistActivationListener listener) throws PowerAuthErrorException {
        try {
            authentication.validateAuthenticationUsage(true);

            final Password password = authentication.getPassword();
            if (password == null) {
                throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Password must be set for persist activation operation");
            }
            final CoreTask<Object> task = mSession.confirmActivation(password, authentication.getBiometryFactorRelatedKey());
            if (listener == null) {
                // @Deprecated 2.0.0
                // Listener is not provided, so application is still using deprecated synchronous API.
                if (task != null) {
                    // Persist is unfortunately asynchronous, so we cannot continue. Cancel the task and report error.
                    task.cancel();
                    throw new PowerAuthErrorException(PowerAuthErrorCodes.WRONG_PARAMETER, "Synchronous persist is not supported at this protocol version");
                }
                return null;
            }
            if (task == null) {
                // This is legit for V3 activations. Persist doesn't require HTTP communication with the server.
                saveSerializedState();
                dispatchCallback(listener::onPersistActivationSucceeded);
                return null;
            }
            // So far, so good, execute the task.
            return mClient.post(task, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    saveSerializedState();
                    listener.onPersistActivationSucceeded();
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onPersistActivationFailed(throwable);
                }

                @Override
                public void onCancel() {
                    // Canceled by application itself
                    dispatchCallback(() -> listener.onPersistActivationCancelled(false));
                }
            });

        } catch (CoreException exception) {
            // Wrap core exception into PowerAuthErrorException
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     * @noinspection DeprecatedIsStillUsed
     */
    @CheckResult
    @PowerAuthErrorCodes
    @Deprecated // 2.0.0
    public int persistActivationWithPassword(@NonNull Context context, @NonNull String password) {
        return persistActivationWithAuthentication(context, PowerAuthAuthentication.persistWithPassword(password));
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     * @noinspection DeprecatedIsStillUsed
     */
    @CheckResult
    @PowerAuthErrorCodes
    @Deprecated // 2.0.0
    public int persistActivationWithPassword(@NonNull Context context, @NonNull Password password) {
        return persistActivationWithAuthentication(context, PowerAuthAuthentication.persistWithPassword(password));
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentActivity Activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used to persist activation.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable persistActivation(
            final @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            @NonNull final String password,
            final @NonNull IPersistActivationWithBiometricsListener callback) {
        return persistActivationWithBiometricsImpl(context, PowerAuthBiometricPrompt.prompt(fragmentActivity, title, description), new Password(password), callback);
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragmentActivity Activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used to persist activation.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable persistActivation(
            final @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            @NonNull final Password password,
            final @NonNull IPersistActivationWithBiometricsListener callback) {
        return persistActivationWithBiometricsImpl(context, PowerAuthBiometricPrompt.prompt(fragmentActivity, title, description), password, callback);
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragment Fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used to persist activation.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable persistActivation(
            final @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            @NonNull final String password,
            final @NonNull IPersistActivationWithBiometricsListener callback) {
        return persistActivationWithBiometricsImpl(context, PowerAuthBiometricPrompt.prompt(fragment, title, description), new Password(password), callback);
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param fragment Fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param password Password used to persist activation.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable persistActivation(
            final @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            @NonNull final Password password,
            final @NonNull IPersistActivationWithBiometricsListener callback) {
        return persistActivationWithBiometricsImpl(context, PowerAuthBiometricPrompt.prompt(fragment, title, description), password, callback);
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password and biometry key.
     *
     * @param context Context.
     * @param prompt Prompt with information required for the dialog presentation.
     * @param password Password used to persist activation.
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @noinspection deprecation
     */
    @UiThread
    @NonNull
    // @Deprecated // 2.0.0 - remove in 2.1.0
    private ICancelable persistActivationWithBiometricsImpl(
            final @NonNull Context context,
            @NonNull PowerAuthBiometricPrompt prompt,
            @NonNull final Password password,
            final @NonNull IPersistActivationWithBiometricsListener callback) {
        return authenticateUsingBiometrics(context, prompt, true, new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                if (userCancel) {
                    callback.onBiometricDialogCancelled();
                }
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                final PowerAuthAuthentication authentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(password, biometricKeyData.getDerivedData());
                final int errorCode = persistActivationWithAuthentication(context, authentication);
                biometricKeyData.destroy();
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
     * Persist activation that was created and store related data using default authentication instance setup with provided password.
     * <p>
     * Calling this method is equivalent to {@link #persistActivationWithAuthentication(Context, PowerAuthAuthentication)}  with authentication object set to use all factors and provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @param encryptedBiometryKey Optional biometry related factor key.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @CheckResult
    @PowerAuthErrorCodes
    @Deprecated // 2.0.0
    public int persistActivationWithPassword(@NonNull Context context, @NonNull String password, @Nullable SecureData encryptedBiometryKey) {
        return persistActivationWithPassword(context, new Password(password), encryptedBiometryKey);
    }

    /**
     * Persist activation that was created and store related data using default authentication instance setup with provided password.
     * <p>
     * Calling this method is equivalent to {@link #persistActivationWithAuthentication(Context, PowerAuthAuthentication)} with authentication object set to use all factors and provided password.
     *
     * @param context Context
     * @param password Password to be used for the knowledge related authentication factor.
     * @param encryptedBiometryKey Optional biometry related factor key.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     */
    @CheckResult
    @PowerAuthErrorCodes
    @Deprecated // 2.0.0
    public int persistActivationWithPassword(@NonNull Context context, @NonNull Password password, @Nullable SecureData encryptedBiometryKey) {
        return persistActivationWithAuthentication(context, new PowerAuthAuthentication(true, password, null, encryptedBiometryKey, null));
    }

    /**
     * Persist activation that was created and store related data using provided authentication instance.
     *
     * @param context android context object
     * @param authentication An authentication instance specifying what factors should be stored.
     * @return int {@link PowerAuthErrorCodes} error code.
     * @deprecated Replaced with asynchronous methods with {@link IPersistActivationListener} callback parameter.
     * @noinspection DeprecatedIsStillUsed
     */
    @CheckResult
    @PowerAuthErrorCodes
    @Deprecated // 2.0.0
    public int persistActivationWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication) {
        try {
            persistActivationImpl(authentication, null);
            return PowerAuthErrorCodes.SUCCEED;
        } catch (PowerAuthErrorException e) {
            return e.getPowerAuthErrorCode();
        }
    }

    //
    // User Info
    //

    /**
     * Return last fetched information about the user. The information about user is optional and
     * must be supported by the server. The value is updated during the activation process or by
     * calling {@link #fetchUserInfo(Context, IUserInfoListener)}.
     *
     * @return {@link UserInfo} object or {@code null} if information is not retrieved yet.
     */
    public @Nullable UserInfo getLastFetchedUserInfo() {
        final Map<String, Object> claims = mSession.getLastUserInfo();
        return claims == null ? null : new UserInfo(claims);
    }

    /**
     * Fetch information about the user from the server. If operation succeed, then the user
     * information object is also internally stored and available in {@link #getLastFetchedUserInfo()}
     * method.
     *
     * @param context Android context.
     * @param listener A callback called once the user info is retrieved from the server.
     * @return {@link ICancelable} object associated with the pending HTTP request.
     */
    @Nullable
    public ICancelable fetchUserInfo(@NonNull Context context, @NonNull IUserInfoListener listener) {
        try {
            final CoreRequest<Map<String, Object>> request = mSession.fetchUserInfo();
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Map<String, Object> claims) {
                    listener.onUserInfoSucceed(new UserInfo(claims));
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onUserInfoFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onUserInfoFailed(PowerAuthErrorException.wrapException(e)));
        }
        return null;
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
     * Return {@link PowerAuthActivationStatus} recently received from the server. You need to call
     * {@link #fetchActivationStatusWithCallback(Context, IActivationStatusListener)} method to
     * update result from this method.
     *
     * @return {@link PowerAuthActivationStatus} object recently received from the server or null, if
     *         there's no activation, or status was not received yet.
     */
    public @Nullable PowerAuthActivationStatus getLastFetchedActivationStatus() {
        final CoreActivationStatus coreStatus = mSession.getLastActivationStatus();
        return  coreStatus == null ? null : new PowerAuthActivationStatus(coreStatus);
    }

    /**
     * Fetch the activation status for current activation.
     * <p>
     * If server returns custom object, it is returned in the callback as NSDictionary.
     *
     * @param context  Context
     * @param listener A callback listener with activation status result - it contains status information in case of success and error in case of failure.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable fetchActivationStatusWithCallback(@NonNull final Context context, @NonNull final IActivationStatusListener listener) {
        // Cancelable object returned to the application
        ICancelable task = null;

        final ITaskCompletion<PowerAuthActivationStatus> completion = new ITaskCompletion<>() {
            @Override
            public void onSuccess(@NonNull PowerAuthActivationStatus activationStatus) {
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
                mGetActivationStatusTask = new GetActivationStatusTask(mClient, mSession, mLock, mCallbackDispatcher, this::saveSerializedState, getActivationStatusTask -> {
                    // The mLock is already locked, because GetActivationStatusTask uses shared lock.
                    if (getActivationStatusTask == mGetActivationStatusTask) {
                        mGetActivationStatusTask = null;
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
     */
    public @Nullable
    ICancelable removeActivationWithAuthentication(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final IActivationRemoveListener listener) {
        try {
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final CoreRequest<Object> request = mSession.removeActivation(credentials);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    listener.onActivationRemoveSucceed();
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onActivationRemoveFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onActivationRemoveFailed(PowerAuthErrorException.wrapException(e)));
        } catch (PowerAuthErrorException e) {
            dispatchCallback(() -> listener.onActivationRemoveFailed(e));
        }
        return null;
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
     */
    public void removeActivationLocal(@NonNull Context context) {

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
     * @deprecated Use {@link #removeActivationLocal(Context)} as a replacement.
     */
    @Deprecated // 1.7.10 - remove in 2.0.0
    public void removeActivationLocal(@NonNull Context context, boolean removeSharedBiometryKey) {
        removeActivationLocal(context);
    }

    // Protocol Upgrade

    /**
     * Start the protocol upgrade process.
     *
     * @param context Android context.
     * @param password Required {@link Password} instance used to authenticate the protocol upgrade start.
     * @param encryptedBiometryKey TODO
     * @param listener A callback with protocol upgrade result.
     * @return {@link ICancelable} associated with the running task.
     */
    public @Nullable
    ICancelable startProtocolUpgrade(@NonNull final Context context,
                                     @NonNull final Password password,
                                     @Nullable final SecureData encryptedBiometryKey,
                                     @NonNull final IProtocolUpgradeListener listener) {

        try {
            final CoreTask<CoreProtocolUpgradeResult> task = mSession.startProtocolUpgrade(password, encryptedBiometryKey);
            return mClient.post(task, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable CoreProtocolUpgradeResult coreProtocolUpgradeResult) {
                    final CoreProtocolUpgradeResult coreResult = Objects.requireNonNull(coreProtocolUpgradeResult);
                    saveSerializedState();
                    listener.onProtocolUpgradeSucceed(
                            new ProtocolUpgradeResult(
                                    coreResult.isActivationStatusFetchRequired(),
                                    coreResult.getActivationFingerprint()
                            )
                    );
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onProtocolUpgradeFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onProtocolUpgradeFailed(PowerAuthErrorException.wrapException(e)));
            return null;
        }
    }

    /**
     * Start the protocol upgrade process.
     *
     * @param context Android context.
     * @param password Required password used to authenticate the protocol upgrade start.
     * @param encryptedBiometryKey TODO
     * @param listener A callback with protocol upgrade result.
     * @return {@link ICancelable} associated with the running task.
     */
    public @Nullable
    ICancelable startProtocolUpgrade(@NonNull final Context context,
                                     @NonNull final String password,
                                     @Nullable final SecureData encryptedBiometryKey,
                                     @NonNull final IProtocolUpgradeListener listener) {
        return startProtocolUpgrade(context, new Password(password), encryptedBiometryKey, listener);
    }

    /**
     * Start the protocol upgrade process.
     *
     * @param context Android context.
     * @param password Required {@link Password} instance used to authenticate the protocol upgrade start.
     * @param listener A callback with protocol upgrade result.
     * @return {@link ICancelable} associated with the running task.
     */
    public @Nullable
    ICancelable startProtocolUpgrade(@NonNull final Context context,
                                     @NonNull final Password password,
                                     @NonNull final IProtocolUpgradeListener listener) {
        return startProtocolUpgrade(context, password, null, listener);
    }

    /**
     * Start the protocol upgrade process.
     *
     * @param context Android context.
     * @param password Required password used to authenticate the protocol upgrade start.
     * @param listener A callback with protocol upgrade result.
     * @return {@link ICancelable} associated with the running task.
     */
    public @Nullable
    ICancelable startProtocolUpgrade(@NonNull final Context context,
                                     @NonNull final String password,
                                     @NonNull final IProtocolUpgradeListener listener) {
        return startProtocolUpgrade(context, new Password(password), null, listener);
    }

    /**
     * Returns {@code true}, if there is a valid activation that has available protocol upgrade.
     * Once the upgrade process has started, it contains {@code false}.
     *
     * @return {@code true} if protocol upgrade is available. {@code false} otherwise.
     */
    public boolean hasProtocolUpgradeAvailable() {
        return mSession.hasProtocolUpgradeAvailable();
    }

    /**
     * Returns {@code true} if the session has pending protocol upgrade, meaning the protocol
     * upgrade process has started, but has not yet finished. Some SDK functionality may be
     * temporarily blocked during the upgrade process.
     *
     * @return {@code true} if the protocol upgrade process is pending, {@code false} otherwise.
     */
    public boolean hasPendingProtocolUpgrade() {
        return mSession.hasPendingProtocolUpgrade();
    }

    // Authentication codes

    /**
     * Computes the HTTP header containing the authentication code for an HTTP method, URI identifier, and HTTP body
     * using the provided authentication information.
     * <p>
     * It is recommended to call this method from the context of the SDK-provided serial executor to avoid counter
     * de-synchronization. See the documentation for {@link #getSerialExecutor()} for more details.
     *
     * @param authentication An authentication instance specifying which factors should be used to authenticate the request.
     * @param method         HTTP method used for the authentication code computation.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @return HTTP header with PowerAuth authentication code.
     * @throws PowerAuthErrorException thrown in case the failure. The reason of failure is indicated in value
     *                       returned in {@link PowerAuthErrorException#getPowerAuthErrorCode()} method.
     */
    @NonNull
    public PowerAuthHttpHeader authenticationHeaderForRequestWithBody(@NonNull PowerAuthAuthentication authentication,
                                                                      @NonNull String method,
                                                                      @NonNull String uriId,
                                                                      @Nullable byte[] body) throws PowerAuthErrorException {
        try {
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final CoreHttpHeader header = mSession.calculateOnlineAuthenticationHeader(credentials, uriId, method, body);
            saveSerializedState();
            return PowerAuthHttpHeader.fromCoreObject(header);
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Compute the HTTP header containing authentication code for HTTP method, URI identifier and HTTP query parameters
     * using provided authentication information.
     * <p>
     * It is recommended to call this method from the context of the SDK-provided serial executor to avoid counter
     * de-synchronization. See the documentation for {@link #getSerialExecutor()} for more details.
     *
     * @param authentication An authentication instance specifying which factors should be used to authenticate the request.
     * @param method         HTTP method used for the authentication code computation.
     * @param uriId          URI identifier.
     * @param params         HTTP request query parameters
     * @return HTTP header with PowerAuth authentication code.
     * @throws PowerAuthErrorException thrown in case the failure. The reason of failure is indicated in value
     *                       returned in {@link PowerAuthErrorException#getPowerAuthErrorCode()} method.
     */
    @NonNull
    public PowerAuthHttpHeader authenticationHeaderForRequestWithParams(@NonNull PowerAuthAuthentication authentication,
                                                                        @NonNull String method,
                                                                        @NonNull String uriId,
                                                                        @Nullable Map<String, String> params) throws PowerAuthErrorException {
        try {
            final byte[] normalizedParams = mSession.normalizeGetRequestParameters(params);
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final CoreHttpHeader header = mSession.calculateOnlineAuthenticationHeader(credentials, uriId, method, normalizedParams);
            saveSerializedState();
            return PowerAuthHttpHeader.fromCoreObject(header);
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Computes the offline authentication code for a given URI identifier, and HTTP request body using
     * the provided authentication information.
     * <p>
     * Unlike methods for calculating an authentication header for an online HTTP request, you don't need to authenticate
     * with biometry in advance. This method properly handles biometric authentication if the biometric factor is requested.
     * @param context        Context.
     * @param authentication An authentication instance specifying which factors should be used to authenticate the request.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @param nonce          Nonce in Base64 format.
     * @param listener       A callback listener.
     * @return Cancelable object associated with the pending biometric authentication.
     */
    @NonNull
    public ICancelable offlineAuthenticationCode(@NonNull Context context,
                                                 @NonNull PowerAuthAuthentication authentication,
                                                 @NonNull String uriId,
                                                 @Nullable byte[] body,
                                                 @NonNull String nonce,
                                                 @NonNull IOfflineAuthenticationCodeListener listener) {
        // Prepare composite task that will cover the whole operation
        final CompositeCancelableTask task = new CompositeCancelableTask(true);
        // Prepare a completion function that dispatch result to the main thread.
        final IBiConsumer<PowerAuthErrorException, String> taskCompletion = (PowerAuthErrorException exception, String authenticationCode) -> {
            dispatchCallback(() -> {
                if (task.setCompleted()) {
                    if (authenticationCode != null) {
                        listener.onOfflineAuthenticationCodeSucceed(authenticationCode);
                    } else {
                        listener.onOfflineAuthenticationCodeFailed(exception);
                    }
                }
            });
        };
        // Prepare execution function that compute authentication code in the serial queue
        final IConsumer<PowerAuthAuthentication> taskExecution = (PowerAuthAuthentication auth) -> {
            try {
                // Execute calculation in the serial executor.
                getSerialExecutor().execute(() -> {
                    try {
                        if (task.isCancelled()) {
                            return;
                        }
                        final String authCode = calculateOfflineAuthenticationCode(authentication, uriId, nonce, body);
                        taskCompletion.accept(null, authCode);
                        throw new PowerAuthErrorException(PowerAuthErrorCodes.OTHER, "Not implemented");
                    } catch (PowerAuthErrorException exception) {
                        // Authentication code calculation failed.
                        taskCompletion.accept(exception, null);
                    }
                });
            } catch (PowerAuthErrorException e) {
                // Failed to acquire executor, due to an invalid activation state.
                taskCompletion.accept(e, null);
            }
        };
        if (authentication.getBiometryFactorRelatedKey() == null && authentication.getBiometricPrompt() != null) {
            // If biometric authentication is requested and the key is not resolved yet, then authenticate with biometry first.
            task.addCancelable(
                    authenticateUsingBiometrics(context, authentication.getBiometricPrompt(), new IAuthenticateWithBiometricsListener() {
                        @Override
                        public void onBiometricDialogCancelled(boolean userCancel) {
                            if (userCancel) {
                                taskCompletion.accept(new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_CANCEL), null);
                            }
                        }

                        @Override
                        public void onBiometricDialogSuccess(@NonNull PowerAuthAuthentication authentication) {
                            taskExecution.accept(authentication);
                        }

                        @Override
                        public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                            taskCompletion.accept(error, null);
                        }
                    })
            );
        } else {
            // Seems that authentication object is already resolved, no additional tasks are required. So execute the
            // authentication code computation.
            taskExecution.accept(authentication);
        }
        return task;
    }

    /**
     * Calculate offline authentication code.
     *
     * @param authentication Authentication object.
     * @param uriId URI Identifier.
     * @param nonce Offline nonce in Base64 format.
     * @param body Data to sign.
     * @return Human readable authentication code.
     * @throws PowerAuthErrorException In case of failure.
     */
    @NonNull
    private String calculateOfflineAuthenticationCode(@NonNull PowerAuthAuthentication authentication,
                                                      @NonNull String uriId,
                                                      @NonNull String nonce,
                                                      @Nullable byte[] body) throws PowerAuthErrorException {
        try {
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final int codeLength = mConfiguration.getOfflineAuthenticationCodeComponentLength();
            String code = mSession.calculateOfflineAuthenticationCode(credentials, uriId, nonce, codeLength, body);
            saveSerializedState();
            return code;
        } catch (CoreException e) {
            throw PowerAuthErrorException.wrapException(e);
        }
    }

    // Deprecated signatures

    /**
     * Compute the HTTP signature header for given GET request, URI identifier and query parameters using provided authentication information.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param uriId          URI identifier.
     * @param params         GET request query parameters
     * @return HTTP header with PowerAuth authentication code when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @deprecated Use {@link #authenticationHeaderForRequestWithParams(PowerAuthAuthentication, String, String, Map)} for replacement.
     */
    @Deprecated // 2.0.0
    public @NonNull PowerAuthAuthorizationHttpHeader requestGetSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, Map<String, String> params) {
        try {
            return new PowerAuthAuthorizationHttpHeader(authenticationHeaderForRequestWithParams(authentication, "GET", uriId, params));
        } catch (PowerAuthErrorException e) {
            return new PowerAuthAuthorizationHttpHeader(e.getPowerAuthErrorCode());
        }
    }

    /**
     * Compute the HTTP signature header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
     *
     * @param context        Context.
     * @param authentication An authentication instance specifying what factors should be used to sign the request.
     * @param method         HTTP method used for the signature computation.
     * @param uriId          URI identifier.
     * @param body           HTTP request body.
     * @return HTTP header with PowerAuth authentication signature when PA2Succeed returned in powerAuthErrorCode. In case of error return null header value.
     * @deprecated Use {@link #authenticationHeaderForRequestWithBody(PowerAuthAuthentication, String, String, byte[])} for replacement.
     */
    @Deprecated // 2.0.0
    public @NonNull PowerAuthAuthorizationHttpHeader requestSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String method, String uriId, byte[] body) {
        try {
            return new PowerAuthAuthorizationHttpHeader(authenticationHeaderForRequestWithBody(authentication, method, uriId, body));
        } catch (PowerAuthErrorException e) {
            return new PowerAuthAuthorizationHttpHeader(e.getPowerAuthErrorCode());
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
     * @deprecated Use {@link #offlineAuthenticationCode(Context, PowerAuthAuthentication, String, byte[], String, IOfflineAuthenticationCodeListener)}
     */
    @Deprecated // 2.0.0
    public @Nullable String offlineSignatureWithAuthentication(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, String uriId, byte[] body, String nonce) {
        if (nonce == null) {
            PowerAuthLog.e("offlineSignatureWithAuthentication: 'nonce' parameter is required.");
            return null;
        }
        if (uriId == null) {
            PowerAuthLog.e("offlineSignatureWithAuthentication: 'uriId' parameter is required.");
            return null;
        }
        try {
            return calculateOfflineAuthenticationCode(authentication, uriId, nonce, body);
        } catch (PowerAuthErrorException e) {
            PowerAuthLog.e("offlineSignatureWithAuthentication: Failed at: " + e.getMessage());
            return null;
        }
    }

    // Digital signatures

    /**
     * Export device public key(s) into the specified format.
     * @param format Required format of the output public key data.
     * @return List with {@link PowerAuthDevicePublicKeyData} containing public key data.
     * @throws PowerAuthErrorException In case of failure.
     */
    @NonNull
    public List<PowerAuthDevicePublicKeyData> exportDevicePublicKeys(@PowerAuthDevicePublicKeyFormat int format) throws PowerAuthErrorException {
        try {
            final int coreFormat = format == PowerAuthDevicePublicKeyFormat.DER ? CoreDevicePublicKeyFormat.SPKI : CoreDevicePublicKeyFormat.RAW;
            CoreDevicePublicKeyData[] coreKeys = mSession.exportDevicePublicKeys(coreFormat);
            return PowerAuthDevicePublicKeyData.fromCoreObject(coreKeys);
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Convert {@link PowerAuthSignatureKeyId} into {@link CoreSignatureKeyId}.
     * @param keyId Key identifier to convert.
     * @return Converted key identifier.
     */
    @SuppressLint("WrongConstant")
    @CoreSignatureKeyId
    private static int convertPowerAuthSignatureKeyId(@PowerAuthSignatureKeyId int keyId) {
        // @PowerAuthSignatureKeyId is defined from @CoreSignatureKeyId constants, so direct return
        // with suppressed warning is OK.
        return keyId;
    }

    /**
     * Verifies a digital signature for the given data using the key specified by its identifier.
     * <p>
     * If the selected key identifier represents multiple key types, an error is reported.
     * Hybrid signatures are not supported in this version of the library.
     *
     * @param signature The digital signature calculated for the data.
     * @param signedData The data that was signed.
     * @param keyIdentifier The identifier of the key used for verification.
     * @throws PowerAuthErrorException In case of failure. If the signature is not valid, then
     *      exception with {@link PowerAuthErrorCodes#WRONG_SIGNATURE} code is raised.
     */
    public void verifyDigitalSignature(@NonNull byte[] signature,
                                       @Nullable byte[] signedData,
                                       @PowerAuthSignatureKeyId int keyIdentifier) throws PowerAuthErrorException {
        try {
            mSession.verifySignature(signature, signedData, convertPowerAuthSignatureKeyId(keyIdentifier));
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Calculates a digital signature for the given data using the key specified by its identifier.
     * <p>
     * The selected key must support signature calculation; otherwise, an error is reported.
     * If the key identifier represents multiple key types, an error is also reported.
     * Hybrid signatures are not supported in this version of the library.
     *
     * @param context Android context.
     * @param authentication The authentication object used for vault unlocking.
     * @param dataToSign The data to sign.
     * @param keyIdentifier The identifier of the key used for signature calculation.
     * @param listener The callback interface invoked with the resulting signature or an error.
     * @return Cancelable object associated with the asynchronous operation, or {@code null} if
     *         the error is detected immediately.
     */
    @Nullable
    public ICancelable calculateDigitalSignature(@NonNull Context context,
                                                 @NonNull PowerAuthAuthentication authentication,
                                                 @Nullable byte[] dataToSign,
                                                 @PowerAuthSignatureKeyId int keyIdentifier,
                                                 @NonNull IDigitalSignatureListener listener) {
        try {
            final int coreKeyId = convertPowerAuthSignatureKeyId(keyIdentifier);
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final CoreRequest<byte[]> request = mSession.signData(dataToSign, credentials, coreKeyId);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable byte[] bytes) {
                    byte[] response = Objects.requireNonNull(bytes);
                    listener.onDigitalSignatureSucceed(response);
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onDigitalSignatureFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException exception) {
            dispatchCallback(() -> listener.onDigitalSignatureFailed(PowerAuthErrorException.wrapException(exception)));
        } catch (PowerAuthErrorException exception) {
            dispatchCallback(() -> listener.onDigitalSignatureFailed(exception));
        }
        return null;
    }

    /**
     * Validates whether the data has been signed with master server private key, or personalized server's private key.
     *
     * @param data An arbitrary data
     * @param signature A signature calculated for data
     * @param useMasterKey If true, then master server's public key is used for validation, otherwise personalized server's key.
     * @return true if signature is valid
     * @deprecated Method is deprecated, please use {@link #verifyDigitalSignature(byte[], byte[], int)} instead.
     */
    @Deprecated // 2.0.0
    public boolean verifyServerSignedData(byte[] data, byte[] signature, boolean useMasterKey) {
        if (signature == null) {
            return false;
        }
        try {
            int keyId = useMasterKey ? PowerAuthSignatureKeyId.MASTER_EC : PowerAuthSignatureKeyId.SERVER_EC;
            verifyDigitalSignature(signature, data, keyId);
            return true;
        } catch (PowerAuthErrorException exception) {
            return false;
        }
    }

    /**
     * Sign provided data with a private key that is stored in secure vault.
     * @param context Context.
     * @param authentication Authentication object for vault unlock request.
     * @param data Data to be signed.
     * @param listener Listener with callbacks to signature status.
     * @return Async task associated with vault unlock request.
     * @deprecated Method is deprecated, please use {@link #calculateDigitalSignature(Context, PowerAuthAuthentication, byte[], int, IDigitalSignatureListener)} instead.
     */
    @Deprecated // 2.0.0
    @Nullable
    public ICancelable signDataWithDevicePrivateKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, @NonNull final byte[] data, @NonNull final IDataSignatureListener listener) {
        return calculateDigitalSignature(context, authentication, data, PowerAuthSignatureKeyId.DEVICE_EC, new IDigitalSignatureListener() {
            @Override
            public void onDigitalSignatureSucceed(@NonNull byte[] signature) {
                listener.onDataSignedSucceed(signature);
            }

            @Override
            public void onDigitalSignatureFailed(@NonNull Throwable throwable) {
                listener.onDataSignedFailed(throwable);
            }
        });
    }

    // JWS

    /**
     * Verifies JWS or JWT signed data using the key specified by its identifier.
     * <p>
     * If the selected key identifier represents multiple key types, compact format cannot be used.
     *
     * @param signature A string containing JWS or JWT signed data.
     * @param compactForm If {@code true}, the input string is a compact JWT; otherwise, a full JWS object is expected.
     * @param strictVerify If {@code true}, all provided keys must be used to successfully verify their corresponding signatures.
     *                     If {@code false}, verification succeeds when at least one provided key matches a valid signature; however,
     *                     invalid or mismatched signatures still result in an error.
     * @param keyIdentifier The identifier of the key used for verification.
     * @throws PowerAuthErrorException In case of failure. If the signature is not valid, then
     *          exception with {@link PowerAuthErrorCodes#WRONG_SIGNATURE} code is raised.
     */
    public void verifyJwsSignature(@NonNull String signature,
                                   boolean compactForm,
                                   boolean strictVerify,
                                   @PowerAuthSignatureKeyId int keyIdentifier) throws PowerAuthErrorException {
        try {
            final int keyId = convertPowerAuthSignatureKeyId(keyIdentifier);
            mSession.jwsVerifySignature(signature, compactForm, strictVerify, keyId);
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Calculates a JWS signature for the given data using the key specified by its identifier.
     * <p>
     * The selected key must support signature calculation; otherwise, an error is reported.
     * If the key identifier represents multiple key types, compact format cannot be used for output.
     *
     * @param context Android context.
     * @param authentication The authentication object used for vault unlocking.
     * @param dataToSign The data to sign.
     * @param dataType Data type set to JOSE header. Use {@code "JWT"} or {@code null} if no type is set.
     * @param compactForm If {@code true}, the output string is a compact JWT; otherwise, a full JWS object is returned.
     * @param keyIdentifier The identifier of the key used for signature calculation.
     * @param listener The callback interface invoked with the resulting signature or an error.
     * @return Cancelable object associated with the asynchronous operation, or {@code null} if
     *         the error is detected immediately.
     */
    @Nullable
    public ICancelable calculateJwsSignature(@NonNull Context context,
                                             @NonNull PowerAuthAuthentication authentication,
                                             @Nullable byte[] dataToSign,
                                             @Nullable String dataType,
                                             boolean compactForm,
                                             @PowerAuthSignatureKeyId int keyIdentifier,
                                             @NonNull IJwsSignatureListener listener) {
        try {
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final int keyId = convertPowerAuthSignatureKeyId(keyIdentifier);
            final CoreRequest<String> request = mSession.jwsSignData(dataToSign, dataType, compactForm, credentials, keyId);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable String s) {
                    String response = Objects.requireNonNull(s);
                    listener.onJwsSignatureSucceed(response, compactForm);
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onJwsSignatureFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException exception) {
            dispatchCallback(() -> listener.onJwsSignatureFailed(PowerAuthErrorException.wrapException(exception)));
        } catch (PowerAuthErrorException exception) {
            dispatchCallback(() -> listener.onJwsSignatureFailed(exception));
        }
        return null;
    }

    /**
     * Creates X.509 CSR (Certificate Signing Request) with given Distinguished Names and optional Subject Alternative Names,
     * embedded device public key and signed with the device private key.
     *
     * @param context Android context.
     * @param authentication The authentication object used for vault unlocking.
     * @param distinguishedNames Distinguished Names (DN) to be embedded in the CSR. The dictionary keys are DN types (like "CN", "O", etc.) and values are corresponding DN values.
     * @param subjectAltNames Optional array of Subject Alternative Names (SAN)
     * @param keyIdentifier The identifier of the key used for the signature calculation.
     * @param listener The callback interface invoked with the resulting CSR or an error.
     * @return Cancelable object associated with the asynchronous operation, or {@code null} if
     *         the error is detected immediately.
     */
    @Nullable
    public ICancelable createCertificateSigningRequest(@NonNull Context context,
                                                       @NonNull PowerAuthAuthentication authentication,
                                                       @NonNull Map<String, String> distinguishedNames,
                                                       @Nullable List<String> subjectAltNames,
                                                       @PowerAuthSignatureKeyId int keyIdentifier,
                                                       @NonNull ICreateCertificateSigningRequestListener listener) {
        try {
            final CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            final int keyId = convertPowerAuthSignatureKeyId(keyIdentifier);
            final CoreRequest<String> request = mSession.createCertificateSigningRequest(credentials, distinguishedNames, subjectAltNames, keyId);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable String s) {
                    String response = Objects.requireNonNull(s);
                    listener.onCreateCertificateSigningRequestSucceed(response);
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onCreateCertificateSigningRequestFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException exception) {
            dispatchCallback(() -> listener.onCreateCertificateSigningRequestFailed(PowerAuthErrorException.wrapException(exception)));
        } catch (PowerAuthErrorException exception) {
            dispatchCallback(() -> listener.onCreateCertificateSigningRequestFailed(exception));
        }
        return null;
    }

    /**
     * Sign provided claims with the original device private key (asymmetric signature).
     * <p>
     * This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key
     * used for private key decryption. Claims provided as a dictionary is then converted to Base64 encoded format and
     * signed using ECDSA algorithm (ES256 or ES384) with the private key and converted to JWT representation that can be
     * validated on the server side.
     *
     * @param context Android context.
     * @param authentication Authentication object that must contain the possession factor.
     * @param claims Claims to be signed with the private key.
     * @param listener Listener with the callback methods
     * @return {@link ICancelable} object associated with the underlying HTTP request.
     * @deprecated Method is deprecated, please use {@link #calculateJwsSignature(Context, PowerAuthAuthentication, byte[], String, boolean, int, IJwsSignatureListener)} instead.
     */
    @Deprecated // 2.0.0
    @Nullable
    public ICancelable signJwtWithDevicePrivateKey(@NonNull Context context, @NonNull PowerAuthAuthentication authentication, @NonNull Map<String, Object> claims, @NonNull IJwtSignatureListener listener) {
        byte[] dataForSign = new JsonSerialization().serializeObject(claims);
        return calculateJwsSignature(context, authentication, dataForSign, "JWT", true, PowerAuthSignatureKeyId.DEVICE_EC, new IJwsSignatureListener() {
            @Override
            public void onJwsSignatureSucceed(@NonNull String signedData, boolean compactForm) {
                listener.onJwtSignatureSucceed(signedData);
            }

            @Override
            public void onJwsSignatureFailed(@NonNull Throwable throwable) {
                listener.onJwtSignatureFailed(throwable);
            }
        });
    }

    /**
     * Creates X.509 CSR (Certificate Signing Request) with given Distinguished Names and optional Subject Alternative Names, embedded device public key and signed with the device private key.
     *
     * @param context Android context.
     * @param authentication Authentication object that must contain the possession and password factor.
     * @param distinguishedNames Distinguished Names (DN) to be embedded in the CSR. The dictionary keys are DN types (like "CN", "O", etc.) and values are corresponding DN values.
     * @param subjectAltNames Optional array of Subject Alternative Names (SAN)
     * @param listener Listener with the callback methods. CSR in PEM format with lines separated by `\n` (including `-----BEGIN CERTIFICATE REQUEST`----- and `-----END CERTIFICATE REQUEST-----` lines) is returned in case of success.
     * @return {@link ICancelable} object associated with the underlying HTTP request.
     * @deprecated Use {@link #createCertificateSigningRequest(Context, PowerAuthAuthentication, Map, List, int, ICreateCertificateSigningRequestListener)} as replacement.
     */
    @Deprecated(since = "2.0.0")
    @Nullable
    public ICancelable createSignedCSR(
            @NonNull Context context,
            @NonNull PowerAuthAuthentication authentication,
            @NonNull Map<String, String> distinguishedNames,
            @Nullable String[] subjectAltNames,
            @NonNull ICreateCSRListener listener) {
        List<String> san = subjectAltNames == null ? null : Arrays.asList(subjectAltNames);
        return createCertificateSigningRequest(context, authentication, distinguishedNames, san, PowerAuthSignatureKeyId.DEVICE_EC, new ICreateCertificateSigningRequestListener() {
            @Override
            public void onCreateCertificateSigningRequestSucceed(@NonNull String certificateSigningRequest) {
                listener.onCSRCreateSucceed(certificateSigningRequest);
            }

            @Override
            public void onCreateCertificateSigningRequestFailed(@NonNull Throwable throwable) {
                listener.onCSRCreateFailed(PowerAuthErrorException.wrapException(PowerAuthErrorCodes.NETWORK_ERROR, throwable));
            }
        });
    }

    /**
     * Change the password using local re-encryption, do not validate old password by calling any endpoint.
     * <p>
     * You are responsible for validating the old password against some server endpoint yourself before using it in this method.
     * If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
     * existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
     *
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password to be set to store the data.
     * @return Returns 'true' in case password was changed without error, 'false' otherwise.
     * @deprecated Methods {@link #beginPasswordChange(Context, String, IBeginPasswordChangeListener)} and {@link #finishPasswordChange(Context, String, PowerAuthPasswordChangeData, IFinishPasswordChangeListener)} should be used instead.
     */
    @Deprecated(since = "2.0.0")
    public boolean changePasswordUnsafe(@NonNull final String oldPassword, @NonNull final String newPassword) {
        return changePasswordUnsafeImpl(new Password(oldPassword), new Password(newPassword));
    }

    /**
     * Change the password using local re-encryption, do not validate old password by calling any endpoint.
     * <p>
     * You are responsible for validating the old password against some server endpoint yourself before using it in this method.
     * If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
     * existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
     *
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password to be set to store the data.
     * @return Returns 'true' in case password was changed without error, 'false' otherwise.
     * @deprecated Methods {@link #beginPasswordChange(Context, String, IBeginPasswordChangeListener)} and {@link #finishPasswordChange(Context, String, PowerAuthPasswordChangeData, IFinishPasswordChangeListener)} should be used instead.
     */
    @Deprecated(since = "2.0.0")
    public boolean changePasswordUnsafe(@NonNull final Password oldPassword, @NonNull final Password newPassword) {
        return changePasswordUnsafeImpl(oldPassword, newPassword);
    }

    /**
     * Change the password using local re-encryption. This is private implementation of deprecated function.
     *
     * @param oldPassword Old password, currently set to store the data.
     * @param newPassword New password to be set to store the data.
     * @return Returns 'true' in case password was changed without error, 'false' otherwise.
     */
    //@Deprecated // 2.0.0
    private boolean changePasswordUnsafeImpl(@NonNull final Password oldPassword, @NonNull final Password newPassword) {
        try {
            final CoreRequest<Object> request = mSession.changePassword(oldPassword, newPassword);
            if (request != null) {
                request.cancel();
                PowerAuthLog.d("Synchronous password change is not supported at this protocol version");
                return false;
            }

            saveSerializedState();
            return true;
        } catch (CoreException e) {
            return false;
        }
    }

    /**
     * Change the password.
     *
     * @param context     Context.
     * @param oldPassword The password currently set to store the data.
     * @param newPassword New password to be set.
     * @param listener    The callback method with the password change result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @deprecated Methods {@link #beginPasswordChange(Context, String, IBeginPasswordChangeListener)} and {@link #finishPasswordChange(Context, String, PowerAuthPasswordChangeData, IFinishPasswordChangeListener)} should be used instead.
     */
    @Deprecated(since = "2.0.0")
    public @Nullable
    ICancelable changePassword(@NonNull Context context, @NonNull final String oldPassword, @NonNull final String newPassword, @NonNull final IChangePasswordListener listener) {
        return changePassword(context, new Password(oldPassword), new Password(newPassword), listener);
    }

    /**
     * Change the password.
     *
     * @param context     Context.
     * @param oldPassword The password currently set to store the data.
     * @param newPassword New password to be set.
     * @param listener    The callback method with the password change result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @deprecated Methods {@link #beginPasswordChange(Context, Password, IBeginPasswordChangeListener)} and {@link #finishPasswordChange(Context, Password, PowerAuthPasswordChangeData, IFinishPasswordChangeListener)} should be used instead.
     */
    @Deprecated(since = "2.0.0")
    public @Nullable
    ICancelable changePassword(@NonNull Context context, @NonNull final Password oldPassword, @NonNull final Password newPassword, @NonNull final IChangePasswordListener listener) {
        return finishPasswordChange(context, newPassword, new PowerAuthPasswordChangeData(oldPassword), new IFinishPasswordChangeListener() {
            @Override
            public void onFinishPasswordChangeSucceed() {
                listener.onPasswordChangeSucceed();
            }

            @Override
            public void onFinishPasswordChangeFailed(@NonNull Throwable throwable) {
                listener.onPasswordChangeFailed(throwable);
            }
        });
    }

    /**
     * Initiates the first step of a two-step password change operation by validating the user's
     * current password. The provided password is used to compute the appropriate authentication
     * header required for password verification. If the verification succeeds,
     * the `PowerAuthPasswordChangeData` object is received, which is required to complete
     * the second step.
     *
     * @param context     Context.
     * @param oldPassword The password currently set to store the data.
     * @param listener    The callback method providing either the password-change data needed
     *                    for the next step, or an error if verification fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable beginPasswordChange(@NonNull Context context, @NonNull final String oldPassword, @NonNull final IBeginPasswordChangeListener listener) {
        return beginPasswordChange(context, new Password(oldPassword), listener);
    }

    /**
     * Initiates the first step of a two-step password change operation by validating the user's
     * current password. The provided password is used to compute the appropriate authentication
     * header required for password verification. If the verification succeeds,
     * the {@link PowerAuthPasswordChangeData} object is received, which is required to complete
     * the second step.
     *
     * @param context     Context.
     * @param oldPassword The password currently set to store the data.
     * @param listener    The callback method providing either the password-change data needed
     *                    for the next step, or an error if verification fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable beginPasswordChange(@NonNull Context context, @NonNull final Password oldPassword, @NonNull final IBeginPasswordChangeListener listener) {
        try {
            final CoreRequest<Object> request = mSession.verifyPassword(oldPassword);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    listener.onBeginPasswordChangeSucceed(new PowerAuthPasswordChangeData(oldPassword));
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onBeginPasswordChangeFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onBeginPasswordChangeFailed(PowerAuthErrorException.wrapException(e)));
        }
        return null;
    }

    /**
     * Completes the second step of a two-step password change operation by submitting new password.
     * The SDK uses the {@link PowerAuthPasswordChangeData} object obtained in the first step
     * to calculate the necessary authentication header for finalizing the password change.
     *
     * @param context     Context.
     * @param newPassword The new password to be set for the user.
     * @param changeData  The password-change data obtained from the first step {@link #beginPasswordChange(Context, String, IBeginPasswordChangeListener)}.
     * @param listener    The callback method with the password change result.
     * @return            {@link ICancelable} object associated with the running HTTP request,
     *                    or {@code null}, if there's no additional asynchronous operation required.
     */
    public @Nullable
    ICancelable finishPasswordChange(@NonNull Context context, @NonNull String newPassword, @NonNull final PowerAuthPasswordChangeData changeData, @NonNull final IFinishPasswordChangeListener listener) {
        return finishPasswordChange(context, new Password(newPassword), changeData, listener);
    }

    /**
     * Completes the second step of a two-step password change operation by submitting new password.
     * The SDK uses the {@link PowerAuthPasswordChangeData} object obtained in the first step
     * to calculate the necessary authentication header for finalizing the password change.
     *
     * @param context     Context.
     * @param newPassword The new password to be set for the user.
     * @param changeData  The password-change data obtained from the first step {@link #beginPasswordChange(Context, Password, IBeginPasswordChangeListener)}.
     * @param listener    The callback method with the password change result.
     * @return            {@link ICancelable} object associated with the running HTTP request,
     *                    or {@code null}, if there's no additional asynchronous operation required.
     */
    public @Nullable
    ICancelable finishPasswordChange(@NonNull Context context, @NonNull Password newPassword, @NonNull final PowerAuthPasswordChangeData changeData, @NonNull final IFinishPasswordChangeListener listener) {
        try {
            final CoreRequest<Object> request = mSession.changePassword(changeData.getOldPassword(), newPassword);
            if (request == null) {
                // V3 change password is executed immediately. It's OK to exit immediately,
                // because there's no additional asynchronous operation required. So, we can
                // end here for both, successful and failure scenarios.
                saveSerializedState();
                dispatchCallback(listener::onFinishPasswordChangeSucceed);
                return null;
            }

            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    saveSerializedState();
                    listener.onFinishPasswordChangeSucceed();
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onFinishPasswordChangeFailed(throwable);
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onFinishPasswordChangeFailed(PowerAuthErrorException.wrapException(e)));
        }
        return null;
    }

    /**
     * Check if the current PowerAuth instance has biometry factor in place.
     *
     * @param context Android context object
     * @return True in case biometry factor is present, false otherwise.
     */
    public boolean hasBiometryFactor(@NonNull Context context) {
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
     * @param password Password used for authentication during vault unlocking call.
     * @param biometricPrompt Prompt displayed during the biometric authentication. You can provide a "dummy" prompt in case that
     *                        biometric authentication is not required for the biometric factor setup.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            @NonNull final Password password,
            @NonNull final PowerAuthBiometricPrompt biometricPrompt,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, biometricPrompt, password, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param biometricPrompt Prompt displayed during the biometric authentication. You can provide a "dummy" prompt in case that
     *                        biometric authentication is not required for the biometric factor setup.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @Nullable
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            @NonNull final String password,
            @NonNull final PowerAuthBiometricPrompt biometricPrompt,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, biometricPrompt, new Password(password), listener);
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
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     * @deprecated Use {@link #addBiometryFactor(Context, String, PowerAuthBiometricPrompt, IAddBiometryFactorListener)} as replacement.
     */
    @UiThread
    @Nullable
    @Deprecated(since = "2.0.0")
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull Fragment fragment,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull String password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, PowerAuthBiometricPrompt.prompt(fragment, title, description), new Password(password), listener);
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
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     * @deprecated Use {@link #addBiometryFactor(Context, Password, PowerAuthBiometricPrompt, IAddBiometryFactorListener)} as replacement.
     */
    @UiThread
    @Nullable
    @Deprecated(since = "2.0.0")
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull Fragment fragment,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, PowerAuthBiometricPrompt.prompt(fragment, title, description), password, listener);
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
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     * @deprecated Use {@link #addBiometryFactor(Context, String, PowerAuthBiometricPrompt, IAddBiometryFactorListener)} as replacement.
     */
    @UiThread
    @Nullable
    @Deprecated(since = "2.0.0")
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull FragmentActivity fragmentActivity,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull String password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, PowerAuthBiometricPrompt.prompt(fragmentActivity, title, description), new Password(password), listener);
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
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     * @deprecated Use {@link #addBiometryFactor(Context, Password, PowerAuthBiometricPrompt, IAddBiometryFactorListener)} as replacement.
     */
    @UiThread
    @Nullable
    @Deprecated(since = "2.0.0")
    public ICancelable addBiometryFactor(
            @NonNull final Context context,
            final @NonNull FragmentActivity fragmentActivity,
            final @NonNull String title,
            final @NonNull String description,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, PowerAuthBiometricPrompt.prompt(fragmentActivity, title, description), password, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param prompt Prompt with information required for the dialog presentation.
     * @param password Password used for authentication during vault unlocking call.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request and the biometric prompt.
     */
    @UiThread
    @Nullable
    private ICancelable addBiometryFactorImpl(
            @NonNull final Context context,
            final @NonNull PowerAuthBiometricPrompt prompt,
            @NonNull Password password,
            @NonNull final IAddBiometryFactorListener listener) {

        final CompositeCancelableTask composite = new CompositeCancelableTask(true);
        final ICancelable biometricDialogTask = authenticateUsingBiometrics(context, prompt, true, new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                if (userCancel) {
                    if (composite.setCompleted()) {
                        listener.onAddBiometryFactorFailed(new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_CANCEL));
                    }
                }
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                final ICancelable addBiometryTask = addBiometryFactorImpl(context, password, biometricKeyData.getDerivedData(), listener);
                if (addBiometryTask != null) {
                    composite.addCancelable(addBiometryTask);
                } else {
                    composite.setCompleted();
                }
            }

            @Override
            public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                listener.onAddBiometryFactorFailed(error);
            }
        });

        composite.addCancelable(biometricDialogTask);
        return composite;
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * The method is useful in situations where you're manage your own biometry related factor key, or you have obtained
     * the key in advance.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable addBiometryFactor(
            final @NonNull Context context,
            @NonNull String password,
            final @NonNull SecureData encryptedBiometryKey,
            final @NonNull IAddBiometryFactorListener listener) {
        return addBiometryFactor(context, new Password(password), encryptedBiometryKey, listener);
    }

    /**
     * Regenerate a biometry related factor key.
     * <p>
     * The method is useful in situations where you're manage your own biometry related factor key, or you have obtained
     * the key in advance.
     * <p>
     * This method calls PowerAuth REST API endpoint to obtain the vault encryption key used for original private key encryption.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public @Nullable
    ICancelable addBiometryFactor(
            final @NonNull Context context,
            @NonNull Password password,
            final @NonNull SecureData encryptedBiometryKey,
            final @NonNull IAddBiometryFactorListener listener) {
        return addBiometryFactorImpl(context, password, encryptedBiometryKey, listener);
    }

    /**
     * Private method that adds a biometric factor key when the biometric key
     * is managed by the caller or obtained in advance.
     *
     * @param context  Context.
     * @param password Password used for authentication during vault unlocking call.
     * @param encryptedBiometryKey Encrypted biometry key used for storing biometry related factor key.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    private @Nullable
    ICancelable addBiometryFactorImpl(
            final @NonNull Context context,
            @NonNull Password password,
            final @NonNull SecureData encryptedBiometryKey,
            final @NonNull IAddBiometryFactorListener listener) {
        try {
            final CoreRequest<Object> request = mSession.addBiometryFactor(password, encryptedBiometryKey);
            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    saveSerializedState();
                    listener.onAddBiometryFactorSucceed();
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onAddBiometryFactorFailed(PowerAuthErrorException.wrapException(throwable));
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onAddBiometryFactorFailed(PowerAuthErrorException.wrapException(e)));
        }
        return null;
    }

    /**
     * Remove the biometry related factor key.
     *
     * @param context Context.
     * @return TRUE if the key was successfully removed, FALSE otherwise.
     * @deprecated Please use asynchronous variant {@link #removeBiometryFactor(Context, IRemoveBiometryFactorListener)}.
     */
    @Deprecated(since = "2.0.0")
    public boolean removeBiometryFactor(@NonNull Context context) {
        try {
            final CoreRequest<Object> request = mSession.removeBiometryFactor();
            if (request != null) {
                request.cancel();
                PowerAuthLog.d("Synchronous biometry factor remove is not supported at this protocol version");
                return false;
            } else {
                removeBiometryKeyData(context);
                return true;
            }
        } catch (CoreException e) {
            return false;
        }
    }

    /**
     * Remove the biometry related factor key.
     *
     * @param context Context.
     * @param listener The callback method with the operation result.
     * @return {@link ICancelable} object associated with the running asynchronous operation.
     */
    @Nullable
    public ICancelable removeBiometryFactor(@NonNull Context context, @NonNull IRemoveBiometryFactorListener listener) {
        try {
            final CoreRequest<Object> request = mSession.removeBiometryFactor();
            if (request == null) {
                // V3 activation, remove doesn't use request
                removeBiometryKeyData(context);
                dispatchCallback(listener::onRemoveBiometryFactorSucceed);
                return null;
            }

            return mClient.post(request, new INetworkResponseListener<>() {
                @Override
                public void onNetworkResponse(@Nullable Object o) {
                    removeBiometryKeyData(context);
                    listener.onRemoveBiometryFactorSucceed();
                }

                @Override
                public void onNetworkError(@NonNull Throwable throwable) {
                    listener.onRemoveBiometryFactorFailed(PowerAuthErrorException.wrapException(throwable));
                }

                @Override
                public void onCancel() {
                }
            });
        } catch (CoreException e) {
            dispatchCallback(() -> listener.onRemoveBiometryFactorFailed(PowerAuthErrorException.wrapException(e)));
            return null;
        }
    }

    /**
     * Private method to remove the biometry related factor key.
     * @param context Android context object.
     */
    private void removeBiometryKeyData(@NonNull Context context) {
        final IBiometricKeystore keystore = BiometricAuthentication.getBiometricKeystore();
        final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(keystore, context, BiometricDataMapper.BIO_MAPPING_REMOVE_KEY);
        saveSerializedState();
        mBiometryKeychain.remove(biometricDataMapping.keychainKey);
        keystore.removeBiometricKeyEncryptor(biometricDataMapping.keystoreId);
    }

    /**
     * Validate a user password. This method calls PowerAuth REST API endpoint to validate the password on the server.
     *
     * @param context  Context.
     * @param password Password to be verified.
     * @param listener The callback method with error associated with the password validation.
     * @return {@link ICancelable} object associated with the running HTTP request.
     * @deprecated Method has no direct replacement. If your application requires password validation here,
     *             it indicates a deeper architectural issue that may introduce security vulnerabilities.
     */
    @Deprecated(since = "2.0.0")
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
     * @deprecated Method has no direct replacement. If your application requires password validation here,
     *             it indicates a deeper architectural issue that may introduce security vulnerabilities.
     */
    @Deprecated(since = "2.0.0")
    public @Nullable
    ICancelable validatePassword(@NonNull Context context, @NonNull Password password, @NonNull final IValidatePasswordListener listener) {
        return beginPasswordChange(context, password, new IBeginPasswordChangeListener() {
            @Override
            public void onBeginPasswordChangeSucceed(@NonNull PowerAuthPasswordChangeData passwordChangeData) {
                listener.onPasswordValid();
            }

            @Override
            public void onBeginPasswordChangeFailed(@NonNull Throwable throwable) {
                listener.onPasswordValidationFailed(throwable);
            }
        });
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and
     * {@link IAuthenticateWithBiometricsListener#onBiometricDialogSuccess(PowerAuthAuthentication)} callback is called.
     *
     * @param context Context.
     * @param biometricPrompt Object containing information for the biometric prompt display.
     * @param listener Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @NonNull
    public ICancelable authenticateUsingBiometrics(
            @NonNull Context context,
            @NonNull PowerAuthBiometricPrompt biometricPrompt,
            @NonNull IAuthenticateWithBiometricsListener listener) {
        return authenticateUsingBiometrics(context,biometricPrompt, false, getBiometricCallbackWithListener(listener));
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and
     * {@link IAuthenticateWithBiometricsListener#onBiometricDialogSuccess(PowerAuthAuthentication)} callback is called.
     *
     * @param context Context.
     * @param fragment The fragment of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param listener Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Use {@link #authenticateUsingBiometrics(Context, PowerAuthBiometricPrompt, IAuthenticateWithBiometricsListener)} instead.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable authenticateUsingBiometrics(
            @NonNull Context context,
            @NonNull Fragment fragment,
            @NonNull String title,
            @NonNull String description,
            final @NonNull IAuthenticateWithBiometricsListener listener) {
        return authenticateUsingBiometrics(context, PowerAuthBiometricPrompt.prompt(fragment, title, description), false, getBiometricCallbackWithListener(listener));
    }

    /**
     * Authenticate a client using biometric authentication. In case of the authentication is successful and
     * {@link IAuthenticateWithBiometricsListener#onBiometricDialogSuccess(PowerAuthAuthentication)} callback is called.
     *
     * @param context Context.
     * @param fragmentActivity The activity of the application that will host the prompt.
     * @param title Dialog title.
     * @param description Dialog description.
     * @param listener Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     * @deprecated Use {@link #authenticateUsingBiometrics(Context, PowerAuthBiometricPrompt, IAuthenticateWithBiometricsListener)} instead.
     */
    @UiThread
    @NonNull
    @Deprecated // 2.0.0
    public ICancelable authenticateUsingBiometrics(
            @NonNull Context context,
            @NonNull FragmentActivity fragmentActivity,
            @NonNull String title,
            @NonNull String description,
            final @NonNull IAuthenticateWithBiometricsListener listener) {
        return authenticateUsingBiometrics(context, PowerAuthBiometricPrompt.prompt(fragmentActivity, title, description), false, getBiometricCallbackWithListener(listener));
    }

    /**
     * Create low level biometric authentication callback that bridge the result to the provided listener.
     * @param listener Target listener.
     * @return Instance of {@link IBiometricAuthenticationCallback}.
     */
    @NonNull
    private IBiometricAuthenticationCallback getBiometricCallbackWithListener(@NonNull IAuthenticateWithBiometricsListener listener) {
        return new IBiometricAuthenticationCallback() {
            @Override
            public void onBiometricDialogCancelled(boolean userCancel) {
                listener.onBiometricDialogCancelled(userCancel);
            }

            @Override
            public void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData) {
                final PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithBiometry(biometricKeyData.getDerivedData());
                // TODO: This should be moved in the next release to some global point to make sure that we always clear this object.
                biometricKeyData.destroy();
                listener.onBiometricDialogSuccess(authentication);
            }

            @Override
            public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
                listener.onBiometricDialogFailed(error);
            }
        };
    }

    /**
     * Authenticate a client using biometric authentication.
     *
     * @param context Context.
     * @param prompt Prompt with information required for the dialog presentation.
     * @param forceGenerateNewKey Pass true to indicate that a new key should be generated in Keystore
     * @param callback Callback with the authentication result.
     * @return {@link ICancelable} object associated with the biometric prompt.
     */
    @UiThread
    @NonNull
    private ICancelable authenticateUsingBiometrics(
            final @NonNull Context context,
            final @NonNull PowerAuthBiometricPrompt prompt,
            final boolean forceGenerateNewKey,
            final @NonNull IBiometricAuthenticationCallback callback) {

        if (prompt.isDummy()) {
            // Validate whether "dummy" prompt can be used
            if (!forceGenerateNewKey) {
                throw new IllegalStateException("Dummy biometric prompt is not allowed for authentication");
            }
            if (mBiometricConfiguration.isAuthenticateOnBiometricKeySetup()) {
                throw new IllegalStateException("Dummy biometric prompt is not allowed because key setup require authentication");
            }
        }
        final BiometricDataMapper.Mapping biometricDataMapping = mBiometricDataMapper.getMapping(null, context, forceGenerateNewKey ? BiometricDataMapper.BIO_MAPPING_CREATE_KEY : BiometricDataMapper.BIO_MAPPING_NOOP);
        final SecureData rawKeyData;
        if (forceGenerateNewKey) {
            // new key has to be generated
            try {
                // Always generate a 256-bit key, even for the V3 protocol. This prepares the
                // biometry data for a future activation upgrade to V4, where 256-bit keys are the
                // default.
                //
                // If the activation is still using V3, the generated 256-bit key is later
                // reduced to the actual KEK size during the normalization step (SHA-256,
                // then truncated to 16 bytes). This ensures compatibility with both 128-bit
                // and 256-bit key sizes.
                rawKeyData = CoreSession.generateFactorKekForProtocolVersion(CoreProtocolVersion.V4);
            } catch (CoreException e) {
                // This should never happen.
                throw new IllegalStateException("Failed to generate random KEK", e);
            }
        } else {
            // old key should be used, if present
            rawKeyData = mBiometryKeychain.getSecureData(biometricDataMapping.keychainKey);
        }

        if (rawKeyData == null) {
            dispatchCallback(() -> {
                final BiometricErrorInfo info = new BiometricErrorInfo(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, true);
                final PowerAuthErrorException exception = new PowerAuthErrorException(PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE, "Biometric authentication failed due to missing biometric key.", null, info);
                callback.onBiometricDialogFailed(exception);
            });
            // Return dummy cancelable object.
            return new DummyCancelable();
        }

        // Build a new authentication request.
        final BiometricAuthenticationRequest.Builder authenticationRequestBuilder = new BiometricAuthenticationRequest.Builder(context)
                .setTitle(prompt.getTitle())
                .setDescription(prompt.getDescription())
                .setRawKeyData(rawKeyData)
                .setKeystoreAlias(biometricDataMapping.keystoreId)
                .setForceGenerateNewKey(forceGenerateNewKey, mBiometricConfiguration.isInvalidateBiometricFactorAfterChange(), mBiometricConfiguration.isAuthenticateOnBiometricKeySetup())
                .setUserConfirmationRequired(mBiometricConfiguration.isConfirmBiometricAuthentication())
                .setBackgroundTaskExecutor(mExecutorProvider.getBiometricExecutor());
        if (prompt.getSubtitle() != null) {
            authenticationRequestBuilder.setSubtitle(prompt.getSubtitle());
        }
        if (prompt.getFragment() != null) {
            authenticationRequestBuilder.setFragment(prompt.getFragment());
        } else if (prompt.getFragmentActivity() != null) {
            authenticationRequestBuilder.setFragmentActivity(prompt.getFragmentActivity());
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
                    mBiometryKeychain.putSecureData(biometricKeyData.getDataToSave(), biometricDataMapping.keychainKey);
                }
                try {
                    SecureData normalizedEncryptionKey = mSession.generateFactorKekFromData(biometricKeyData.getDerivedData());
                    callback.onBiometricDialogSuccess(new BiometricKeyData(biometricKeyData.getDataToSave(), normalizedEncryptionKey, biometricKeyData.isNewKey()));
                } catch (CoreException exception) {
                    callback.onBiometricDialogFailed(PowerAuthErrorException.wrapException(exception));
                }
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
                    final SecureData randomData;
                    try {
                        randomData = mSession.generateFactorKek();
                    } catch (CoreException exception) {
                        callback.onBiometricDialogFailed(PowerAuthErrorException.wrapException(exception));
                        return;
                    }
                    callback.onBiometricDialogSuccess(new BiometricKeyData(randomData, randomData, false));
                } else {
                    // Otherwise just report the failure.
                    callback.onBiometricDialogFailed(error);
                }
            }
        });
    }

    // Vault keys

    /**
     * Fetch secure vault key from the server.
     * @param context Context.
     * @param authentication Authentication object.
     * @param keyIdentifier {@link CoreSecureVaultKeyId} identifier.
     * @param index Derivation index for {@link CoreSecureVaultKeyId#LEGACY} key.
     * @param listener Completion listener.
     * @return Cancelable operation with the pending HTTP request.
     */
    @Nullable
    private ICancelable fetchVaultEncryptionKey(@NonNull Context context,
                                                @NonNull PowerAuthAuthentication authentication,
                                                @CoreSecureVaultKeyId int keyIdentifier,
                                                long index,
                                                INetworkResponseListener<SecureData> listener) {
        try {
            CoreCredentials credentials = resolveCredentialsWithAuthentication(authentication);
            CoreRequest<SecureData> request = mSession.fetchVaultEncryptionKey(credentials, keyIdentifier, index);
            return mClient.post(request, listener);
        } catch (PowerAuthErrorException exception) {
            dispatchCallback(() -> listener.onNetworkError(exception));
        } catch (CoreException exception) {
            dispatchCallback(() -> listener.onNetworkError(PowerAuthErrorException.wrapException(exception)));
        }
        return null;
    }

    /**
     * Generate an derived encryption key with given index. The method is effective only if
     * PowerAuthSDK is running at protocol version 3.3
     * <p>
     * Be aware that the method is subject to remove once PowerAuth Mobile SDK drops support of old
     * protocol version.
     *
     * @param context        Context.
     * @param authentication Authentication used for vault unlocking call.
     * @param index          Index of the derived key using KDF.
     * @param listener       The callback method with the derived encryption key.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    @Nullable
    public ICancelable fetchEncryptionKey(@NonNull final Context context, @NonNull PowerAuthAuthentication authentication, final long index, @NonNull final IFetchEncryptionKeyListener listener) {
        return fetchVaultEncryptionKey(context, authentication, CoreSecureVaultKeyId.LEGACY, index, new INetworkResponseListener<>() {
            @Override
            public void onNetworkResponse(@Nullable SecureData secureData) {
                SecureData legacyKey = Objects.requireNonNull(secureData);
                listener.onFetchEncryptionKeySucceed(legacyKey);
            }

            @Override
            public void onNetworkError(@NonNull Throwable throwable) {
                listener.onFetchEncryptionKeyFailed(throwable);
            }

            @Override
            public void onCancel() {
            }
        });
    }

    /**
     * Get a vault encryption key from the server. This method is effective only if PowerAuthSDK is running
     * at protocol version 4.0 and higher.
     * @param context Context.
     * @param authentication Authentication used for vault unlocking call.
     * @param keyIdentifier Key to retrieve.
     * @param listener Listener with the callback methods.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    public ICancelable fetchSecureVaultKey(@NonNull Context context,
                                           @NonNull PowerAuthAuthentication authentication,
                                           @PowerAuthSecureVaultKeyId int keyIdentifier,
                                           @NonNull IFetchSecureVaultKeyListener listener) {
        final int keyId = PowerAuthSecureVaultKey.toCoreKeyId(keyIdentifier);
        return fetchVaultEncryptionKey(context, authentication, keyId, 0, new INetworkResponseListener<>() {
            @Override
            public void onNetworkResponse(@Nullable SecureData secureData) {
                SecureData baseKey = Objects.requireNonNull(secureData);
                listener.onFetchSecureVaultKeySucceed(new PowerAuthSecureVaultKey(keyIdentifier, baseKey));
            }

            @Override
            public void onNetworkError(@NonNull Throwable throwable) {
                listener.onFetchSecureVaultKeyFailed(throwable);
            }

            @Override
            public void onCancel() {
            }
        });
    }

    // E2EE

    /**
     * Creates a new instance of End-To-End encryptor suited for application's general end-to-end encryption purposes.
     * The returned encryptor is cryptographically bound to the PowerAuth configuration, so it can be used
     * with or without a valid activation.
     *
     * @param listener Listener with the callback methods.
     * @return {@link ICancelable} operation in case that the temporary encryption key needs to be acquired from the server. If the key is already
     *         present, then returns {@code null}.
     */
    public @Nullable ICancelable getEncryptorForApplicationScope( @NonNull IGetEncryptorListener listener) {
        return createEncryptor(listener, true);
    }

    /**
     * Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes.
     * The returned encryptor is cryptographically bound to a device's activation, so it can be used only
     * when this instance has a valid activation.
     * <p>
     * Note that the created encryptor has no reference to this instance of {@link PowerAuthSDK}. This means
     * that if the instance will lose its activation in the future, then the encryptor will still be capable
     * to encrypt, or decrypt the data. This is an expected behavior, so if you plan to keep the encryptor for
     * multiple requests, then it's up to you to release its instance after you change the state of {@code PowerAuthSDK}.
     *
     * @param listener Listener with the callback methods.
     * @return {@link ICancelable} operation in case that the temporary encryption key needs to be acquired from the server. If the key is already
     *         present, then returns {@code null}.
     */
    public @Nullable ICancelable getEncryptorForActivationScope(@NonNull IGetEncryptorListener listener) {
        return createEncryptor(listener, false);
    }

    /**
     * Create application or activation scoped ECIES encryptor.
     * @param listener Listener with the callback methods.
     * @param applicationScope If {@code true} then encryptor in application scope is created.
     * @return {@link ICancelable} operation in case that the temporary encryption key needs to be acquired from the server. If the key is already
     *         present, then returns {@code null}.
     */
    private @Nullable ICancelable createEncryptor(@NonNull final IGetEncryptorListener listener, final boolean applicationScope) {
        final @CoreEncryptorScope int scope = applicationScope ? CoreEncryptorScope.APPLICATION : CoreEncryptorScope.ACTIVATION;
        return mKeystoreService.createKeyForEncryptor(scope, new ICreateKeyListener() {
            @Override
            public void onCreateKeySucceeded() {
                try {
                    final CoreEncryptor encryptor = mSession.getEncryptorFactory().createEncryptorWithScope(scope);
                    listener.onGetEncryptorSuccess(encryptor);
                } catch (CoreException exception) {
                    listener.onGetEncryptorFailed(PowerAuthErrorException.wrapException(exception));
                }
            }

            @Override
            public void onCreateKeyFailed(@NonNull Throwable throwable) {
                listener.onGetEncryptorFailed(throwable);
            }
        });
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
     * at the time. The PowerAuth authentication codes are based on a logical counter, so this technique makes that all requests are delivered
     * to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
     * them with the SDK.
     *
     * <h3>Recommended practices</h3>
     * <ul>
     *     <li>You should calculate PowerAuth authentication code from the {@link Runnable#run()} method.
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
        return mExecutorProvider.getSerialExecutor();
    }

    /**
     * Dispatch callback via {@link ICallbackDispatcher}.
     *
     * @param runnable Runnable wrapping a callback that's supposed to be dispatched.
     */
    void dispatchCallback(@NonNull Runnable runnable) {
        mCallbackDispatcher.dispatchCallback(runnable);
    }


    // External Encryption key

    /**
     * @return true if EEK (external encryption key) is set.
     */
    public boolean hasExternalEncryptionKey() {
        return mSession.hasExternalEncryptionKey();
    }

    /**
     * Remove EEK if factor keys are still protected with EEK. The method throws an exception
     * if activation is not present, or if factor keys are not protected with EEK.
     * @param eek EEK previously used for the factor keys protection.
     * @throws PowerAuthErrorException In case of failure.
     */
    public void removeExternalEncryptionKey(@NonNull SecureData eek) throws PowerAuthErrorException {
        try {
            mSession.removeExternalEncryptionKey(eek);
            saveSerializedState();
        } catch (CoreException exception) {
            throw PowerAuthErrorException.wrapException(exception);
        }
    }

    /**
     * Add external encryption key for testing purposes. The method should not be used in the
     * release build. The legacy activation must be present and the size of EEK must match the size
     * of factor keys used in V3.3 protocol version (e.g. 16 bytes).
     * @param eek EEK to apply.
     * @throws PowerAuthErrorException In case of failure,
     */
    public void addExternalEncryptionKeyForTest(@NonNull SecureData eek) throws PowerAuthErrorException {
        if (BuildConfig.DEBUG) {
            try {
                mSession.addExternalEncryptionKeyForTest(eek);
                saveSerializedState();
            } catch (CoreException exception) {
                throw PowerAuthErrorException.wrapException(exception);
            }
        } else {
            throw new PowerAuthErrorException(PowerAuthErrorCodes.INVALID_ACTIVATION_STATE, "Function is not available in release SDK build");
        }
    }

    // Server status

    /**
     * Fetch status of the server from the server.
     * @param listener The callback called when operation succeeds or fails.
     * @return {@link ICancelable} object associated with the running HTTP request.
     */
    @Nullable
    public ICancelable fetchServerStatus(@NonNull IServerStatusListener listener) {
        return mServerStatusProvider.getServerStatus(listener);
    }
}
