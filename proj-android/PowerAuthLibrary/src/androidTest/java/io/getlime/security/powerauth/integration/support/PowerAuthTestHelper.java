/*
 * Copyright 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.integration.support;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.test.platform.app.InstrumentationRegistry;

import io.getlime.security.powerauth.integration.support.client.PowerAuthClientFactory;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;
import io.getlime.security.powerauth.integration.support.model.ApplicationVersion;
import io.getlime.security.powerauth.networking.ssl.HttpClientSslNoValidationStrategy;
import io.getlime.security.powerauth.sdk.PowerAuthAlgorithm;
import io.getlime.security.powerauth.sdk.PowerAuthAuthenticationHelper;
import io.getlime.security.powerauth.sdk.PowerAuthBiometricConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthClientConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthKeychainConfiguration;
import io.getlime.security.powerauth.sdk.PowerAuthSDK;
import io.getlime.security.powerauth.system.PowerAuthLog;
import io.getlime.security.powerauth.system.PowerAuthSystem;

/**
 * The {@code PowerAuthTestHelper} class helps with Android Integration tests. The class provides
 * various functionality required for PowerAuth SDK testing.
 */
public class PowerAuthTestHelper {

    public static final String PA_VERSION3_HEADER = "3.3";
    public static final String PA_VERSION4_HEADER = "4.0";

    private final @NonNull Context context;
    private final @NonNull PowerAuthTestConfig testConfig;
    private final @NonNull PowerAuthServerApi serverApi;
    private final @NonNull RandomGenerator randomGenerator;
    private final @Nullable FragmentActivity testFragmentActivity;
    private final @Nullable Fragment testFragment;

    private @NonNull PowerAuthSDK sharedSdk;
    private @NonNull PowerAuthConfiguration sharedConfiguration;
    private @NonNull PowerAuthBiometricConfiguration sharedBiometricConfiguration;
    private @NonNull PowerAuthKeychainConfiguration sharedKeychainConfiguration;
    private @NonNull PowerAuthClientConfiguration sharedClientConfiguration;

    private final @NonNull ApplicationDetail sharedApplication;
    private final @NonNull ApplicationVersion sharedApplicationVersion;

    /**
     * Interface allows adjust PowerAuthSDK configurations before the SDK instance is created.
     */
    public interface IConfigurationObserver {
        /**
         * Adjust future PowerAuthConfiguration.
         * @param builder Builder that can alter future PowerAuthConfiguration.
         */
        void adjustPowerAuthConfiguration(@NonNull PowerAuthConfiguration.Builder builder);

        /**
         * Adjust future PowerAuthBiometricConfiguration.
         * @param builder Builder that can alter future PowerAuthBiometricConfiguration.
         */
        void adjustPowerAuthBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration.Builder builder);

        /**
         * Adjust future PowerAuthClientConfiguration.
         * @param builder Builder that can alter future PowerAuthClientConfiguration.
         */
        void adjustPowerAuthClientConfiguration(@NonNull PowerAuthClientConfiguration.Builder builder);
        /**
         * Adjust future PowerAuthKeychainConfiguration.
         * @param builder Builder that can alter future PowerAuthKeychainConfiguration.
         */
        void adjustPowerAuthKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration.Builder builder);
    }

    /**
     * A builder that creates {@link PowerAuthTestHelper} instances.
     */
    public static class Builder {

        private final @NonNull Context context;
        private final @NonNull PowerAuthTestConfig testConfig;
        private final @NonNull PowerAuthServerApi serverApi;

        private PowerAuthSDK sharedSdk;
        private IConfigurationObserver configurationObserver;
        private PowerAuthConfiguration sharedConfiguration;
        private PowerAuthKeychainConfiguration sharedKeychainConfiguration;
        private PowerAuthBiometricConfiguration sharedBiometricConfiguration;
        private PowerAuthClientConfiguration sharedClientConfiguration;

        private FragmentActivity testFragmentActivity;
        private Fragment testFragment;

        private ApplicationDetail sharedApplication;
        private ApplicationVersion sharedApplicationVersion;

        private boolean authenticationUsageStrictMode = true;

        private @PowerAuthAlgorithm int powerAuthAlgorithm = PowerAuthAlgorithm.DEFAULT;

        /**
         * Creates a new default builder. Note that the method does a synchronous communication
         * with PowerAuth Server REST API.
         * @throws Exception In case that PowerAuth Server REST API is not accessible or config is invalid.
         */
        public Builder() throws Exception {
            this.context = InstrumentationRegistry.getInstrumentation().getContext();
            this.testConfig = PowerAuthTestConfig.loadDefaultConfig();
            this.serverApi = new PowerAuthClientFactory().createApiClient(testConfig);
        }

        /**
         * Creates a new builder with provided custom parameters. Note that method does a synchronous
         * communication with PowerAuth Server REST API.
         * @param context Android Context
         * @param testConfig Custom test configuration.
         * @throws Exception In case that PowerAuth Server REST API is not accessible or config is invalid.
         */
        public Builder(@NonNull Context context, @NonNull PowerAuthTestConfig testConfig) throws Exception {
            this.context = context;
            this.testConfig = testConfig;
            this.serverApi = new PowerAuthClientFactory().createApiClient(testConfig);
        }

        /**
         * Set configuration observer that can alter configurations for PowerAuthSDK created in this helper.
         * @param observer Observer to set.
         * @return Instance of this builder.
         */
        public @NonNull Builder configurationObserver(@NonNull IConfigurationObserver observer) {
            this.configurationObserver = observer;
            return this;
        }


        /**
         * Assign custom {@link PowerAuthAlgorithm} for the future helper.
         * @param algorithm Custom algorithm.
         * @return Instance of this builder.
         */
        public @NonNull Builder powerAuthAlgorithm(@PowerAuthAlgorithm int algorithm) {
            this.powerAuthAlgorithm = algorithm;
            return this;
        }

        /**
         * Assign custom {@link PowerAuthConfiguration} for the future helper. This method also affects
         * {@link PowerAuthAlgorithm }applied to future SDK helper. The algorithm is get from the
         * provided configuration.
         *
         * @param configuration Custom configuration.
         * @return Instance of this builder.
         */
        public @NonNull Builder sharedConfiguration(@NonNull PowerAuthConfiguration configuration) {
            this.sharedConfiguration = configuration;
            this.powerAuthAlgorithm = configuration.getAlgorithm();
            return this;
        }

        /**
         * Assign custom {@link PowerAuthBiometricConfiguration} for the future helper.
         * @param biometricConfiguration Custom configuration.
         * @return Instance of this builder.
         */
        public @NonNull Builder sharedBiometricConfiguration(@NonNull PowerAuthBiometricConfiguration biometricConfiguration) {
            this.sharedBiometricConfiguration = biometricConfiguration;
            return this;
        }

        /**
         * Assign custom {@link PowerAuthKeychainConfiguration} for the future helper.
         * @param keychainConfiguration Custom configuration.
         * @return Instance of this builder.
         */
        public @NonNull Builder sharedKeychainConfiguration(@NonNull PowerAuthKeychainConfiguration keychainConfiguration) {
            this.sharedKeychainConfiguration = keychainConfiguration;
            return this;
        }

        /**
         * Assign custom {@link PowerAuthClientConfiguration} for the future helper.
         * @param clientConfiguration Custom configuration.
         * @return Instance of this builder.
         */
        public @NonNull Builder sharedClientConfiguration(@NonNull PowerAuthClientConfiguration clientConfiguration) {
            this.sharedClientConfiguration = clientConfiguration;
            return this;
        }

        /**
         * Enable or disable strict mode for PowerAuthAuthentication usage. The default value is that
         * strict mode is enabled. See {@link io.getlime.security.powerauth.sdk.PowerAuthAuthenticationHelper#setStrictModeForUsageValidation(boolean)}.
         * @param strictMode Enable or disable strict mode.
         * @return Instance of this builder.
         */
        public @NonNull Builder powerAuthAuthenticationUsageValidationMode(boolean strictMode) {
            this.authenticationUsageStrictMode = strictMode;
            return this;
        }

        public @NonNull Builder testFragmentActivity(@NonNull FragmentActivity activity) {
            this.testFragmentActivity = activity;
            return this;
        }

        public @NonNull Builder testFragment(@NonNull Fragment fragment) {
            this.testFragment = fragment;
            return this;
        }

        /**
         * Build {@link PowerAuthTestHelper} instance. Note that the method does a synchronous communication with
         * PowerAuth Server REST API.
         * @return Prepared instance of {@link PowerAuthTestHelper}
         * @throws Exception In case that cannot create the helper object.
         */
        public @NonNull PowerAuthTestHelper build() throws Exception {
            return build(false);
        }

        /**
         * Build {@link PowerAuthTestHelper} instance. Note that the method does a synchronous communication with
         * PowerAuth Server REST API.
         * @param isActive If true, then it's expected that PowerAuthSDK contains a valid activation.
         * @return Prepared instance of {@link PowerAuthTestHelper}
         * @throws Exception In case that cannot create the helper object.
         */
        public @NonNull PowerAuthTestHelper build(boolean isActive) throws Exception {
            // Prepare logger
            PowerAuthLog.setEnabled(true);
            PowerAuthLog.setVerbose(true);
            // Prepare authentication validation mode
            PowerAuthAuthenticationHelper.setStrictModeForUsageValidation(authenticationUsageStrictMode);
            // Prepare PowerAuthSDK configurations.
            final PowerAuthConfiguration configuration = prepareConfiguration();
            final PowerAuthBiometricConfiguration biometricConfiguration = prepareBiometricConfiguration();
            final PowerAuthClientConfiguration clientConfiguration = prepareClientConfiguration();
            final PowerAuthKeychainConfiguration keychainConfiguration = prepareKeychainConfiguration();
            // Prepare PowerAuthSDK instance.
            final PowerAuthSDK sdk = new PowerAuthSDK.Builder(configuration)
                    .biometricConfiguration(biometricConfiguration)
                    .clientConfiguration(clientConfiguration)
                    .keychainConfiguration(prepareKeychainConfiguration())
                    .build(context);
            if (!isActive) {
                if (sdk.hasValidActivation()) {
                    Logger.e("Shared PowerAuthSDK has a valid activation at test initialization.");
                }
                sdk.removeActivationLocal(context);
            } else {
                if (!sdk.hasValidActivation()) {
                    Logger.e("Shared PowerAuthSDK doesn't have a valid activation at test initialization.");
                }
            }
            // Apply client API to server API
            serverApi.setClientAlgorithm(sdk.getCurrentAlgorithm());
            // Build helper
            return new PowerAuthTestHelper(
                    context,
                    testConfig,
                    serverApi,
                    sdk,
                    configuration,
                    biometricConfiguration,
                    keychainConfiguration,
                    clientConfiguration,
                    sharedApplication,
                    sharedApplicationVersion,
                    testFragmentActivity,
                    testFragment);
        }

        /**
         * Prepare {@link PowerAuthConfiguration} for build method.
         * @return Instance of valid configuration.
         * @throws Exception In case that PowerAuth Server REST API is not accessible or cannot acquire required data.
         */
        private @NonNull PowerAuthConfiguration prepareConfiguration() throws Exception {
            if (sharedConfiguration == null) {
                return acquireDefaultConfiguration();
            }
            return sharedConfiguration;
        }

        /**
         * Prepare {@link PowerAuthBiometricConfiguration} for build method.
         * @return Instance of valid configuration.
         */
        private @NonNull PowerAuthBiometricConfiguration prepareBiometricConfiguration() {
            if (sharedBiometricConfiguration == null) {
                PowerAuthBiometricConfiguration.Builder builder = new PowerAuthBiometricConfiguration.Builder();
                if (configurationObserver != null) {
                    configurationObserver.adjustPowerAuthBiometricConfiguration(builder);
                }
                return builder.build();
            }
            return sharedBiometricConfiguration;
        }

        /**
         * Prepare {@link PowerAuthClientConfiguration} for build method.
         * @return Instance of valid configuration.
         */
        private @NonNull PowerAuthClientConfiguration prepareClientConfiguration() {
            if (sharedClientConfiguration == null) {
                PowerAuthClientConfiguration.Builder builder = new PowerAuthClientConfiguration.Builder();
                if (testConfig.getRestApiUrl().startsWith("http://")) {
                    builder.allowUnsecuredConnection(true);
                } else if (testConfig.getRestApiUrl().startsWith("https://")) {
                    builder.clientValidationStrategy(new HttpClientSslNoValidationStrategy());
                }
                if (configurationObserver != null) {
                    configurationObserver.adjustPowerAuthClientConfiguration(builder);
                }
                return builder.build();
            }
            return sharedClientConfiguration;
        }

        /**
         * Prepare {@link PowerAuthKeychainConfiguration} for build method.
         * @return Instance of valid configuration.
         */
        private @NonNull PowerAuthKeychainConfiguration prepareKeychainConfiguration() {
            if (sharedKeychainConfiguration == null) {
                PowerAuthKeychainConfiguration.Builder builder = new PowerAuthKeychainConfiguration.Builder();
                if (configurationObserver != null) {
                    configurationObserver.adjustPowerAuthKeychainConfiguration(builder);
                }
                return builder.build();
            }
            return sharedKeychainConfiguration;
        }

        /**
         * Creates a new instance of {@link PowerAuthConfiguration} with secrets and keys prepared for a real PowerAuth application,
         * configured on the target PowerAuth Server. Note that the method does a communication with PowerAuth Server RESTFul API,
         * to acquire all required paramters.
         *
         * @return Instance of {@link PowerAuthConfiguration} configured for a valid PowerAuth application and version.
         * @throws Exception In case of failure.
         */
        private @NonNull PowerAuthConfiguration acquireDefaultConfiguration() throws Exception {
            // Acquire application.
            Application application = serverApi.findApplicationByName(testConfig.getPowerAuthAppName());
            if (application == null) {
                // If server has no such application, then create a new one.
                application = serverApi.createApplication(testConfig.getPowerAuthAppName());
            }
            // Acquire application detail to get the list of application versions.
            sharedApplication = serverApi.getApplicationDetailById(application.getApplicationId());
            sharedApplicationVersion = serverApi.findApplicationVersionByName(sharedApplication, testConfig.getPowerAuthAppVersion());

            if (sharedApplicationVersion == null) {
                // If application version is not available, then create a new one.
                sharedApplicationVersion = serverApi.createApplicationVersion(sharedApplication.getApplicationId(), testConfig.getPowerAuthAppVersion());
            }
            if (!sharedApplicationVersion.isSupported()) {
                // Make sure that application is supported.
                serverApi.setApplicationVersionSupported(sharedApplicationVersion.getApplicationVersionId(), true);
            }
            // Finally, create a new instance of PowerAuthConfiguration.
            PowerAuthConfiguration.Builder builder = new PowerAuthConfiguration.Builder(
                    null,
                    testConfig.getRestApiUrl(),
                    sharedApplicationVersion.getMobileSdkConfig());
            builder.algorithm(powerAuthAlgorithm);
            if (configurationObserver != null) {
                configurationObserver.adjustPowerAuthConfiguration(builder);
            }
            return builder.build();
        }
    }

    private PowerAuthTestHelper(
            @NonNull Context context,
            @NonNull PowerAuthTestConfig testConfig,
            @NonNull PowerAuthServerApi serverApi,
            @NonNull PowerAuthSDK sharedSdk,
            @NonNull PowerAuthConfiguration sharedConfiguration,
            @NonNull PowerAuthBiometricConfiguration biometricConfiguration,
            @NonNull PowerAuthKeychainConfiguration sharedKeychainConfiguration,
            @NonNull PowerAuthClientConfiguration sharedClientConfiguration,
            @NonNull ApplicationDetail sharedApplication,
            @NonNull ApplicationVersion sharedApplicationVersion,
            @Nullable FragmentActivity fragmentActivity,
            @Nullable Fragment fragment) {
        this.context = context;
        this.testConfig = testConfig;
        this.serverApi = serverApi;
        this.sharedSdk = sharedSdk;
        this.sharedConfiguration = sharedConfiguration;
        this.sharedBiometricConfiguration = biometricConfiguration;
        this.sharedKeychainConfiguration = sharedKeychainConfiguration;
        this.sharedClientConfiguration = sharedClientConfiguration;
        this.sharedApplication = sharedApplication;
        this.sharedApplicationVersion = sharedApplicationVersion;
        this.randomGenerator = new RandomGenerator();
        this.testFragment = fragment;
        this.testFragmentActivity = fragmentActivity;
    }

    /**
     * @return Android Context object.
     */
    public @NonNull Context getContext() {
        return context;
    }

    /**
     * @return Test configuration associated to this helper.
     */
    public @NonNull PowerAuthTestConfig getTestConfig() {
        return testConfig;
    }

    /**
     * Get shared instance of {@link PowerAuthServerApi} that allows direct communication
     * with the PowerAuth Server.
     * @return Shared instance that implements {@link PowerAuthServerApi}.
     */
    public @NonNull PowerAuthServerApi getServerApi() {
        return serverApi;
    }

    /**
     * Renturn helper class that generates random data.
     * @return {@link RandomGenerator} instance;
     */
    public @NonNull RandomGenerator getRandomGenerator() {
        return randomGenerator;
    }

    /**
     * @return {@link ApplicationDetail} with test application prepared on PowerAuth Server.
     */
    public @NonNull ApplicationDetail getSharedApplicationDetail() {
        return sharedApplication;
    }

    /**
     * @return {@link Application} with test application prepared on PowerAuth Server.
     */
    public @NonNull Application getSharedApplication() {
        return new Application(sharedApplication);
    }

    /**
     * @return {@link ApplicationVersion} with test application version prepared on PowerAuth Server.
     */
    public @NonNull ApplicationVersion getSharedApplicationVersion() {
        return sharedApplicationVersion;
    }

    /**
     * @return Shared user identifier, loaded from configuration.
     */
    public @NonNull String getUserId() {
        return testConfig.getUserIdentifier();
    }

    /**
     * Return a shared instance of {@link PowerAuthSDK}. This instance has been created with
     * all shared configurations for SDK, keychain and for HTTP client.
     *
     * @return Shared instance of {@link PowerAuthSDK}.
     */
    public @NonNull PowerAuthSDK getSharedSdk() {
        return sharedSdk;
    }

    /**
     * @return Testing device name.
     */
    public @NonNull String getDeviceInfo() {
        return "Testing on " + PowerAuthSystem.getDeviceInfo();
    }

    /**
     * @return Shared instance of {@link PowerAuthConfiguration} that was used for shared {@link PowerAuthSDK}
     *         instance creation.
     */
    public @NonNull PowerAuthConfiguration getSharedPowerAuthConfiguration() {
        return sharedConfiguration;
    }

    /**
     * @return Shared instance of {@link PowerAuthBiometricConfiguration} that was used for shared {@link PowerAuthSDK}
     *         instance creation.
     */
    public @NonNull PowerAuthBiometricConfiguration getSharedBiometricConfiguration() {
        return sharedBiometricConfiguration;
    }

    /**
     * @return Shared instance of {@link PowerAuthClientConfiguration} that was used for shared {@link PowerAuthSDK}
     *         instance creation.
     */
    public @NonNull PowerAuthClientConfiguration getSharedPowerAuthClientConfiguration() {
        return sharedClientConfiguration;
    }

    /**
     * @return Shared instance of {@link PowerAuthKeychainConfiguration} that was used for shared {@link PowerAuthSDK}
     *         instance creation.
     */
    public @NonNull PowerAuthKeychainConfiguration getSharedPowerAuthKeychainConfiguration() {
        return sharedKeychainConfiguration;
    }

    /**
     * @return Fragment activity for tests. If not set, then throws {@link IllegalStateException}.
     */
    public @NonNull FragmentActivity getFragmentActivity() {
        if (testFragmentActivity == null) {
            throw new IllegalStateException("Fragment activity is not set");
        }
        return testFragmentActivity;
    }

    /**
     * @return Fragment for tests. If not set, then throws {@link IllegalStateException}.
     */
    public @NonNull Fragment getFragment() {
        if (testFragment == null) {
            throw new IllegalStateException("Fragment is not set");
        }
        return testFragment;
    }

    /**
     * Creates a new instance of {@link PowerAuthSDK} with a custom instance identifier.
     *
     * @param instanceName Name of instance for newly created SDK.
     * @param resetActivation Reset activation after it's creation.
     * @return New instance of {@link PowerAuthSDK}.
     * @throws Exception In case that instance creation failed.
     */
    public @NonNull PowerAuthSDK createSdk(@NonNull String instanceName, boolean resetActivation) throws Exception {
        final PowerAuthSDK sdk = new PowerAuthSDK.Builder(getSharedPowerAuthConfiguration())
                .clientConfiguration(getSharedPowerAuthClientConfiguration())
                .keychainConfiguration(getSharedPowerAuthKeychainConfiguration())
                .build(getContext());
        if (resetActivation && sdk.hasValidActivation()) {
            sdk.removeActivationLocal(getContext());
        }
        return sdk;
    }

    /**
     * Re-create a new instance of shared {@link PowerAuthSDK} with provided configurations.
     * @param configuration If null, then shared configuration will be used.
     * @param biometricConfiguration  If null, then shared biometric configuration will be used.
     * @param clientConfiguration If null, then shared client configuration will be used.
     * @param keychainConfiguration If null, then shared keychain configuration will be used.
     * @return New instance of {@link PowerAuthSDK} that will be also used as new shared instance.
     * @throws Exception In case that instance creation failed.
     */
    public @NonNull PowerAuthSDK reCreateSdk(
            @Nullable PowerAuthConfiguration configuration,
            @Nullable PowerAuthBiometricConfiguration biometricConfiguration,
            @Nullable PowerAuthClientConfiguration clientConfiguration,
            @Nullable PowerAuthKeychainConfiguration keychainConfiguration) throws Exception {
        final PowerAuthConfiguration newConfiguration = configuration != null ? configuration : getSharedPowerAuthConfiguration();
        final PowerAuthBiometricConfiguration newBiometricConfiguration = biometricConfiguration != null ? biometricConfiguration : getSharedBiometricConfiguration();
        final PowerAuthClientConfiguration newClientConfiguration = clientConfiguration != null ? clientConfiguration : getSharedPowerAuthClientConfiguration();
        final PowerAuthKeychainConfiguration newKeychainConfiguration = keychainConfiguration != null ? keychainConfiguration : getSharedPowerAuthKeychainConfiguration();
        final PowerAuthSDK sdk = new PowerAuthSDK.Builder(newConfiguration)
                .clientConfiguration(newClientConfiguration)
                .biometricConfiguration(newBiometricConfiguration)
                .keychainConfiguration(newKeychainConfiguration)
                .build(getContext());
        sharedSdk = sdk;
        sharedConfiguration = newConfiguration;
        sharedBiometricConfiguration = newBiometricConfiguration;
        sharedClientConfiguration = newClientConfiguration;
        sharedKeychainConfiguration = newKeychainConfiguration;
        return sdk;
    }

    /**
     * @return Expected protocol version for HTTP headers.
     */
    public @NonNull String getProtocolVersionForHeader() {
        if (sharedSdk.getCurrentAlgorithm() == PowerAuthAlgorithm.LEGACY_P256) {
            return PA_VERSION3_HEADER;
        }
        return PA_VERSION4_HEADER;
    }

    /**
     * Convert PowerAuth Algorithm name into numeric constant.
     * @param algorithmName Algorithm name.
     * @return {@link PowerAuthAlgorithm} constant.
     */
    @PowerAuthAlgorithm
    public static int getAlgorithmForName(String algorithmName) {
        switch (algorithmName) {
            case "EC_P384": return PowerAuthAlgorithm.EC_P384;
            case "EC_P384_ML_L3": return PowerAuthAlgorithm.EC_P384_ML_L3;
            case "EC_P384_ML_L5": return PowerAuthAlgorithm.EC_P384_ML_L5;
            case "LEGACY_P256": return PowerAuthAlgorithm.LEGACY_P256;
            default: throw new IllegalArgumentException("Unsupported algorithm name " + algorithmName);
        }
    }
}
