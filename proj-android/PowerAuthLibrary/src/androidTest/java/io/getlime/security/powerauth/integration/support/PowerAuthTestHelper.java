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
import androidx.test.platform.app.InstrumentationRegistry;

import io.getlime.security.powerauth.integration.support.client.PowerAuthClientFactory;
import io.getlime.security.powerauth.integration.support.model.Application;
import io.getlime.security.powerauth.integration.support.model.ApplicationDetail;
import io.getlime.security.powerauth.integration.support.model.ApplicationVersion;
import io.getlime.security.powerauth.networking.ssl.HttpClientSslNoValidationStrategy;
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

    private final @NonNull Context context;
    private final @NonNull PowerAuthTestConfig testConfig;
    private final @NonNull PowerAuthServerApi serverApi;
    private final @NonNull RandomGenerator randomGenerator;

    private final @NonNull PowerAuthSDK sharedSdk;
    private final @NonNull PowerAuthConfiguration sharedConfiguration;
    private final @NonNull PowerAuthKeychainConfiguration sharedKeychainConfiguration;
    private final @NonNull PowerAuthClientConfiguration sharedClientConfiguration;

    private final @NonNull ApplicationDetail sharedApplication;
    private final @NonNull ApplicationVersion sharedApplicationVersion;

    /**
     * A builder that creates {@link PowerAuthTestHelper} instances.
     */
    public static class Builder {

        private final @NonNull Context context;
        private final @NonNull PowerAuthTestConfig testConfig;
        private final @NonNull PowerAuthServerApi serverApi;

        private PowerAuthSDK sharedSdk;
        private PowerAuthConfiguration sharedConfiguration;
        private PowerAuthKeychainConfiguration sharedKeychainConfiguration;
        private PowerAuthClientConfiguration sharedClientConfiguration;

        private ApplicationDetail sharedApplication;
        private ApplicationVersion sharedApplicationVersion;

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
         * Assign custom {@link PowerAuthConfiguration} for the future helper.
         * @param configuration Custom configuration.
         * @return Instance of this builder.
         */
        public @NonNull Builder sharedConfiguration(@NonNull PowerAuthConfiguration configuration) {
            this.sharedConfiguration = configuration;
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
         * Build {@link PowerAuthTestHelper} instance. Note that the method does a synchronous communication with
         * PowerAuth Server REST API.
         * @return Prepared instance of {@link PowerAuthTestHelper}
         * @throws Exception In case that cannot create the helper object.
         */
        public @NonNull PowerAuthTestHelper build() throws Exception {
            // Prepare logger
            PowerAuthLog.setEnabled(true);
            PowerAuthLog.setVerbose(true);
            // Prepare PowerAuthSDK configurations.
            final PowerAuthConfiguration configuration = prepareConfiguration();
            final PowerAuthClientConfiguration clientConfiguration = prepareClientConfiguration();
            final PowerAuthKeychainConfiguration keychainConfiguration = prepareKeychainConfiguration();
            // Prepare PowerAuthSDK instance.
            final PowerAuthSDK sdk = new PowerAuthSDK.Builder(configuration)
                    .clientConfiguration(clientConfiguration)
                    .keychainConfiguration(prepareKeychainConfiguration())
                    .build(context);
            if (sdk.hasValidActivation()) {
                Logger.e("Shared PowerAuthSDK has a valid activation at test initialization.");
            }
            sdk.removeActivationLocal(context, true);
            return new PowerAuthTestHelper(
                    context,
                    testConfig,
                    serverApi,
                    sdk,
                    configuration,
                    keychainConfiguration,
                    clientConfiguration,
                    sharedApplication,
                    sharedApplicationVersion);
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
                return new PowerAuthKeychainConfiguration.Builder().build();
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
            Application application = null;
            for (Application a : serverApi.getApplicationList()) {
                if (a.getApplicationName().equals(testConfig.getPowerAuthAppName())) {
                    application = a;
                    break;
                }
            }
            if (application == null) {
                // If server has no such application, then create a new one.
                application = serverApi.createApplication(testConfig.getPowerAuthAppName());
            }
            // Acquire application detail to get the list of application versions.
            sharedApplication = serverApi.getApplicationDetailById(application.getApplicationId());
            for (ApplicationVersion v : sharedApplication.getVersions()) {
                if (v.getApplicationVersionName().equals(testConfig.getPowerAuthAppVersion())) {
                    sharedApplicationVersion = v;
                    break;
                }
            }
            if (sharedApplicationVersion == null) {
                // If application version is not available, then create a new one.
                sharedApplicationVersion = serverApi.createApplicationVersion(sharedApplication.getApplicationId(), testConfig.getPowerAuthAppVersion());
            }
            if (!sharedApplicationVersion.isSupported()) {
                // Make sure that application is supported.
                serverApi.setApplicationVersionSupported(sharedApplicationVersion.getApplicationVersionId(), true);
            }
            // Finally, create a new instance of PowerAuthConfiguration.
            return new PowerAuthConfiguration.Builder(
                    null,
                    testConfig.getRestApiUrl(),
                    sharedApplicationVersion.getApplicationKey(),
                    sharedApplicationVersion.getApplicationSecret(),
                    sharedApplication.getMasterPublicKey())
                    .build();
        }

    }

    private PowerAuthTestHelper(
            @NonNull Context context,
            @NonNull PowerAuthTestConfig testConfig,
            @NonNull PowerAuthServerApi serverApi,
            @NonNull PowerAuthSDK sharedSdk,
            @NonNull PowerAuthConfiguration sharedConfiguration,
            @NonNull PowerAuthKeychainConfiguration sharedKeychainConfiguration,
            @NonNull PowerAuthClientConfiguration sharedClientConfiguration,
            @NonNull ApplicationDetail sharedApplication,
            @NonNull ApplicationVersion sharedApplicationVersion) {
        this.context = context;
        this.testConfig = testConfig;
        this.serverApi = serverApi;
        this.sharedSdk = sharedSdk;
        this.sharedConfiguration = sharedConfiguration;
        this.sharedKeychainConfiguration = sharedKeychainConfiguration;
        this.sharedClientConfiguration = sharedClientConfiguration;
        this.sharedApplication = sharedApplication;
        this.sharedApplicationVersion = sharedApplicationVersion;
        this.randomGenerator = new RandomGenerator();
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
            sdk.removeActivationLocal(getContext(), true);
        }
        return sdk;
    }

    /**
     * @return Expected protocol version for HTTP headers.
     */
    public @NonNull String getProtocolVersionForHeader() {
        return testConfig.getServerVersion().maxProtocolVersion.versionForHeader;
    }
}
