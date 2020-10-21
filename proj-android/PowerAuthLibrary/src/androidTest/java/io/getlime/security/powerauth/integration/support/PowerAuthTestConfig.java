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

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.test.InstrumentationRegistry;

import io.getlime.security.powerauth.integration.support.model.ServerVersion;

/**
 * The {@code PowerAuthTestConfig} contains configuration required for integration tests. You can use
 * the following instrumentation parameters to affect instance of this configuration class:
 * <ul>
 *     <li>
 *         {@code "test.powerauth.restApiUrl"} - <b>required</b> URL to public server that implements PowerAuth RESTful API.
 *     </li>
 *     <li>
 *         {@code "test.powerauth.serverApiUrl"} - <b>required</b> URL to private PowerAuth Server RESTful API.
 *     </li>
 *     <li>
 *         {@code "test.powerauth.serverVersion"} - Expected PowerAuth Server version.
 *     </li>
 *     <li>
 *         {@code "test.powerauth.appName"} - Name of PowerAuth Application that should be used for testing.
 *     </li>
 *     <li>
 *         {@code "test.powerauth.appVersion"} - Name of PowerAuth Application Version that should be used for testing.
 *     </li>
 *     <li>
 *         {@code "test.powerauth.userIdentifier"} - User identifier that should be used for testing.
 *         This is optional value, but you should set your custom user identifier in case that you expect
 *         that another developer will run tests on the same server.
 *     </li>
 * </ul>
 *
 * You can also check <b>{@code "${GIT_REPO}/proj-android/configs/powerauth-instrumentation-tests.properties"}</b> file that contains
 * default set of parameters.
 */
public class PowerAuthTestConfig {

    private final @NonNull String restApiUrl;
    private final @NonNull String serverApiUrl;
    private final @NonNull ServerVersion serverVersion;
    private final @NonNull String powerAuthAppName;
    private final @NonNull String powerAuthAppVersion;
    private final @NonNull String userIdentifier;

    private PowerAuthTestConfig(
            @NonNull String restApiUrl,
            @NonNull String serverApiUrl,
            @NonNull ServerVersion serverVersion,
            @NonNull String powerAuthAppName,
            @NonNull String powerAuthAppVersion,
            @NonNull String userIdentifier) {
        this.restApiUrl = restApiUrl;
        this.serverApiUrl = serverApiUrl;
        this.serverVersion = serverVersion;
        this.powerAuthAppName = powerAuthAppName;
        this.powerAuthAppVersion = powerAuthAppVersion;
        this.userIdentifier = userIdentifier;
    }

    /**
     * @return URL to public server that implements PowerAuth RESTful API.
     */
    public @NonNull String getRestApiUrl() {
        return restApiUrl;
    }

    /**
     * @return URL to private server that implements PowerAuth Server RESTful API.
     */
    public @NonNull String getServerApiUrl() {
        return serverApiUrl;
    }

    /**
     * @return Expected server version.
     */
    public @NonNull ServerVersion getServerVersion() {
        return serverVersion;
    }

    /**
     * @return Name of PowerAuth Application that should be used for testing.
     */
    public @NonNull String getPowerAuthAppName() {
        return powerAuthAppName;
    }

    /**
     * @return Name of PowerAuth Application Version that should be used for testing.
     */
    public @NonNull String getPowerAuthAppVersion() {
        return powerAuthAppVersion;
    }

    /**
     * @return Test user identifier.
     */
    public @NonNull String getUserIdentifier() {
        return userIdentifier;
    }

    /**
     * Load testing parameters from instrumentation registry.
     *
     * @return Instance of {@link PowerAuthTestConfig}
     * @throws Exception In case that required parameters are not set or are invalid.
     */
    public static @NonNull PowerAuthTestConfig loadDefaultConfig() throws Exception {
        final String restApiUrl = getInstrumentationParameter("restApiUrl");
        final String serverApiUrl = getInstrumentationParameter("serverApiUrl");
        final String serverVersionString = getInstrumentationParameter("serverVersion", ServerVersion.LATEST.version);
        final ServerVersion serverVersion = ServerVersion.versionFromString(serverVersionString, true);
        final String powerAuthAppName = getInstrumentationParameter("appName", "AutomaticTest-Android");
        final String powerAuthAppVersion = getInstrumentationParameter("appVersion", "default");
        final String userIdentifier = getInstrumentationParameter("userIdentifier", "TestUserAndroid");
        return new PowerAuthTestConfig(restApiUrl, serverApiUrl, serverVersion, powerAuthAppName, powerAuthAppVersion, userIdentifier);
    }

    /**
     * Get optional instrumentation parameter.
     *
     * @param paramName Parameter name. The final instrumentation parameter will be constructed as {@code "test.powerauth." + paramName}.
     * @return Value of optional instrumentation parameter.
     * @throws Exception In case that parameter name is empty.
     */
    public static @Nullable String getInstrumentationOptionalParameter(@NonNull String paramName) throws Exception {
        final Bundle arguments = InstrumentationRegistry.getArguments();
        return arguments.getString(getFullParam(paramName));
    }

    /**
     * Get required instrumentation parameter.
     *
     * @param paramName Parameter name. The final instrumentation parameter will be constructed as {@code "test.powerauth." + paramName}.
     * @return Value of required instrumentation parameter.
     * @throws Exception In case that value is not set or parameter name is empty.
     */
    public static @NonNull String getInstrumentationParameter(@NonNull String paramName) throws Exception {
        final Bundle arguments = InstrumentationRegistry.getArguments();
        final String fullParamName = getFullParam(paramName);
        final String value = arguments.getString(fullParamName);
        if (value == null) {
            throw new Exception("Missing '" + fullParamName + "' required for instrumentation testing");
        }
        return value;
    }

    /**
     * Get instrumentation parameter. If parameter is not set, then return default value.
     * @param paramName Parameter name. The final instrumentation parameter will be constructed as {@code "test.powerauth." + paramName}.
     * @param defaultValue Default value that is returned in case that instrumentation parameter is not set.
     * @return Value of instrumentation parameter or default value if such parameter is not set.
     * @throws Exception In case that parameter name is empty.
     */
    public static @NonNull String getInstrumentationParameter(@NonNull String paramName, @NonNull String defaultValue) throws Exception {
        final Bundle arguments = InstrumentationRegistry.getArguments();
        return arguments.getString(getFullParam(paramName), defaultValue);
    }

    /**
     * Build a full instrumentation parameter name as {@code "test.powerauth." + paramName}.
     * @param paramName Parameter name.
     * @return Full instrumentation parameter name.
     * @throws Exception In case that parameter name is empty.
     */
    private static @NonNull String getFullParam(@NonNull String paramName) throws Exception {
        if (paramName.length() == 0) {
            throw new Exception("Parameter name must not be empty.");
        }
        return "test.powerauth." + paramName;
    }
}
