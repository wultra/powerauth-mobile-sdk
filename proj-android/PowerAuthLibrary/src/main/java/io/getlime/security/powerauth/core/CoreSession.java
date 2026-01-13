/*
 * Copyright 2025 Wultra s.r.o.
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

package io.getlime.security.powerauth.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * The {@code CoreSession} class provides Java interface for low-level C++ Session implementation.
 */
public class CoreSession extends NativeObject {

    @NonNull
    private final CoreConfig configuration;
    @NonNull
    private final CoreTimeService timeService;

    // Construction & destroy

    /**
     * Create {@code CoreSession} instance initialized with a given configuration.
     * @param configuration Session's configuration.
     * @return Instance of {@link CoreSession} class.
     * @throws CoreException In case the configuration is not valid.
     */
    @NonNull
    public native static CoreSession createSession(@NonNull CoreConfig configuration) throws CoreException;

    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public void destroy() {
        safeNativeDestroy(nativeObjectHandle);
    }

    /**
     * Construct object with handle to native object and required parameters. This is a designated
     * constructor used from JNI, when C++ object is being wrapped into Java object.
     *
     * @param nativeObjectHandle Handle to session's native object.
     * @param configuration Configuration object instance.
     * @param timeService Time service instance.
     */
    private CoreSession(long nativeObjectHandle, @NonNull CoreConfig configuration, @NonNull CoreTimeService timeService) {
        super(nativeObjectHandle);
        this.configuration = configuration;
        this.timeService = timeService;
    }

    /**
     * Resets session into its initial state. The existing session's configuration is preserved
     * after the call.
     */
    public native void resetSession();

    // Getters

    /**
     * @return {@link CoreConfig} object used for instance initialization.
     */
    @NonNull
    public CoreConfig getConfiguration() {
        return configuration;
    }

    /**
     * @return {@code APPLICATION_KEY} read from the configuration object object.
     */
    @NonNull
    public native String getApplicationKey();

    /**
     * @return Instance identifier provided in session's configuration.
     */
    @NonNull
    public String getInstanceId() {
        return configuration.getInstanceId();
    }

    /**
     * @return Current effective algorithm used in the session. If there's no activation, then
     *         returns algorithm provided in the configuration.
     */
    @CoreAlgorithm
    public native int getCurrentAlgorithm();

    /**
     * @return Version of protocol in which the session currently operates. If session has no
     *         activation, then the most up to date version is returned.
     */
    @ProtocolVersion
    public native int getProtocolVersion();

    /**
     * @return {@code true} if the session is in state where it's possible to create a new activation.
     */
    public native boolean canCreateActivation();

    /**
     * @return {@code true} if the session has pending activation create
     */
    public native boolean hasPendingCreateActivation();

    /**
     * @return {@code true} if the session has valid activation and the shared secret between the
     *         client and the server has been established. You can sign data in this state.
     */
    public native boolean hasValidActivationData();

    /**
     * Checks if there's a valid activation that requires a protocol upgrade. Contains {@code false}
     * once the upgrade process is started.
     *
     * @return {@code true} if protocol upgrade is available.
     */
    public native boolean hasProtocolUpgradeAvailable();

    /**
     * @return {@code true} if the session has pending upgrade to newer protocol version. Some
     *         operations may be temporarily blocked during the upgrade process.
     */
    public native boolean hasPendingProtocolUpgrade();

    // Serialization

    /**
     * Save the state of session into the sequence of bytes.
     * <p>
     * Note that saving a state during the pending activation has no effect. In this case,
     * the returned byte sequence represents the state of the session before the activation
     * process is started.
     *
     * @return Array of bytes with serialized state of the session.
     * @throws CoreException In case of failure.
     */
    public native byte[] getSerializedState() throws CoreException;

    /**
     * Loads state of session from previously saved sequence of bytes. If the serialized state is
     * invalid then the session ends in empty, uninitialized state.
     *
     * @param serializedState Bytes with previously serialized state.
     * @throws CoreException In case of failure.
     */
    public native void deserializeState(@NonNull byte[] serializedState) throws CoreException;

    /**
     * @return Information that session has modified internal state that needs to be saved to
     *         the persistent storage.
     */
    public native boolean isModifiedState();

    // Activation

    /**
     * @return If the session has valid activation, then returns the activation identifier.
     *         Otherwise returns {@code null}.
     */
    @Nullable
    public native String getActivationIdentifier();

    /**
     * @return If the session has valid activation, then returns decimalized fingerprint, calculated
     *         from the device and public public keys. Otherwise returns nil
     */
    @Nullable
    public native String getActivationFingerprint();

    // Factor keys management

    /**
     * @return {@code true} in case the biometric factor is set.
     */
    public native boolean hasBiometryFactor();

    // Services

    /**
     * @return Instance of {@link CoreTimeService} associated with the session.
     */
    @NonNull
    public CoreTimeService getTimeService() {
        return timeService;
    }

    /**
     * Get instance of {@link CoreEncryptorFactory} associated with the session.
     * <p>
     * Note that the method always create a new instance of the factory.
     *
     * @return New instance of {@link CoreEncryptorFactory} associated with the session.
     */
    @NonNull
    public native CoreEncryptorFactory getEncryptorFactory();

    // Utilities

    /**
     * Generate new factor KEK. The size of KEK depends on the current protocol version.
     *
     * @return New KEK.
     * @throws CoreException in case of failure.
     */
    @NonNull
    public native SecureData generateFactorKek() throws CoreException;

    /**
     * Generate new factor KEK for selected protocol version.
     *
     * @param protocolVersion Protocol version.
     * @return New KEK.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public static native SecureData generateFactorKekForProtocolVersion(@ProtocolVersion int protocolVersion) throws CoreException;

    /**
     * Get textual representation for given protocol version. For example, for `ProtocolVersion.V3`
     * returns "3.3". You can use `ProtocolVersion.NA` to get the value for the latest supported version.
     * @param protocolVersion Protocol version.
     * @return Textual representation for given protocol version.
     */
    @NonNull
    public static native String maxSupportedHttpProtocolVersion(@ProtocolVersion int protocolVersion);
}
