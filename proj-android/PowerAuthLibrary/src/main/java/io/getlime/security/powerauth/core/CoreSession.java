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

import java.util.List;
import java.util.Map;

import io.getlime.security.powerauth.core.response.CoreActivationResult;
import io.getlime.security.powerauth.core.response.CoreActivationStatus;
import io.getlime.security.powerauth.core.response.CoreProtocolUpgradeResult;
import io.getlime.security.powerauth.core.response.CoreTokenData;

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
    @CoreProtocolVersion
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

    /**
     * Starts a new activation process. Once the activation is started you have to complete
     * whole activation sequence or reset a whole session.
     *
     * @param L1Data JSON serializable map with L1 activation data.
     * @param L2Data JSON serializable map with L2 activation data.
     * @return {@link CoreRequest} object containing all required information for activation creation.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<CoreActivationResult> createActivation(@NonNull Map<String, Object> L1Data,
                                                                     @NonNull Map<String, Object> L2Data) throws CoreException;

    /**
     * Fetch activation status from the server.
     * @return {@link CoreTask} for getting activation status.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreTask<CoreActivationStatus> fetchActivationStatus() throws CoreException;

    /**
     * Get last activation status received from the server. This property provides the most recent
     * activation status and does not trigger any server communication. If no such information has
     * been received yet, {@code null} is returned.
     * @return Last activation status received from the server
     */
    @Nullable
    public native CoreActivationStatus getLastActivationStatus();

    /**
     * Confirm activation and complete the activation process with user's password and optional biometry KEK.
     *
     * @param password User's password.
     * @param biometryKek Optional biometric factor KEK. If null then this session will not have biometry configured.
     * @return {@link CoreTask} object for activation confirmation.
     * @throws CoreException In case of failure.
     */
    @Nullable
    public native CoreTask<Object> confirmActivation(@NonNull Password password,
                                                     @Nullable SecureData biometryKek) throws CoreException;

    /**
     * Remove activation from the server.
     *
     * @param credentials Credentials with at least two factors.
     * @return {@link CoreRequest} object containing all required information for activation remove.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<Object> removeActivation(@NonNull CoreCredentials credentials) throws CoreException;

    /**
     * Start protocol upgrade procedure.
     *
     * @param password User's password to authenticate start of the protocol upgrade,
     *                 if {@code null} the task is only allowed to confirm the protocol upgrade.
     * @param biometryKek Biometric factor KEK. Should be set if the session already have a biometry configured.
     * @return {@link CoreTask} for protocol upgrade procedure.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreTask<CoreProtocolUpgradeResult> startProtocolUpgrade(@Nullable Password password,
                                                                           @Nullable SecureData biometryKek) throws CoreException;

    // Factor keys management

    /**
     * @return {@code true} in case the biometric factor is set.
     */
    public native boolean hasBiometryFactor();

    /**
     * Verify user's password on the server.
     * @param password User's password.
     * @return {@link CoreRequest} object containing all required information for password verify.
     * @throws CoreException In case of failure.
     */
    public native CoreRequest<Object> verifyPassword(@NonNull Password password) throws CoreException;

    /**
     * Change user's password.
     *
     * @param oldPassword Old password.
     * @param newPassword New password.
     * @return {@link CoreRequest} in case that operation require communication with the server,
     *         or {@code null} in case the password has been changed synchronously.
     * @throws CoreException In case of failure.
     */
    @Nullable
    public native CoreRequest<Object> changePassword(@NonNull Password oldPassword, @NonNull Password newPassword) throws CoreException;

    /**
     * Add biometry factor.
     *
     * @param password User's password.
     * @param biometryKek New biometry KEK.
     * @return {@link CoreRequest} object containing all required information for biometry add.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<Object> addBiometryFactor(@NonNull Password password, @NonNull SecureData biometryKek) throws CoreException;

    /**
     * Remove biometry factor.
     *
     * @return {@link CoreRequest} in case that operation require communication with the server,
     *         or {@code null} in case the biometry has been removed synchronously.
     * @throws CoreException In case of failure.
     */
    @Nullable
    public native CoreRequest<Object> removeBiometryFactor() throws CoreException;

    // Authentication

    /**
     * Calculate online authentication header for HTTP request.
     *
     * @param credentials Credentials used for authentication.
     * @param uriIdentifier URI identifier.
     * @param httpMethod HTTP method.
     * @param requestBody Request body.
     * @return HTTP header with authentication code.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreHttpHeader calculateOnlineAuthenticationHeader(@NonNull CoreCredentials credentials,
                                                                     @NonNull String uriIdentifier,
                                                                     @NonNull String httpMethod,
                                                                     @Nullable byte[] requestBody) throws CoreException;

    /**
     * Calculate human readable authentication code for offline authentication.
     *
     * @param credentials Credentials used for authentication.
     * @param uriIdentifier URI identifier.
     * @param offlineNonce Offline nonce.
     * @param codeLength Length of calculated code.
     * @param data Data for authentication.
     * @return Human readable authentication code.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native String calculateOfflineAuthenticationCode(@NonNull CoreCredentials credentials,
                                                            @NonNull String uriIdentifier,
                                                            @NonNull String offlineNonce,
                                                            int codeLength,
                                                            @Nullable byte[] data) throws CoreException;

    /**
     * Normalize parameters of GET HTTP request into data suitable for function that calculate online authentication header.
     *
     * @param parameters Map with GET parameters.
     * @return Normalized data crated from GET parameters.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native byte[] normalizeGetRequestParameters(@Nullable Map<String, String> parameters) throws CoreException;

    // Tokens

    /**
     * Calculate HTTP header for token authentication.
     *
     * @param tokenIdentifier Token's identifier.
     * @param tokenSecret Token's secret.
     * @return {@link CoreHttpHeader} authentication header.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreHttpHeader calculateTokenHeader(@NonNull String tokenIdentifier, @NonNull byte[] tokenSecret) throws CoreException;

    /**
     * Create access token on the server.
     *
     * @param credentials Credentials used for token creation.
     * @return {@link CoreRequest} object containing all required information for token creation.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<CoreTokenData> createAccessToken(@NonNull CoreCredentials credentials) throws CoreException;

    /**
     * Remove access token from the server.
     *
     * @param tokenIdentifier Token's identifier.
     * @return {@link CoreRequest} object containing all required information for token removal.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<Object> removeAccessToken(@NonNull String tokenIdentifier) throws CoreException;

    // Digital signatures

    /**
     * Export device public keys into the specified format.
     * @param format Required format of the output public key data.
     * @return Array of {@link CoreDevicePublicKeyData} objects.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreDevicePublicKeyData[] exportDevicePublicKeys(@CoreDevicePublicKeyFormat int format) throws CoreException;

    /**
     * Verify a digital signature over the given data.
     * @param signature Signature calculated from signed data.
     * @param data Signed data.
     * @param keyId Key used for signature verification. The key must support signature verification.
     * @throws CoreException In case of failure. If the signature is not valid, then exception with
     *                       {@link CoreErrorCode#WRONG_SIGNATURE} code is raised.
     */
    public native void verifySignature(@NonNull byte[] signature,
                                       @Nullable byte[] data,
                                       @CoreSignatureKeyId int keyId) throws CoreException;


    /**
     * Create a digital signature over the given data. If the request succeeds, the response
     * contains an array of bytes with the calculated signature.
     * @param data Data to sign.
     * @param credentials Credentials used for unlocking the device private key.
     * @param keyId Key used for signature calculation. The key must support such operation.
     * @return {@link CoreRequest} object containing all required information for unlocking device private key.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<byte[]> signData(@Nullable byte[] data,
                                               @NonNull CoreCredentials credentials,
                                               @CoreSignatureKeyId int keyId) throws CoreException;

    // JWS

    /**
     * Verify server-signed data in JWS or JWT form.
     * @param signedData JWS or JWT signed data.
     * @param compactForm If {@code true}, the provided string is a JWT instead of a full JWS object.
     * @param strict If {@code true}, all provided keys must be used to successfully verify
     *               their corresponding signatures. If {@code false}, verification succeeds when at
     *               least one provided key matches a valid signature; however, invalid or
     *               mismatched signatures still result in an error.
     * @param keyId Key used for signature verification. The key must support such operation.
     * @throws CoreException In case of failure. If the signature is not valid, then exception with
     *                       {@link CoreErrorCode#WRONG_SIGNATURE} code is raised.
     */
    public native void jwsVerifySignature(@NonNull String signedData,
                                          boolean compactForm,
                                          boolean strict,
                                          @CoreSignatureKeyId int keyId) throws CoreException;

    /**
     * Create a JWS (or compact JWT) over the given data. If the request succeeds, the response
     * contains a {@code String} with the calculated JWS or JWT.
     *
     * @param data Data to sign and embed into JWS.
     * @param dataType Data type set to JOSE header. Use {@code "JWT"} or {@code null} if no type
     *                 is set.
     * @param compactForm If {@code true}, the result contains a compact JWT string instead of a JWS.
     *                    If used with hybrid keys, an error is reported.
     * @param credentials Credentials used for unlocking the device private key.
     * @param keyId Key used for signature calculation. The key must support such operation.
     * @return {@link CoreRequest} object containing all required information for unlocking device
     *         private key.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<String> jwsSignData(@Nullable byte[] data,
                                                  @Nullable String dataType,
                                                  boolean compactForm,
                                                  @NonNull CoreCredentials credentials,
                                                  @CoreSignatureKeyId int keyId) throws CoreException;

    /**
     * Creates X.509 CSR (Certificate Signing Request) with given Distinguished Names and
     * optional Subject Alternative Names, embedded device public key and signed with the device
     * private key. If the request succeeds, the response contains a {@code String} with
     * the CSR in PEM format.
     *
     * @param credentials Credentials to use to unlock the device private key.
     * @param dnItems Map with distinguished names.
     * @param sanItems Optional subject alternative names.
     * @param keyId Key used for signature calculation. The key must support sign operation.
     * @return {@link CoreRequest} object containing all required information for unlocking device
     *         private key.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<String> createCertificateSigningRequest(@NonNull CoreCredentials credentials,
                                                                      @NonNull Map<String, String> dnItems,
                                                                      @Nullable List<String> sanItems,
                                                                      @CoreSignatureKeyId int keyId) throws CoreException;

    // EEK

    /**
     * Get information whether EEK is still present in V3 persistent data.
     * @return {@code true} if V3 persistent data still contains factor keys protected with EEK.
     */
    public native boolean hasExternalEncryptionKey();

    /**
     * Remove EEK if factor keys are still protected with EEK. The method throws an exception
     * if activation is not present, or if factor keys are not protected with EEK.
     * @param eek EEK previously used for the factor keys protection.
     * @throws CoreException In case of failure.
     */
    public native void removeExternalEncryptionKey(@NonNull SecureData eek) throws CoreException;

    /**
     * Add external encryption key for testing purposes. The method should not be used in the
     * release build. The legacy activation must be present and the size of EEK must match the size
     * of factor keys used in V3.3 protocol version (e.g. 16 bytes).
     * @param eek EEK to apply.
     * @throws CoreException In case of failure.
     */
    public native void addExternalEncryptionKeyForTest(@NonNull SecureData eek) throws CoreException;

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

    // Vault operations

    /**
     * Fetch vault key from the server. If the requested key is {@link CoreSecureVaultKeyId#LEGACY},
     * then also apply key derivation with given index. In case of success, the response object
     * contains instance of {@link SecureData} object.
     * @param credentials Credentials used for access the key.
     * @param keyId Vault encryption key to fetch.
     * @param index Derivation index of the vault key. The value is ignored for non-"legacy" keys.
     * @return {@link CoreRequest} object containing all required information for accessing the key.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<SecureData> fetchVaultEncryptionKey(@NonNull CoreCredentials credentials,
                                                                  @CoreSecureVaultKeyId int keyId,
                                                                  long index) throws CoreException;

    /**
     * Derive already existing key into new key. If the key type is {@link CoreSecureVaultKeyId#LEGACY},
     * then throws exception.
     * @param vaultKey Original key.
     * @param keyId Identifier of current vault encryption key.
     * @param index Derivation index of the new key.
     * @param keySize Size of derived key in bytes. Minimum is 16 bytes.
     * @return {@link SecureData} object with derived key.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native static SecureData deriveVaultEncryptionKey(@NonNull SecureData vaultKey,
                                                             @CoreSecureVaultKeyId int keyId,
                                                             long index,
                                                             int keySize) throws CoreException;

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
     * Generates a factor KEK from the provided input data. This method is typically used to derive
     * a KEK for a biometric factor.
     * <p>
     * If the activation is still using protocol V3, the method is compatible with the normalization
     * used in SDK 1.9.x and older ({@code Session.normalizeSignatureUnlockKeyFromData()}).
     *
     * @param data Input data.
     * @return KEK calculated from input data.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native SecureData generateFactorKekFromData(@NonNull SecureData data) throws CoreException;

    /**
     * Generates a factor KEK from the provided input data. This method is typically used to derive
     * a KEK for a biometric factor for specific protocol version.
     * <p>
     * If KEK is derived for protocol V3, the method is compatible with the normalization
     * used in SDK 1.9.x and older ({@code Session.normalizeSignatureUnlockKeyFromData()}).
     *
     * @param data Input data.
     * @param protocolVersion Protocol version for which the KEK will be used.
     * @return KEK calculated from input data for specified protocol version.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public static native SecureData generateFactorKekFromDataForVersion(@NonNull SecureData data, @CoreProtocolVersion int protocolVersion) throws CoreException;

    /**
     * Remove biometric factor from the persistent data.
     */
    public native void cleanupBiometricFactorData();

    /**
     * Generate new factor KEK for selected protocol version.
     *
     * @param protocolVersion Protocol version.
     * @return New KEK.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public static native SecureData generateFactorKekForProtocolVersion(@CoreProtocolVersion int protocolVersion) throws CoreException;

    /**
     * Get textual representation for given protocol version. For example, for `ProtocolVersion.V3`
     * returns "3.3". You can use `ProtocolVersion.NA` to get the value for the latest supported version.
     * @param protocolVersion Protocol version.
     * @return Textual representation for given protocol version.
     */
    @NonNull
    public static native String maxSupportedHttpProtocolVersion(@CoreProtocolVersion int protocolVersion);

    // User Info

    /**
     * Fetch user info from the server.
     * @return {@link CoreRequest} for getting user info.
     * @throws CoreException In case of failure.
     */
    @NonNull
    public native CoreRequest<Map<String, Object>> fetchUserInfo() throws CoreException;

    /**
     * Get last user info received from the server. This property provides the most recent
     * user info and does not trigger any server communication. If no such information has
     * been received yet, {@code null} is returned.
     * @return Last user info received from the server.
     */
    @Nullable
    public native Map<String, Object> getLastUserInfo();

}
