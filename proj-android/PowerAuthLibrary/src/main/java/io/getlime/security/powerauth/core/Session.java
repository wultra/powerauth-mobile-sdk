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

package io.getlime.security.powerauth.core;

import android.support.annotation.NonNull;

import java.util.ArrayList;
import java.util.Map;

public class Session {
    
    //
    // Init & Destroy
    //
    
    static {
        System.loadLibrary("PowerAuth2Module");
    }
    
    /**
     * Pointer to native underlying object
     */
    private long handle;

    /**
     * Constructs a new Session with given setup.
     *
     * @param setup {@link SessionSetup} object with a session configuration.
     */
    public Session(SessionSetup setup) {
        this.handle = init(setup);
    }
    
    /**
     * Internal JNI initialization.
     *
     * @return pointer to underlying C++ object
     */
    private native long init(SessionSetup setup);

    /**
     * Internal JNI destroy. You have to provide handle created during the initialization.
     *
     * @param handle pointer to underlying C++ object
     */
    private native void destroy(long handle);
    
    /**
     * Destroys underlying native C++ object. You can call this method
     * if you want to be sure that internal C++ object is properly destroyed.
     * You can't use instance of this java object anymore after this call.
     */
    public synchronized void destroy() {
        if (this.handle != 0) {
            destroy(this.handle);
            this.handle = 0;
        }
    }
    
    /**
     * Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }
    
    /**
     * @return {@link SessionSetup} object with parameters provided in Session's constructor
     */
    public native SessionSetup getSessionSetup();
    
    /**
     * Resets session into its initial state. The existing session's setup and EEK is preserved
     * after the call.
     */
    public native void resetSession();
    
    /**
     * Returns true if dynamic library was compiled with a debug features. It is highly recommended
     * to check this boolean and force application to crash, if the production, final app
     * is running against a debug featured library.
     *
     * @return true if Session was compiled with a some debug feature turned ON.
     */
    public native boolean hasDebugFeatures();

    /**
     * Returns true if the internal {@link SessionSetup} object is valid.
     * Note that the method doesn't validate whether the provided master key is valid
     * or not.
     *
     * @return true if provided setup appears to be correct
     */
    public native boolean hasValidSetup();

    /**
     * @return Version of protocol in which the session currently operates. If the session has no
     *         activation, then the most up to date version is returned.
     */
    public native ProtocolVersion getProtocolVersion();

    //
    // Serialization
    //

    /**
     * Saves state of session into the sequence of bytes. The saved sequence contains content of
     * internal PersistentData structure, if is present.
     * <p>
     * Note that saving a state during the pending activation has no effect. In this case,
     * the returned byte sequence represents the state of the session before the activation started.
     *
     * @return byte array with serialized state
     */
    public native byte[] serializedState();

    /**
     * Loads state of session from previously saved sequence of bytes. If the serialized state is
     * invalid then the session ends in its initial state.
     *
     * @param state byte array containing previously serialized state
     * @return integer value, which can be compared to the constants from an {@link ErrorCode} class.
     */
    @ErrorCode
    public native int deserializeState(byte[] state);

    //
    // Activation
    //

    /**
     * @return true if Session is in its initial state an you can start activation.
     *         Otherwise returns false.
     */
    public native boolean canStartActivation();

    /**
     * @return true if activation is in progress. You should not save the state of
     *         Session in this case.
     */
    public native boolean hasPendingActivation();

    /**
     * @return true if Session has a valid activation and you can perform
     *         request signing and other post-activation tasks.
     */
    public native boolean hasValidActivation();

    /**
     * @return activation identifier if the Session has valid activation. If there's
     *         no activation then returns null.
     */
    public native String getActivationIdentifier();

    /**
     * @return If the session has valid activation, then returns decimalized fingerprint, calculated
     *         from device's public key. Otherwise returns null.
     */
    public native String getActivationFingerprint();
    
    /**
     * Starts a new activation process. The Session must be in its initial state. Once the
     * activation is started you have to complete whole activation sequence or reset Session
     * to its initial state.
     * <p>
     * You have to provide ActivationStep1Param object with all required properties available.
     * The result of the operation is stored into the ActivationStep1Result object.
     * <p>
     * The method always returns valid object and you have to check result's errorCode
     * property whether the operation failed or not.
     *
     * @param param {@link ActivationStep1Param} parameters required for activation start.
     * @return {@link ActivationStep1Result} object with operation result
     */
    public native ActivationStep1Result startActivation(ActivationStep1Param param);

    /**
     * Validates activation response from the server. The Session expects that activation process
     * was previously started with using {@link #startActivation(ActivationStep1Param)} method. You have to provide
     * {@link ActivationStep2Param} object with all properties available. The result of the operation
     * is stored into {@link ActivationStep2Result} object. If the response is correct then you can
     * finish activation with {@link #completeActivation(SignatureUnlockKeys)} method.
     *
     * <h2>Discussion</h2>
     * <p>
     * If the operation succeeds then the PA2 handshake is from a network communication point of view
     * considered as complete. The server knows our client and both sides have calculated shared
     * secret key. Because of the complexity of whole operation, there's last separate step in our
     * activation flow, which finally protects all sensitive information with user password and
     * other local keys. This last step is offline only, no data is transmitted over the network
     * and therefore if you don't complete the activation (you can reset Session for example)
     * then the server will keep its part of shared secret but nobody will be able to use that
     * established context.
     * <p>
     * Always returns valid object and you have to check result's errorCode property to check,
     * whether the operation failed or not.
     *
     * @param param {@link ActivationStep2Param}response from the server
     * @return {@link ActivationStep2Result} object with operation result
     */
    public native ActivationStep2Result validateActivationResponse(ActivationStep2Param param);

    /**
     * Completes previously started activation process and protects sensitive local information with
     * provided keys. Please check documentation for SignatureUnlockKeys class for details about
     * constructing protection keys and for other related information.
     * <p>
     * You have to provide at least lockKeys.userPassword and lockKeys.possessionUnlockKey to pass
     * the method's input validation. After the activation is complete you can finally save Session's
     * state to keep that information for future use.
     * <p>
     * <b>WARNING:</b> You have to save Session's state when the activation is completed.
     *
     * @param lockKeys encryption keys to protect signature factors created during the activation.
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int completeActivation(SignatureUnlockKeys lockKeys);


    //
    // Activation status
    //

    /**
     * The method decodes received status blob into ActivationStatus object. You can call this method after a successful
     * activation and obtain information about pairing between the client and the server. You have to provide valid
     * possessionUnlockKey in unlockKeys keys object.
     *
     * @param encryptedStatus encrypted status blob received from the server
     * @param unlockKeys object with unlock keys, with the required possession factor.
     * @return Always returns a valid object and you have to check result's errorCode property whether
     *         the operation failed or not.
     */
    public native ActivationStatus decodeActivationStatus(@NonNull EncryptedActivationStatus encryptedStatus, @NonNull SignatureUnlockKeys unlockKeys);

    //
    // Data signing
    //

    /**
     * Converts key:value dictionary into normalized data, suitable for data signing. The method is handy
     * in cases where you have to sign parameters of GET request. You have to provide key-value map constructed
     * from your GET parameters. The result is normalized data sequence, prepared for data signing.
     * <p>
     * For a POST requests it's recommended to sign a whole POST body.
     *
     * @param keyValueMap map with GET parameters
     * @return normalized byte array, prepared for data signing
     */
    public byte[] prepareKeyValueDictionaryForDataSigning(Map<String, String> keyValueMap) {
        ArrayList<String> keys = new ArrayList<>();
        ArrayList<String> values = new ArrayList<>();
        for (Map.Entry<String, String> entry : keyValueMap.entrySet()) {
            keys.add(entry.getKey());
            values.add(entry.getValue());
        }
        return prepareKeyValueDictionaryForDataSigning(keys.toArray(new String[0]), values.toArray(new String[0]));
    }

    /**
     * Internal JNI implementation for key-value data normalization. You have to provide two arrays,
     * where the related keys and values are at the same indexes.
     *
     * @param keys array with keys
     * @param values array with values
     * @return normalized byte array, prepared for data signing
     */
    private native byte[] prepareKeyValueDictionaryForDataSigning(String[] keys, String[] values);

    /**
     * Calculates signature from given data. You have to provide all involved |unlockKeys| required for
     * the |signatureFactor|. For |request.body| you can provide whole POST body or prepare data with
     * using 'prepareKeyValueDictionaryForDataSigning' method. The |request.method| parameter is the HTML
     * method of signed request. The |request.uri| parameter should be relative URI. Check the original PA2
     * documentation for details about signing the HTTP requests.
     * <p>
     * The returned object contains 'errorCode' and 'signature' string, which is an exact and
     * complete value for "X-PowerAuth-Authorization" HTTP header.
     *
     * <h2>WARNING</h2>
     *
     * You have to save Session's state after the successful operation, because the internal counter
     * is changed. If you don't save the state then you'll sooner or later loose synchronization
     * with the server and your client will not be able to sign data anymore.
     *
     * <h2>Discussion about thread safety</h2>
     *
     * If your networking infrastructure allows simultaneous HTTP requests then it's recommended to
     * guard this method with locking. There's possible race condition when the internal signing counter
     * is raised in persistent data structure. The Session doesn't provide locking internally.
     *
     * @param request {@link SignatureRequest} object with data for signature calculation
     * @param unlockKeys object with keys to unlock signature factors.
     * @param signatureFactor integer with bitwise mask of factors. See {@link SignatureFactor} class for details.
     *
     * @return {@link SignatureResult} with signature calculation result. You need to check {@link SignatureResult#errorCode}
     *         whether the operation failed or not.
     */
    public native SignatureResult signHTTPRequest(SignatureRequest request, SignatureUnlockKeys unlockKeys, @SignatureFactor int signatureFactor);

    /**
     * @return name of authorization header. The value is constant and is equal to "X-PowerAuth-Authorization".
     *         You can calculate appropriate value with using 'signHTTPRequest' method.
     */
    public native String getHttpAuthHeaderName();

    /**
     * Validates whether the data has been signed with master server private key.
     *
     * @param signedData {@link SignedData} object with parameters required for signature validation
     * @return integer comparable to constants available at {@link ErrorCode} class.
     */
    @ErrorCode
    public native int verifyServerSignedData(SignedData signedData);

    //
    // Signature keys management
    //

    /**
     * Changes user's password. You have to save Session's state to keep this change for later.
     *
     * <h2>Discussion</h2>
     *
     * The method doesn't perform password validation and therefore if the wrong password is provided,
     * then the knowledge key will be permanently lost. You have to validate password on the server by
     * calling some service endpoint, which requires knowledge factor for correct operation.
     *
     * So, the typical flow for password change is:
     *
     * <ol>
     *   <li>ask user for an old password</li>
     *   <li>send HTTP request, signed with knowledge factor, use an old password for key unlock.
     *    If operation fails, then you can repeat step 1 or exit the flow</li>
     *   <li>ask user for a new password as usual (e.g. ask for password for twice, compare both,
     *    check minimum length, etc...)</li>
     *   <li>call this method with using old and new password</li>
     *   <li>save Session's state</li>
     * </ol>
     *
     * @param oldPassword old password
     * @param newPassword new password
     * @return integer comparable to constants available at {@link ErrorCode} class.
     */
    @ErrorCode
    public native int changeUserPassword(Password oldPassword, Password newPassword);

    /**
     * Adds key for biometry factor. You have to provide encrypted vault key |cVaultKey| and |unlockKeys|
     * object with a new biometryUnlockKey and a valid possessionUnlockKey. The possession key
     * is required for a transport unlock key computation and the biometryUnlockKey is a new key which will
     * be used for a biometry signature key protection. You should always save Session's state after this
     * operation, whether it ends with error or not.
     *
     * <h2>Discussion</h2>
     *
     * The adding new key for biometry factor is a quite complex task. At first, you need to ask server
     * for a vault key and sign this HTTP request with a multiple factors. If you don't receive response
     * from the server then it's OK to leave the Session as is.
     *
     * @param cVaultKey encrypted vault key
     * @param unlockKeys unlock keys object with required possession factor
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int addBiometryFactor(String cVaultKey, SignatureUnlockKeys unlockKeys);

    /**
     * Checks if there is a biometry factor present in a current session.
     *
     * @return true if there is a biometry factor related key present, false otherwise.
     */
    public native boolean hasBiometryFactor();

    /**
     * Removes existing biometry key from persisting data. You have to save state of the Session after
     * the operation.
     *
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int removeBiometryFactor();

    //
    // Vault operations
    //

    /**
     * Calculates a cryptographic key, derived from encrypted vault key, received from the server. The method
     * is useful for situations, where the application needs to protect locally stored data with a cryptographic
     * key, which is normally not present on the device and must be acquired from the server at first.
     *
     * <h2>Discussion</h2>
     *
     * You have to provide encrypted |cVaultKey| and |unlockKeys| object with a valid possessionUnlockKey.
     * The |keyIndex| is a parameter to the key derivation function. You should always save session's state
     * after this operation, whether it ends with error or not.
     * <p>
     * You should NOT store the produced key to the permanent storage. If you store the key to the filesystem
     * or even to the keychain, then the whole server based protection scheme will have no effect. You can, of
     * course, keep the key in the volatile memory, if the application needs use the key for a longer period.
     *
     * @param cVaultKey encrypted vault key
     * @param unlockKeys unlock keys object with required possession factor
     * @param keyIndex parameter to key derivation function
     *
     * @return byte array with a derived cryptographic key or null in case of failure.
     */
    public native byte[] deriveCryptographicKeyFromVaultKey(String cVaultKey, SignatureUnlockKeys unlockKeys, long keyIndex);
    
    /**
     * Computes a ECDSA-SHA256 signature of given |data| with using device's private key. You have to provide
     * encrypted |cVaultKey| and |unlockKeys| structure with a valid possessionUnlockKey.
     *
     * <h2>Discussion</h2>
     *
     * The session's state contains device private key but it is encrypted with a vault key, which is normally not
     * available on the device. Just like other vault related operations, you have to properly sign HTTP request
     * with using PA2SignatureFactor_PrepareForVaultUnlock flag, otherwise the operation will fail.
     *
     * @param cVaultKey encrypted vault key
     * @param unlockKeys unlock keys object with required possession factor
     * @param data data to be signed
     *
     * @return array of bytes with calculated signature or null in case of failure.
     */
    public native byte[] signDataWithDevicePrivateKey(String cVaultKey, SignatureUnlockKeys unlockKeys, byte[] data);

    //
    // External encryption key
    //
    
    /**
     * @return true if EEK (external encryption key) is set.
     */
    public native boolean hasExternalEncryptionKey();

    /**
     * Sets a known external encryption key to the internal SessionSetup structure. This method
     * is useful, when the Session is using EEK, but the key is not known yet. You can restore
     * the session without the EEK and use it for a very limited set of operations, like the status
     * decode. The data signing will also work correctly, but only for a knowledge factor, which
     * is by design not protected with EEK.
     *
     * @param externalEncryptionKey EEK to be set to the session
     *
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int setExternalEncryptionKey(byte[] externalEncryptionKey);
    
    /**
     * Adds a new external encryption key permanently to the activated Session and to the internal
     * SessionSetup structure. The method is different than 'setExternalEncryptionKey' and is useful
     * for scenarios, when you need to add the EEK additionally, after the activation.
     * <p>
     * <b>WARNING:</b> You have to save state of the session after the operation.
     *
     * @param externalEncryptionKey EEK to be set to the session
     *
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int addExternalEncryptionKey(byte[] externalEncryptionKey);
    
    /**
     * Removes existing external encryption key from the activated Session. The method removes EEK permanently
     * and clears internal EEK usage flag from the persistent data. The session has to be activated and EEK
     * must be set at the time of call (e.g. 'hasExternalEncryptionKey' returns true).
     * <p>
     * <b>WARNING:</b> You have to save state of the session after the operation.
     *
     * @return integer comparable to constants from {@link ErrorCode} class. If {@link ErrorCode#OK}
     *         is returned then the operation succeeded.
     */
    @ErrorCode
    public native int removeExternalEncryptionKey();

    //
    // End to End encryption
    //

    /**
     * Constructs the {@link EciesEncryptor} object for the required scope and for optional sharedInfo1.
     * The unlockKeys parameter must contain a valid possessionUnlockKey in case that the "activation"
     * scope is requested. For "application" scope, the unlockKeys object may be null.
     *
     * @param scope scope for encryptor. You have to provide integer from {@link EciesEncryptorScope} class.
     * @param unlockKeys unlock keys object with required possession factor
     * @param sharedInfo1 SH1 cryptographic constant
     *
     * @return {@link EciesEncryptor} object or nil in case of error
     */
    public native EciesEncryptor getEciesEncryptor(int scope, SignatureUnlockKeys unlockKeys, byte[] sharedInfo1);
    
    //
    // Utilities
    //

    /**
     * Returns bytes with normalized key suitable for a signature keys protection. The key is computed from
     * provided data with using one-way hash function (SHA256)
     *
     * <h2>Discussion</h2>
     *
     * This method is useful for situations, where you have to prepare key for possession factor,
     * but your source data is not normalized. For example, WI-FI or UDID doesn't fit to
     * requirements for cryptographic key and this function helps derive the key from the input data.
     *
     * @param arbitraryData data to be used for key normalization
     * @return normalized key
     */
    public native byte[] normalizeSignatureUnlockKeyFromData(byte[] arbitraryData);

    /**
     * Returns bytes with a new normalized key usable for a signature keys protection.
     *
     *  <h2>Discussion</h2>
     *
     * The method is useful for situations, whenever you need to create a new key which will be
     * protected with another, external factor. The best example is when a "biometry" factor is
     * involved in the signatures. For this situation, you can generate a new key and save it
     * to the storage, unlocked by only with using biometric properties of the user.
     *
     * Internally, method only generates 16 bytes long random data and therefore is also suitable
     * for all other situations, when the generated random key is required.
     *
     * @return new random key
     */
    public native byte[] generateSignatureUnlockKey();

    /**
     * Returns new challenge for getting activation status.
     *
     * Internally, method only generates 16 bytes long random data encoded to Base64 and therefore
     * is also suitable for all other situations, when the generated random key is required.
     *
     * @return new challenge in Base64 formatted string.
     */
    public native String generateActivationStatusChallenge();

    //
    // Protocol upgrade
    //

    /**
     * @return true if session has pending upgrade to a newer protocol version. Note that some
     *         operations may not be available in this situation.
     */
    public native boolean hasPendingProtocolUpgrade();

    /**
     * @return {@link ProtocolVersion} enumeration with version to which the session is currently
     *         upgrading.
     */
    public native ProtocolVersion getPendingProtocolUpgradeVersion();

    /**
     * Start protocol upgrade. You should serialize the session's state after this operation.
     *
     * @return {@link ErrorCode#OK} if upgrade has been started, or other error constants if not.
     */
    @ErrorCode
    public native int startProtocolUpgrade();

    /**
     * Applies protocol upgrade data to the session. You need to construct upgrade data object
     * to match the upgrade from current protocol version, to the upgraded one.
     *
     * Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     * then the operation succeeded.
     *
     * You should serialize the session's state after this operation.
     *
     * @param protocolUpgradeData data required for protocol upgrade
     * @return {@link ErrorCode#OK} if data has been applied, or other error constants if not.
     */
    @ErrorCode
    public native int applyProtocolUpgradeData(ProtocolUpgradeData protocolUpgradeData);

    /**
     * Completes the upgrade procedure. You should serialize the session's state after this operation.
     *
     * @return {@link ErrorCode#OK} if upgrade has been finished, or other error constants if not.
     */
    @ErrorCode
    public native int finishProtocolUpgrade();

    //
    // Recovery codes
    //

    /**
     * @return true if session contains an activation recovery data.
     */
    public native boolean hasActivationRecoveryData();

    /**
     * Get an activation recovery data. This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock'
     * to obtain the vault encryption key used for private recovery data decryption.
     *
     * @param cVaultKey encrypted vault key
     * @param unlockKeys unlock keys object with required possession factor
     * @return {@link RecoveryData} object or null in case of error
     */
    public native RecoveryData getActivationRecoveryData(String cVaultKey, SignatureUnlockKeys unlockKeys);

}
