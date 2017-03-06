/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
     Pointer to native underlying object
     */
    private long handle;

    /**
     Constructs a new Session with given setup.
     */
    public Session(SessionSetup setup) {
        this.handle = init(setup);
    }
    
    /**
     Internal JNI initialization. Returns handle representing pointer to
     underlying C++ object.
     */
    private native long init(SessionSetup setup);

	/**
	 Internal JNI destroy. You have to provide handle created during the initialization.
	 */
	private native void destroy(long handle);
    
    /**
     Destroys underlying native C++ object. You can call this method
     if you want to be sure that internal C++ object is properly destroyed.
     You can't use instance of this java object anymore after this call.
     */
    public synchronized void destroy() {
        if (this.handle != 0) {
            destroy(this.handle);
            this.handle = 0;
        }
    }
    
    /**
     Make sure that the underlying C++ object is always destroyed.
     */
    protected void finalize() {
        destroy();
    }
    
    /**
	 Returns SessionSetup object used during the object creation.
	 */
	public native SessionSetup getSessionSetup();
    
    /**
	 Resets session into its initial state. The existing session's setup and EEK is preserved
     after the call.
	 */
	public native void resetSession();
    
    /**
     Returns true if dynamic library was compiled with a debug features. It is highly recommended
     to check this boolean and force application to crash, if the producion, final app
     is running against a debug featured library.
     */
	public native boolean hasDebugFeatures();
	
	/**
	 Returns true if the internal SessionSetup object is valid.
     Note that the method doesn't validate whether the provided master key is valid
     or not.
	 */
	public native boolean hasValidSetup();
	
	//
	// Serialization
	//
	
	/**
	 Saves state of session into the sequence of bytes. The saved sequence contains content of 
	 internal PersistentData structure, if is present.
	 
	 Note that saving a state during the pending activation has no effect. In this case, 
	 the returned byte sequence represents the state of the session before the activation started.
     */
	public native byte[] serializedState();
	
	/**
     Loads state of session from previously saved sequence of bytes. If the serialized state is
     invalid then the session ends in its initial state.
     
     Returns integer value, which can be compared to the constants from an ErrorCode class.
     */
	public native int deserializeState(byte[] state);
	
	//
	// Activation
	//
	
	/**
     Returns true if Session is in its initial state an you can start activation.
     Otherwise returns false.
     */
	public native boolean canStartActivation();
	
	/**
     Returns true if activation is in progress. You should not save the state of
     Session in this case.
     */
	public native boolean hasPendingActivation();
	
	/**
     Returns true if Session has a valid activation and you can perform
     request signing and other post-activation tasks.
     */
	public native boolean hasValidActivation();
	
	/**
     Returns activation identifier if the Session has valid activation. If there's
     no activation then returns null.
     */
	public native String getActivationIdentifier();
    
    /**
     Starts a new activation process. The Session must be in its initial state. Once the
     activation is started you have to complete whole activation sequence or reset Session 
     to its initial state.

     You have to provide ActivationStep1Param object with all required properties available.
     The result of the operation is stored into the ActivationStep1Result object.

     The method always returns valid object and you have to check result's errorCode 
     property whether the operation failed or not.
     */
	public native ActivationStep1Result startActivation(ActivationStep1Param param);
	
	/**
     Validates activation response from the server. The Session expects that activation process
     was previously started with using 'startActivation' method. You have to provide
     ActivationStep2Param object with all properties available. The result of the operation
     is stored into ActivationStep2Result object. If the response is correct then you can
     finish activation with 'completeActivation' method.

     Discussion:

     If the operation succeeds then the PA2 handshake is from a network communication point of view
     considered as complete. The server knows our client and both sides have calculated shared
     secret key. Because of the complexity of whole operation, there's last separate step in our
     activation flow, which finally protects all sensitive information with user password and
     other local keys. This last step is offline only, no data is transmitted over the network
     and therefore if you don't complete the activation (you can reset Session for example)
     then the server will keep its part of shared secret but nobody will be able to use that
     estabilished context.

     Always returns valid object and you have to check result's errorCode property to check,
     whether the operation failed or not.
     */
	public native ActivationStep2Result validateActivationResponse(ActivationStep2Param param);
	
	/**
     Completes previously started activation process and protects sensitive local information with
     provided keys. Please check documentation for SignatureUnlockKeys class for details about
     constructing protection keys and for other related information.

     You have to provide at least lockKeys.userPassword and lockKeys.possessionUnlockKey to pass 
     the method's input validation. After the activation is complete you can finally save Session's
     state to keep that information for future use.

     WARNING: You have to save Session's state when the activation is completed.

     Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.
     */
	public native int completeActivation(SignatureUnlockKeys lockKeys);
	
	
	//
	// Activation status
	//
	
	/**
     The method decodes received status blob into ActivationStatus object. You can call this method after a successful
     activation and obtain information about pairing between the client and the server. You have to provide valid
     possessionUnlockKey in unlockKeys keys object.
     
     Always returns valid object and you have to check result's errorCode property whether the operation failed or not.
     */
	public native ActivationStatus decodeActivationStatus(String statusBlob, SignatureUnlockKeys unlockKeys);
	
	//
	// Data signing
	//
	
	/**
     Converts key:value dictionary into normalized data, suitable for data signing. The method is handy
     in cases where you have to sign parameters of GET request. You have to provide key-value map constructed
     from your GET parameters. The result is normalized data sequence, prepared for data signing.

     For a POST requests it's recommended to sign a whole POST body.
     */
	public byte[] prepareKeyValueDictionaryForDataSigning(Map<String, String> keyValueMap) {
	    ArrayList<String> keys = new ArrayList<>();
	    ArrayList<String> values = new ArrayList<>();
	    for (Map.Entry<String, String> entry : keyValueMap.entrySet()) {
	        keys.add(entry.getKey());
	        values.add(entry.getValue());
        }
	    return prepareKeyValueDictionaryForDataSigning(keys.toArray(new String[keys.size()]), values.toArray(new String[values.size()]));
	}
	
	/**
	 Internal JNI implementation for key-value data normalization. You have to provide two arrays, where
	 the related keys and values are at the same indexes.
	 */
	private native byte[] prepareKeyValueDictionaryForDataSigning(String[] keys, String[] values);
	
	/**
     Calculates signature from given data. You have to provide all involved |unlockKeys| required for
     the |signatureFactor|. For |httpBody| you can provide whole POST body or prepare data with
     using 'prepareKeyValueDictionaryForDataSigning' method. The |httpMethod| parameter is the HTML
     method of signed request. The |uri| parameter should be relative URI. Check the original PA2
     documentation for details about signing the HTTP requests.

     If you're going to sign request for a vault key retrieving, then you have to specifiy signature
     factor combined with SignatureFactor.PrepareForVaultUnlock flag. Otherwise the subsequent
     vault unlock operation will calculate wrong transport key (KEY_ENCRYPTION_VAULT_TRANSPORT) 
     and you'll not be able to complete the operation.

     The returned object contais 'errorCode' and 'signature' string, which is an exact and 
     complete value for "X-PowerAuth-Authorization" HTTP header.

     WARNING

     You have to save Session's state after the successfull operation, because the internal counter
     is changed. If you don't save the state then you'll sooner or later loose synchronization
     with the server and your client will not be able to sign data anymore.

     Discussion about thread safety

     If your networking infrastructure allows simultaneous HTTP requests then it's recommended to
     guard this method with locking. There's possible race condition when the internal signing counter
     is raised in persistent data structure. The Session doesn't provide locking internally.
     */
	public native SignatureResult signHTTPRequest(byte[] httpBody, String httpMethod, String uri, SignatureUnlockKeys unlockKeys, int signatureFactor);
	
	/**
     Returns name of authorization header. The value is constant and is equal to "X-PowerAuth-Authorization".
     You can calculate appropriate value with using 'signHTTPRequest' method.
     */
	public native String getHttpAuthHeaderName();
	
	//
	// Signature keys management
	//
	
	/**
     Changes user's password. You have to save Session's state to keep this change for later.
     Returns integer comparable to constants available at ErrorCode class.
     
     Discussion
     
     The method doesn't perform password validation and therefore if the wrong password is provided, 
     then the knowledge key will be permanently lost. You have to validate password on the server by 
     calling some sevice endpoint, which requires knowledge factor for correct operation.
     
     So, the typical flow for password change is:
     
         1. ask user for an old password
         2. send HTTP request, signed with knowledge factor, use an old password for key unlock
              - if operation fails, then you can repeat step 1 or exit the flow
         3. ask user for a new password as usual (e.g. ask for passwd for twice, compare both,
            check minimum length, etc...)
         4. call `changeUserPassword` with using old and new password
         5. save Session's state
     
     WARNING
     
     All this is a preliminary proposal functionality and is not covered by PA2 specification. 
     The behavior or a whole flow of changing password may be a subject of change in the future.
     */
	public native int changeUserPassword(Password oldPassword, Password newPassword);
	
	/**
     Adds key for biometry factor. You have to provide encrypted vault key |cVaultKey| and |unlockKeys|
     object with a new biometryUnlockKey and a valid possessionUnlockKey. The possession key
     is required for a transport unlock key computation and the biometryUnlockKey is a new key which will
     be used for a biometry signature key protection. You should always save Session's state after this 
     operation, whether it ends with error or not.
     
     Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.

     Discussion

     The adding new key for biometry factor is a quite complex task. At first, you need to ask server
     for a vault key and sign this HTTP request with using SignatureFactor.PrepareForVaultUnlock flag 
     in combination with other required factors. The flag guarantees that the internal counter will be 
     correctly raised and next subsequent operation for vault key decryption will finish correctly.

     If you don't receive response from the server then it's OK to leave the Session as is. Our local
     counter is probably at the same value as server's or slightly ahead and therefore everything
     should work correctly later. The Session only displays warning to debug console about previous
     pending vault unlock operation.
     */
	public native int addBiometryFactor(String cVaultKey, SignatureUnlockKeys unlockKeys);
	
	/**
	 Checks if there is a biometry factor present in a current session.
     Returns true if there is a biometry factor related key present, false otherwise.
	 */
	public native boolean hasBiometryFactor();
	
	/**
     Removes existing biometry key from persisting data. You have to save state of the Session after
     the operation.
     
     Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.
     */
	public native int removeBiometryFactor();
	
	//
	// Vault operations
	//
	
	/**
     Calculates a cryptographic key, derived from encrypted vault key, received from the server. The method
     is useful for situations, where the application needs to protect locally stored data with a cryptographic
     key, which is normally not present on the device and must be acquired from the server at first.

     You have to provide encrypted |cVaultKey| and |unlockKeys| object with a valid possessionUnlockKey.
     The |keyIndex| is a parameter to the key derivation function. You should always save session's state 
     after this operation, whether it ends with error or not.

     Discussion

     You should NOT store the produced key to the permanent storage. If you store the key to the filesystem
     or even to the keychain, then the whole server based protection scheme will have no effect. You can, of
     course, keep the key in the volatile memory, if the application needs use the key for a longer period.

     Note that just like the "addBiometryFactor", you have to properly sign HTTP request with using
     PA2SignatureFactor_PrepareForVaultUnlock flag, otherwise the operation will fail.

     Retuns byte array with a derived cryptographic key or null in case of failure.
     */
    public native byte[] deriveCryptographicKeyFromVaultKey(String cVaultKey, SignatureUnlockKeys unlockKeys, long keyIndex);
    
    /**
     Computes a ECDSA-SHA256 signature of given |data| with using device's private key. You have to provide
     encrypted |cVaultKey| and |unlockKeys| structure with a valid possessionUnlockKey.

     Discussion

     The session's state contains device private key but it is encrypted with a vault key, which is normally not
     available on the device. Just like other vault related operations, you have to properly sign HTTP request
     with using PA2SignatureFactor_PrepareForVaultUnlock flag, otherwise the operation will fail.

     Retuns array of bytes with calculated signature or null in case of failure.
     */
    public native byte[] signDataWithDevicePrivateKey(String cVaultKey, SignatureUnlockKeys unlockKeys, byte[] data);

    //
    // External encryption key
    //
    
    /**
	 Returns true if EEK (external encryption key) is set.
	 */
    public native boolean hasExternalEncryptionKey();

    /**
	 Sets a known external encryption key to the internal SessionSetup structure. This method 
	 is useful, when the Session is using EEK, but the key is not known yet. You can restore 
	 the session without the EEK and use it for a very limited set of operations, like the status 
	 decode. The data signing will also work correctly, but only for a knowledge factor, which 
	 is by design not protected with EEK.
    
     Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.
     */
    public native int setExternalEncryptionKey(byte[] externalEncryptionKey);
    
    /**
	 Adds a new external encryption key permanently to the activated Session and to the internal 
	 SessionSetup structure. The method is different than 'setExternalEncryptionKey' and is useful 
	 for scenarios, when you need to add the EEK additionally, after the activation.
	 
	 You have to save state of the session after the operation.
	 
	 Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.
	 */
    public native int addExternalEncryptionKey(byte[] externalEncryptionKey);
    
    /**
	 Removes existing external encryption key from the activated Session. The method removes EEK permanently
	 and clears internal EEK usage flag from the persistent data. The session has to be activated and EEK
	 must be set at the time of call (e.g. 'hasExternalEncryptionKey' returns true).

	 You have to save state of the session after the operation.
	 
	 Returns integer comparable to constants from ErrorCode class. If ErrorCode.OK is returned
     then the operation succeeded.
	 */
    public native int removeExternalEncryptionKey();

    //
    // E2EE
    //
    
    /**
     Creates a new instace of Encryptor class initialized for nonpersonalized End-To-End Encryption.
     The nonpersonalized mode of E2EE is available after the correct Session object initialization,
     so you can basically use the method anytime during the object's lifetime. The |sessionIndex|
     object must contain a 16 bytes long sequence of bytes. If your application doesn't have mechanism
     for session index creation, then you can use generateSignatureUnlockKey() method for this purpose.

     Note that the method doesn't change persistent state of the Session, so you don't need to
     serialize its state after the call.

     Returns always instance of Encryptor object. If the operation fails then the returned encryptor
     is not valid (e.g. Encryptor.isValid() returns false and Encryptor.lastErrorCode contains 
     appropriate error code)
     */
    public native Encryptor createNonpersonalizedEncryptor(byte[] sessionIndex);
    
    /**
     Creates a new instace of Encryptor class initialized for personalized End-To-End Encryption.
     The personalized mode of E2EE is available only when the session contains valid activation.
     The |sessionIndex| object must contain a 16 bytes long sequence of bytes. If your application doesn't
     have mechanism for session index creation, then you can use generateSignatureUnlockKey() method for
     this purpose.
     The provided |unlockKeys| object must contain valid unlock key for a possession factor.

     Note that the method doesn't change persistent state of the Session, so you don't need to
     serialize its state after the call.

     Returns always instance of Encryptor object. If the operation fails then the returned encryptor
     is not valid (e.g. Encryptor.isValid() returns false and Encryptor.lastErrorCode contains 
     appropriate error code)
     */
    public native Encryptor createPersonalizedEncryptor(byte[] sessionIndex, SignatureUnlockKeys unlockKeys);
    
	//
	// Utilities
	//
	
	/**
     Returns bytes with normalized key suitable for a signagure keys protection. The key is computed from
     provided data with using one-way hash function (SHA256)

     Discussion

     This method is useful for situations, where you have to prepare key for possession factor,
     but your source data is not normalized. For example, WI-FI or UDID doesn't fit to
     requirements for cryptographic key and this function helps derive the key from the input data.
     */
	public native byte[] normalizeSignatureUnlockKeyFromData(byte[] arbitraryData);
	
	/**
     Returns bytes with a new normalized key usable for a signature keys protection.

     Discussion

     The method is useful for situations, whenever you need to create a new key which will be
     protected with another, external factor. The best example is when a "biometry" factor is
     involved in the signatures. For this situation, you can generate a new key and save it
     to the storage, unlocked by only with using biometric properties of the user.

     Internally, method only generates 16 bytes long random data and therefore is also suitable
     for all other situations, when the generated random key is required.
     */
	public native byte[] generateSignatureUnlockKey();
}
