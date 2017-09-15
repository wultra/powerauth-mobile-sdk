/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2Types.h"
#import "PA2Encryptor.h"

@interface PA2Session : NSObject

#pragma mark -  Initialization / Reset

/**
 The designated initializer. You have to provide a valid PA2SessionSetup object.
 */
- (nullable instancetype) initWithSessionSetup:(nonnull PA2SessionSetup *)setup;

/**
 Resets session into its initial state. The existing session's setup and EEK is preserved
 after the call.
 */
- (void) resetSession;

/**
 Returns YES if PA2 library was compiled with a debug features. It is highly recommended
 to check this flag and force application to crash if the producion, final application
 is running against the debug featured library.
 */
+ (BOOL) hasDebugFeatures;


/**
 Returns pointer to an internal SessionSetup object. Returns nil if
 session has no valid setup.
 
 Note that internal implementation always creates a new instance of PA2SessionSetup object.
 If you want to get just a sessionIdentifier, then you can use the dedicated read only
 property, which is much faster than accessing the whole setup object.
 */
@property (nonatomic, strong, readonly, nullable) PA2SessionSetup * sessionSetup;

/**
 Returns value of [self sessionSetup].sessionIdentifier if the setup object is present or 0 if not.
 */
@property (nonatomic, assign, readonly) UInt32 sessionIdentifier;

/**
 Contains error code from last executed operation. You can use
 this value for debug purposes.
 */
@property (nonatomic, assign, readonly) PA2CoreErrorCode lastErrorCode;


#pragma mark - Session state

/**
 Contains YES if the internal SessionSetup object is valid.
 Note that the method doesn't validate whether the provided master key is valid
 or not.
 */
@property (nonatomic, assign, readonly) BOOL hasValidSetup;
/**
 Contains YES if the session is in state where it's possible to start a new activation.
 */
@property (nonatomic, assign, readonly) BOOL canStartActivation;
/**
 Contains YES if the session has pending and unfinished activation.
 */
@property (nonatomic, assign, readonly) BOOL hasPendingActivation;
/**
 Contains YES if the session has valid activation and the shared secret between the client and
 the server has been estabilished. You can sign data in this state.
 */
@property (nonatomic, assign, readonly) BOOL hasValidActivation;


#pragma mark - Serialization

/**
 Saves state of session into the sequence of bytes. The saved sequence contains content of
 internal PersistentData structure, if is present.
 
 Note that saving a state during the pending activation has no effect. In this case,
 the returned byte sequence represents the state of the session before the activation started.
 */
- (nonnull NSData*) serializedState;

/**
 Loads state of session from previously saved sequence of bytes. If the serialized state is
 invalid then the session ends in empty, unitialized state.
 
 Returns YES if operation succeeds. In case of faulure, the lastErrorCode is set
 to appropriate value.
 */
- (BOOL) deserializeState:(nonnull NSData *)state;


#pragma mark - Activation

/**
 If the session has valid activation, then returns the activation identifier.
 Otherwise returns nil.
 */
@property (nonatomic, strong, readonly, nullable) NSString * activationIdentifier;

/**
 Starts a new activation process. The session must have valid setup. Once the activation 
 is started you have to complete whole activation sequence or reset a whole session.
 
 You have to provide PA2ActivationStep1Param object with all required properties available.
 The result of the operation returned in the PA2ActivationStep1Result object. If the
 returned value is nil, then the error occured.
 
 The lastErrorCode is updated with following values:
	EC_Ok,         if operation succeeded
	EC_Encryption, if you provided invalid Base64 strings or if signature is invalid
	EC_WrongState, if called in wrong session's state
	EC_WrongParam, if some required parameter is missing
 */
- (nullable PA2ActivationStep1Result*) startActivation:(nonnull PA2ActivationStep1Param*)param;

/**
 Validates activation respose received from the server. The session expects that the activation
 process was previously started with using 'startActivation' method. You have to provide 
 PA2ActivationStep2Param object with all members filled with the response. The result of the
 operation is stored in the PA2ActivationStep2Result object. If the response is correct then
 you can call 'completeActivation' and finish the activation process.
 
 Discussion
 
 If the operation succeeds then the PA2 handshake is from a network communication point of view
 considered as complete. The server knows our client and both sides have calculated shared
 secret key. Because of the complexity of the operation, there's one more separate step in our
 activation flow, which finally protects all sensitive information with user password and
 other local keys. This last step is offline only, no data is transmitted over the network
 and therefore if you don't complete the activation (you can reset session for example)
 then the server will keep its part of shared secret but nobody will be able to use that
 estabilished context.
 
 If the returned value is nil, then the error occured. The lastErrorCode is updated with 
 following values:
	EC_Ok,         if operation succeeded
	EC_Encryption, if provided data, signature or keys are invalid.
				   If this error occurs then the session resets its state.
	EC_WrongState, if called in wrong session's state
	EC_WrongParam, if required parameter is missing
 */
- (nullable PA2ActivationStep2Result*) validateActivationResponse:(nonnull PA2ActivationStep2Param*)param;

/**
 Completes previously started activation process and protects sensitive local information with
 provided protection keys. Please check the documentation for PA2SignatureUnlockKeys object
 for details about constructing protection keys and for other related information.
 
 You have to provide at least keys.userPassword and keys.possessionUnlockKey to pass the method's
 input validation. After the activation is complete, you can finally save session's state
 into the persistent storage.
 
 WARNING: You have to save session's staate when the activation is completed!
 
 Returns YES if operation succeeds. In case of faulure, the lastErrorCode is set
 to appropriate value:
	EC_Ok,          if operation succeeded
	EC_Encryption,  if some internal encryption failed
					if this error occurs, then the session resets its state
	EC_WrongState,  if called in wrong session's state
	EC_WrongParam,  if required parameter is missing
 */
- (BOOL) completeActivation:(nonnull PA2SignatureUnlockKeys*)keys;


#pragma mark - Activation Status

/**
 The method decodes received status blob into PA2ActivationStatus object. You can call this method after successful
 activation and obtain information about pairing between the client and server. You have to provide valid
 possessionUnlockKey in the unlockKeys object.
 
 If the returned object is nil then the error occured and the lastErrorCode contains reason
 of the failure.
 */
- (nullable PA2ActivationStatus*) decodeActivationStatus:(nonnull NSString *)statusBlob
													keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys;

#pragma mark - Data signing

/**
 Converts NSDictionary into normalized data, suitable for data signing. The method is useful in cases where
 you want to sign parameters of GET request. You have to provide key-value map constructed from your GET parameters.
 The result is normalized byte sequence, prepared for data signing. For POST requests it's recommended to sign
 a whole POST body.
 
 The method returns always NSData object, unless you provide the NSDictionary with wrong type of objects.
 
 Compatibility note
 
 This interface doesn't support multiple values for the same key. This is a known limitation, due to fact, that
 underlying std::map<> doesn't allow duplicit keys. The arrays in GET requests are so rare that I've decided to do not support
 them. You can still implement your own data normalization, if this is your situation.
 */
- (nullable NSData*) prepareKeyValueDictionaryForDataSigning:(nonnull NSDictionary<NSString*, NSString*>*)dictionary;

/**
 Calculates signature from given data. You have to provide all involved unlock keys in |unlockKeys| object,
 required for desired signature |factor|. For the request |requestData.body| you can provide whole POST body or
 you can prepare data with using 'prepareKeyValueDictionaryForDataSigning' method. The |requestData.method| parameter
 is the HTML method of signed request (e.g. GET, POST, etc...). The |requestData.uri| parameter should be relative URI.
 Check the original PA2 documentation for details about signing the HTTP requests.
 
 The result returned string contains a full value for X-PowerAuth-Authorization header.
 
 If you're going to sign request for a vault key retrieving, then you have to specifiy signature
 factor combined with 'PA2SignatureFactor_PrepareForVaultUnlock' flag. Otherwise the subsequent vault unlock
 operation will calculate wrong transport key (KEY_ENCRYPTION_VAULT_TRANSPORT) and you'll
 not be able to complete the operation.
 
 WARNING
 
 You have to save session's state after the successful operation, due to internal counter change.
 If you don't save the state then you'll sooner or later loose synchronization with the server
 and your client will not be able to sign data anymore.
 
 
 Discussion about thread safety
 
 If your networking infrastructure allows simultaneous HTTP requests then it's recommended to
 guard this method with external locking. There's possible race condition when the internal signing counter
 is raised in persistent data structure. The Session doesn't provide locking internally.
 
 Returns string with autorization header or nil if opeartion failed. The lastErrorCode is updated
 to following values:
	EC_Ok,         if operation succeeded
	EC_Encryption, if some cryptographic operation failed
	EC_WrongState, if the session has no valid activation
	EC_WrongParam, if some required parameter is missing
 */
- (nullable PA2HTTPRequestDataSignature*) signHttpRequestData:(nonnull PA2HTTPRequestData*)requestData
														 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
													   factor:(PA2SignatureFactor)factor;
/**
 Returns name of authorization header. The value is constant and is equal to "X-PowerAuth-Authorization".
 You can calculate appropriate value with using 'httpAuthHeaderValueForBody:...' method.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * httpAuthHeaderName;

/**
 Validates whether the data has been signed with master server private key.
 Returns YES if signature is valid. The lastErrorCode is updated
 to following values:
	 EC_Ok,			if operation succeeded and signature is valid
	 EC_Encryption	if signature is not valid or some cryptographic operation failed
	 EC_WrongState	if session contains invalid setup
	 EC_WrongParam	if signedData object doesn't contain signature
 */
- (BOOL) verifyServerSignedData:(nonnull PA2SignedData*)signedData;

#pragma mark - Signature keys management

/**
 Changes user's password. You have to save session's state to keep this change for later.
 
 The method doesn't perform old password validation and therefore, if the wrong password is provided,
 then the internal knowledge key will be permanently lost. Before calling this method, you have to validate
 old password by calling some server's endpoint, which requires at least knowledge factor for completion.
 
 So, the typical flow for password change has a following steps:
 
 1. ask user for an old password
 2. send HTTP request, signed with knowledge factor, use an old password for key unlock
	- if operation fails, then you can repeat step 1 or exit the flow
 3. ask user for a new password as usual (e.g. ask for passwd for twice, compare both,
	check minimum length, entropy, etc...)
 4. call `changeUserPassword` with old and new password
 5. save session's state
 
 WARNING
 
 All this, is just a preliminary proposal functionality and is not covered by PA2 specification.
 The behavior or a whole flow of password changing may be a subject of change in the future.
 
 Returns YES if operation succeeds or NO in case of failure. The lastErrorCode is updated
 to following values:
	EC_Ok,          if operation succeeded
	EC_Encryption,  if underlying cryptograhic operation did fail or
					if you provided too short passwords.
	EC_WrongState,  if the session has no valid activation
 */
- (BOOL) changeUserPassword:(nonnull PA2Password *)old_password newPassword:(nonnull PA2Password*)new_password;

/**
 Adds a key for biometry factor. You have to provide encrypted vault key |cVaultKey| in Base64 format
 and |unlockKeys| object where the valid possessionUnlockKey is set. The |unlockKeys| also must contain a
 new biometryUnlockKey, which will be used for a protection of the newly created biometry signature key. 
 You should always save session's state after this operation, whether it ends with error or not.
 
 Discussion
 
 The adding a new key for biometry factor is a quite complex task. At first, you need to ask server
 for a vault key and sign this HTTP request with using PA2SignatureFactor_PrepareForVaultUnlock flag 
 in combination with other required factors. The flag guarantees that the internal counter will be correctly raised
 and next subsequent operation for vault key decryption will finish correctly.
 
 If you don't receive response from the server then it's OK to leave the session as is. The session's
 counter is probably at the same value as server's or slightly ahead and therefore everything should
 later work correctly. The session then only display a warning to the debug console about the previous
 pending vault unlock operation.
 
 Returns YES if operation succeeds or NO in case of failure. The lastErrorCode is updated
 to following values:
	 EC_Ok,         if operation succeeded
	 EC_Encryption, if general encryption error occurs
	 EC_WrongState, if the session has no valid activation or
					if you did not sign previous HTTP request with PA2SignatureFactor_PrepareForVaultUnlock flag
	 EC_WrongParam, if some required parameter is missing
 */
- (BOOL) addBiometryFactor:(nonnull NSString *)cVaultKey
					  keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys;

/** Checks if there is a biometry factor present in a current session.
 
 @return YES if there is a biometry factor related key present, NO otherwise.
 */
- (BOOL) hasBiometryFactor;

/**
 Removes existing key for biometric signatures from the session. You have to save state of the session
 after the operation. Returns YES if operation succeeds or NO in case of failure. The lastErrorCode is updated
 to following values:
	EC_Ok,         if operation succeeded
	EC_WrongState, if the session has no valid activation
 */
- (BOOL) removeBiometryFactor;

#pragma mark - Vault operations

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
 
 Retuns NSData object with a derived cryptographic key or nil in case of failure. The lastErrorCode is 
 updated to the following values:
	EC_Ok,			if operation succeeded
	EC_Encryption,	if general encryption error occurs
	EC_WrongState,	if the session has no valid activation or
					if you did not sign previous http request with SF_PrepareForVaultUnlock flag
	EC_WrongParam,	if some required parameter is missing
 */
- (nullable NSData*) deriveCryptographicKeyFromVaultKey:(nonnull NSString*)cVaultKey
												   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											   keyIndex:(UInt64)keyIndex;
/**
 Computes a ECDSA-SHA256 signature of given |data| with using device's private key. You have to provide
 encrypted |cVaultKey| and |unlockKeys| structure with a valid possessionUnlockKey.
 
 Discussion
 
 The session's state contains device private key but it is encrypted with vault key, which is normally not
 available on the device. Just like other vault related operations, you have to properly sign HTTP request
 with using PA2SignatureFactor_PrepareForVaultUnlock flag, otherwise the operation will fail.
 
 Retuns NSData object with calculated signature or nil in case of failure. The lastErrorCode is
 updated to the following values:
	EC_Ok,			if operation succeeded
	EC_Encryption,	if general encryption error occurs
	EC_WrongState,	if the session has no valid activation or
					if you did not sign previous http request with SF_PrepareForVaultUnlock flag
	EC_WrongParam,	if some required parameter is missing
 */
- (nullable NSData*) signDataWithDevicePrivateKey:(nonnull NSString*)cVaultKey
											 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											 data:(nonnull NSData*)data;

#pragma mark - External Encryption Key

/**
 Returns YES if EEK (external encryption key) is set.
 */
@property (nonatomic, assign, readonly) BOOL hasExternalEncryptionKey;

/**
 Sets a known external encryption key to the internal SessionSetup structure. This method
 is useful, when the Session is using EEK, but the key is not known yet. You can restore
 the session without the EEK and use it for a very limited set of operations, like the status
 decode. The data signing will also work correctly, but only for a knowledge factor, which
 is by design not protected with EEK.
 
 Returns YES if operation succeeded or NO in case of failure. The lastErrorCode is
 updated to the following values:
	 EC_Ok			if operation succeeded.
	 EC_WrongParam	if key is already set and new EEK is different, or
					if provided key has invalid length.
	 EC_WrongState	if you're setting key to activated session which doesn't use EEK
 */
- (BOOL) setExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey;

/**
 Adds a new external encryption key permanently to the activated Session and to the internal 
 SessionSetup structure. The method is different than 'setExternalEncryptionKey' and is useful 
 for scenarios, when you need to add the EEK additionally, after the activation.
 
 You have to save state of the session after the operation.
 
 Returns YES if operation succeeded or NO in case of failure. The lastErrorCode is
 updated to the following values:
	EC_Ok			if operation succeeded and session is using EEK for all future operations
	EC_WrongParam	if the EEK has wrong size
	EC_WrongState	if session has no valid activation, or
					if the EEK is already set.
	EC_Encryption	if internal cryptographic operation failed
 */
- (BOOL) addExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey;

/**
 Removes existing external encryption key from the activated Session. The method removes EEK permanently
 and clears internal EEK usage flag from the persistent data. The session has to be activated and EEK
 must be set at the time of call (e.g. 'hasExternalEncryptionKey' returns true).
	
 You have to save state of the session after the operation.
 
 Returns YES if operation succeeded or NO in case of failure. The lastErrorCode is
 updated to the following values:
	EC_Ok			if operation succeeded and session doesn't use EEK anymore
	EC_WrongState	if session has no valid activation, or
					if session has no EEK set
	EC_Encryption	if internal cryptographic operation failed
 */
- (BOOL) removeExternalEncryptionKey;

#pragma mark - E2EE

/**
 Creates a new instace of PA2Encryptor class initialized for nonpersonalized End-To-End Encryption.
 The nonpersonalized mode of E2EE is available after the correct PA2Session object initialization,
 so you can basically use the method anytime during the object's lifetime. The |sessionIndex|
 object must contain a 16 bytes long sequence of bytes. If your application doesn't have mechanism
 for session index creation, then you can use +generateSignatureUnlockKey method for this purpose.
 
 Note that the method doesn't change persistent state of the PA2Session, so you don't need to
 serialize its state after the call.
 
 Returns an PA2Encryptor object if succeeded or nil in case of failure. The lastErrorCode is
 updated to the following values:
	EC_Ok		  if operation succeeded. The returned pointer is valid.
	EC_WrongState if session has no valid setup.
	EC_WrongParam if session_index has wrong size, or
				  if session_index is filled with zeros, or
	EC_Encryption if internal cryptographic operation failed.
 */
- (nullable PA2Encryptor*) nonpersonalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex;

/**
 Creates a new instace of PA2Encryptor class initialized for personalized End-To-End Encryption.
 The personalized mode of E2EE is available only when the session contains valid activation.
 The |sessionIndex| object must contain a 16 bytes long sequence of bytes. If your application doesn't
 have mechanism for session index creation, then you can use +generateSignatureUnlockKey method for
 this purpose.
 The provided |unlockKeys| object must contain valid unlock key for a possession factor.
 
 Note that the method doesn't change persistent state of the PA2Session, so you don't need to
 serialize its state after the call.
 
 Returns an PA2Encryptor object if succeeded or nil in case of failure. The lastErrorCode is
 updated to the following values:
	EC_Ok			if operation succeeded.
	EC_WrongState	if session has no valid activation.
	EC_WrongParam	if session_index has wrong size, or
					if session_index is filled with zeros, or
					if possession unlock key is missing.
	EC_Encryption	if internal cryptographic operation failed.
 */
- (nullable PA2Encryptor*) personalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex
														   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys;

#pragma mark - Utilities for generic keys

/**
 Returns normalized key suitable for a signagure keys protection. The key is computed from
 provided data with using one-way hash function (SHA256)
 
 Discussion
 
 This method is useful for situations, where you have to prepare key for possession factor,
 but your source data is not normalized. For example, WI-FI or UDID doesn't fit to
 requirements for cryptographic key and this function helps derive the key from an input data.
 */
+ (nonnull NSData*) normalizeSignatureUnlockKeyFromData:(nonnull NSData*)data;

/**
 Returns new normalized key usable for a signature keys protection.
 
 Discussion
 
 The method is useful for situations, whenever you need to create a new key which will be
 protected with another, external factor. The best example is when a "biometry" factor is
 involved in the signatures. For this situation, you can generate a new key and save it
 to the storage, protected by the biometric factor.
 
 Internally, method only generates 16 bytes long random data and therefore is also suitable
 for all other situations, when the generated random key is required.
 */
+ (nonnull NSData*) generateSignatureUnlockKey;

@end
