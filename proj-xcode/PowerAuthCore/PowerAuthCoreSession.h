/*
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>

@interface PowerAuthCoreSession : NSObject

#pragma mark -  Initialization / Reset

/**
 The designated initializer. You have to provide a valid PowerAuthCoreSessionSetup object.
 */
- (nullable instancetype) initWithSessionSetup:(nonnull PowerAuthCoreSessionSetup *)setup;

/**
 Resets session into its initial state. The existing session's setup and EEK is preserved
 after the call.
 */
- (void) resetSession;

/**
 Returns YES if PowerAuthCore library was compiled with a debug features. It is highly recommended
 to check this flag and force application to crash if the producion, final application
 is running against the debug featured library.
 */
+ (BOOL) hasDebugFeatures;


/**
 Returns pointer to an internal SessionSetup object. Returns nil if
 session has no valid setup.
 
 Note that internal implementation always creates a new instance of PowerAuthCoreSessionSetup object.
 If you want to get just a sessionIdentifier, then you can use the dedicated read only
 property, which is much faster than accessing the whole setup object.
 */
@property (nonatomic, strong, readonly, nullable) PowerAuthCoreSessionSetup * sessionSetup;

/**
 Returns value of [self sessionSetup].sessionIdentifier if the setup object is present or 0 if not.
 */
@property (nonatomic, assign, readonly) UInt32 sessionIdentifier;


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
/**
 Checks if there's a valid activation that requires a protocol upgrade. Contains NO once the upgrade
 process is started. The application should fetch the activation's status to do the upgrade.
 */
@property (nonatomic, assign, readonly) BOOL hasProtocolUpgradeAvailable;
/**
 Contains YES if the session has pending upgrade to newer protocol version.
 Some operations may be temporarily blocked during the upgrade process.
 */
@property (nonatomic, assign, readonly) BOOL hasPendingProtocolUpgrade;
/**
 Contains version of protocol in which the session currently operates. If session has no activation,
 then the most up to date version is returned.
 */
@property (nonatomic, assign, readonly) PowerAuthCoreProtocolVersion protocolVersion;


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
 
 Returns YES if operation succeeds. In case of faulure, you can determine the failure reason from
 DEBUG log.
 */
- (BOOL) deserializeState:(nonnull NSData *)state;


#pragma mark - Activation

/**
 If the session has valid activation, then returns the activation identifier.
 Otherwise returns nil.
 */
@property (nonatomic, strong, readonly, nullable) NSString * activationIdentifier;

/**
 If the session has valid activation, then returns decimalized fingerprint, calculated
 from device's public key. Otherwise returns nil.
 */
@property (nonatomic, strong, readonly, nullable) NSString * activationFingerprint;

/**
 Starts a new activation process. The session must have valid setup. Once the activation 
 is started you have to complete whole activation sequence or reset a whole session.
 
 You have to provide PowerAuthCoreActivationStep1Param object with all required properties available.
 The result of the operation returned in the PowerAuthCoreActivationStep1Result object. If the
 returned value is nil, then the error occured.
 
 You can determine the failure reason from DEBUG log:
	EC_Encryption, if you provided invalid Base64 strings or if signature is invalid
	EC_WrongState, if called in wrong session's state
	EC_WrongParam, if some required parameter is missing
 */
- (nullable PowerAuthCoreActivationStep1Result*) startActivation:(nonnull PowerAuthCoreActivationStep1Param*)param;

/**
 Validates activation respose received from the server. The session expects that the activation
 process was previously started with using 'startActivation' method. You have to provide 
 PowerAuthCoreActivationStep2Param object with all members filled with the response. The result of the
 operation is stored in the PowerAuthCoreActivationStep2Result object. If the response is correct then
 you can call 'completeActivation' and finish the activation process.
 
 Discussion
 
 If the operation succeeds then the PowerAuth handshake is from a network communication point of view
 considered as complete. The server knows our client and both sides have calculated shared
 secret key. Because of the complexity of the operation, there's one more separate step in our
 activation flow, which finally protects all sensitive information with user password and
 other local keys. This last step is offline only, no data is transmitted over the network
 and therefore if you don't complete the activation (you can reset session for example)
 then the server will keep its part of shared secret but nobody will be able to use that
 estabilished context.
 
 If the returned value is nil, then the error occured. You can determine the failure reason from
 DEBUG log:
	EC_Encryption, if provided data, signature or keys are invalid.
				   If this error occurs then the session resets its state.
	EC_WrongState, if called in wrong session's state
	EC_WrongParam, if required parameter is missing
 */
- (nullable PowerAuthCoreActivationStep2Result*) validateActivationResponse:(nonnull PowerAuthCoreActivationStep2Param*)param;

/**
 Completes previously started activation process and protects sensitive local information with
 provided protection keys. Please check the documentation for PowerAuthCoreSignatureUnlockKeys object
 for details about constructing protection keys and for other related information.
 
 You have to provide at least keys.userPassword and keys.possessionUnlockKey to pass the method's
 input validation. After the activation is complete, you can finally save session's state
 into the persistent storage.
 
 WARNING: You have to save session's staate when the activation is completed!
 
 Returns YES if operation succeeds. In case of faulure, you can determine the failure reason from
 DEBUG log:
	EC_Encryption,  if some internal encryption failed
					if this error occurs, then the session resets its state
	EC_WrongState,  if called in wrong session's state
	EC_WrongParam,  if required parameter is missing
 */
- (BOOL) completeActivation:(nonnull PowerAuthCoreSignatureUnlockKeys*)keys;


#pragma mark - Activation Status

/**
 The method decodes received status blob into PowerAuthCoreActivationStatus object. You can call this method after successful
 activation and obtain information about pairing between the client and server. You have to provide valid
 possessionUnlockKey in the unlockKeys object.
 
 If the returned object is nil then the error occured and you can determine the failure reason from
 DEBUG log.
 */
- (nullable PowerAuthCoreActivationStatus*) decodeActivationStatus:(nonnull PowerAuthCoreEncryptedActivationStatus *)encryptedStatus
															  keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys;

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
 Check the original PowerAuth documentation for details about signing the HTTP requests.
 
 The result returned string contains a full value for X-PowerAuth-Authorization header.
 
 WARNING
 
 You have to save session's state after the successful operation, due to internal counter change.
 If you don't save the state then you'll sooner or later loose synchronization with the server
 and your client will not be able to sign data anymore.
 
 Returns string with autorization header or nil if opeartion failed. You can determine the failure reason from
 DEBUG log:
	EC_Encryption, if some cryptographic operation failed
	EC_WrongState, if the session has no valid activation
	EC_WrongParam, if some required parameter is missing
 */
- (nullable PowerAuthCoreHTTPRequestDataSignature*) signHttpRequestData:(nonnull PowerAuthCoreHTTPRequestData*)requestData
																   keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
																 factor:(PowerAuthCoreSignatureFactor)factor;
/**
 Returns name of authorization header. The value is constant and is equal to "X-PowerAuth-Authorization".
 You can calculate appropriate value with using 'httpAuthHeaderValueForBody:...' method.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * httpAuthHeaderName;

/**
 Validates whether the data has been signed with master server private key.
 Returns YES if signature is valid. In case of error, you can determine the failure reason from
 DEBUG log:
	 EC_Encryption	if signature is not valid or some cryptographic operation failed
	 EC_WrongState	if session contains invalid setup
	 EC_WrongParam	if signedData object doesn't contain signature
 */
- (BOOL) verifyServerSignedData:(nonnull PowerAuthCoreSignedData*)signedData;

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
 
 All this, is just a preliminary proposal functionality and is not covered by PowerAuth specification.
 The behavior or a whole flow of password changing may be a subject of change in the future.
 
 Returns YES if operation succeeds or NO in case of failure. You can determine the failure reason from
 DEBUG log:
	EC_Encryption,  if underlying cryptograhic operation did fail or
					if you provided too short passwords.
	EC_WrongState,  if the session has no valid activation
 */
- (BOOL) changeUserPassword:(nonnull PowerAuthCorePassword *)old_password newPassword:(nonnull PowerAuthCorePassword*)new_password;

/**
 Adds a key for biometry factor. You have to provide encrypted vault key |cVaultKey| in Base64 format
 and |unlockKeys| object where the valid possessionUnlockKey is set. The |unlockKeys| also must contain a
 new biometryUnlockKey, which will be used for a protection of the newly created biometry signature key. 
 You should always save session's state after this operation, whether it ends with error or not.
 
 Returns YES if operation succeeds or NO in case of failure. You can determine the failure reason from
 DEBUG log:
	 EC_Encryption, if general encryption error occurs
	 EC_WrongState, if the session has no valid activation
	 EC_WrongParam, if some required parameter is missing
 */
- (BOOL) addBiometryFactor:(nonnull NSString *)cVaultKey
					  keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys;

/** Checks if there is a biometry factor present in a current session.
 
 @return YES if there is a biometry factor related key present, NO otherwise.
 */
- (BOOL) hasBiometryFactor;

/**
 Removes existing key for biometric signatures from the session. You have to save state of the session
 after the operation. Returns YES if operation succeeds or NO in case of failure. You can determine
 the failure reason from DEBUG log:
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
 
 Retuns NSData object with a derived cryptographic key or nil in case of failure. You can determine
 the failure reason from DEBUG log:
	EC_Encryption,	if general encryption error occurs
	EC_WrongState,	if the session has no valid activation
	EC_WrongParam,	if some required parameter is missing
 */
- (nullable NSData*) deriveCryptographicKeyFromVaultKey:(nonnull NSString*)cVaultKey
												   keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
											   keyIndex:(UInt64)keyIndex;
/**
 Computes a ECDSA-SHA256 signature of given |data| with using device's private key. You have to provide
 encrypted |cVaultKey| and |unlockKeys| structure with a valid possessionUnlockKey.
 
 Discussion
 
 The session's state contains device private key but it is encrypted with vault key, which is normally not
 available on the device.
 
 Retuns NSData object with calculated signature or nil in case of failure. You can determine the failure
 reason from DEBUG log:
	EC_Encryption,	if general encryption error occurs
	EC_WrongState,	if the session has no valid activation
	EC_WrongParam,	if some required parameter is missing
 */
- (nullable NSData*) signDataWithDevicePrivateKey:(nonnull NSString*)cVaultKey
											 keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
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
 
 Returns YES if operation succeeded or NO in case of failure. You can determine the failure
 reason from DEBUG log:
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
 
 Returns YES if operation succeeded or NO in case of failure. You can determine the failure
 reason from DEBUG log:
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
 
 Returns YES if operation succeeded or NO in case of failure. You can determine the failure
 reason from DEBUG log:
	EC_WrongState	if session has no valid activation, or
					if session has no EEK set
	EC_Encryption	if internal cryptographic operation failed
 */
- (BOOL) removeExternalEncryptionKey;

#pragma mark - ECIES

/**
 Constructs the `PowerAuthCoreEciesEncryptor` object for the required `scope` and for optional `sharedInfo1`.
 The `keys` parameter must contain valid `possessionUnlockKey` in case that the "activation" scope is requested.
 For "application" scope, the `keys` object may be nil.
 */
- (nullable PowerAuthCoreEciesEncryptor*) eciesEncryptorForScope:(PowerAuthCoreEciesEncryptorScope)scope
															keys:(nullable PowerAuthCoreSignatureUnlockKeys*)unlockKeys
													 sharedInfo1:(nullable NSData*)sharedInfo1;

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

/**
 Returns new challenge for getting activation status.
 
 Internally, method only generates 16 bytes long random data encoded to Base64 and therefore
 is also suitable for all other situations, when the generated random key is required.
 */
- (nonnull NSString*) generateActivationStatusChallenge;


#pragma mark - Protocol upgrade

/**
 Formally starts the protocol upgrade to a newer version. The function only sets flag
 indicating that upgrade is in progress. You should serialize an activation status
 after this call.
 
 Returns YES if upgrade has been started.
 */
- (BOOL) startProtocolUpgrade;

/**
 Determines which version of the protocol is the session being upgraded to.
 
 Retuns protocol version or `PowerAuthCoreProtocolVersion_NA` if there's no upgrade, or session
 has no activation.
 */
@property (nonatomic, assign, readonly) PowerAuthCoreProtocolVersion pendingProtocolUpgradeVersion;

/**
 Applies upgrade data to the session. The version of data is determined by the
 object you provide. Currently, only `PowerAuthCoreProtocolUpgradeDataV3` is supported.
 
 Returns YES if session has been successfully upgraded.
 */
- (BOOL) applyProtocolUpgradeData:(nonnull id<PowerAuthCoreProtocolUpgradeData>)upgradeData;


/**
 Formally ends the protocol upgrade. The function resets flag indicating that upgrade
 to the next protocol version is in progress. The reset is possible only if the upgrade
 was successful (e.g. when upgrading to V3, the protocol version is now V3)
 
 You should serialize an activation status ater this call.
 
 Returns YES if upgrade has been finished successfully.
 */
- (BOOL) finishProtocolUpgrade;

/**
 Returns textual representation for given protocol version. For example, for `PowerAuthCoreProtocolVersion_V3`
 returns "3.1". You can use `PowerAuthCoreProtocolVersion_NA` to get the lastest supported version.
 */
+ (nonnull NSString*) maxSupportedHttpProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion;


#pragma mark - Recovery codes

/**
 Returns YES, if session contains an activation recovery data.
 */
@property (nonatomic, assign, readonly) BOOL hasActivationRecoveryData;

/**
 Returns an activation recovery data. You have to provide encrypted vault key |c_vault_key| and
 |keys| structure where the valid possessionUnlockKey is set.
 */
- (nullable PowerAuthCoreRecoveryData*) activationRecoveryData:(nonnull NSString*)cVaultKey
														  keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys;

@end
