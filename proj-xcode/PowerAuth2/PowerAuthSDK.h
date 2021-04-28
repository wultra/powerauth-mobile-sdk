/**
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

#import <PowerAuth2/PowerAuthActivation.h>
#import <PowerAuth2/PowerAuthActivationResult.h>
#import <PowerAuth2/PowerAuthActivationStatus.h>
#import <PowerAuth2/PowerAuthActivationRecoveryData.h>
#import <PowerAuth2/PowerAuthAuthentication.h>
#import <PowerAuth2/PowerAuthConfiguration.h>
#import <PowerAuth2/PowerAuthClientConfiguration.h>
#import <PowerAuth2/PowerAuthKeychainConfiguration.h>
#import <PowerAuth2/PowerAuthToken.h>
#import <PowerAuth2/PowerAuthToken+WatchSupport.h>
#import <PowerAuth2/PowerAuthAuthorizationHttpHeader.h>
#import <PowerAuth2/PowerAuthSessionStatusProvider.h>
#import <PowerAuth2/PowerAuthOperationTask.h>
// Deprecated
#import <PowerAuth2/PowerAuthDeprecated.h>

// Core classes
@class PowerAuthCoreSession, PowerAuthCoreEciesEncryptor;

@interface PowerAuthSDK : NSObject<PowerAuthSessionStatusProvider>

/** Reference to the low-level PowerAuthCoreSession class.
 
 WARNING
 
 This property is exposed only for the purpose of giving developers full low-level control over the cryptographic algorithm and
 managed activation state. For example, you can call a direct password change method without prior check of the password correctness
 in cooperation with the server API. Be extremely careful when calling any methods of this instance directly. There are very few
 protective mechanisms for keeping the session state actually consistent in the functional (not low level) sense. As a result, you
 may break your activation state (for example, by changing password from incorrect value to some other value).
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthCoreSession *session;

/**
 Instance of configuration, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthConfiguration *configuration;
/**
 Instance of `PowerAuthClientConfiguration` object, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthClientConfiguration *clientConfiguration;
/**
 Instance of `PowerAuthKeychainConfiguration` object, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthKeychainConfiguration *keychainConfiguration;
	
/**
 Instance of the token store object, which provides interface for generating token based authentication headers.
 The current implementation is keeping acquired tokens in the PowerAuthKeychain under the `PowerAuthKeychainConfiguration.keychainInstanceName_TokenStore` service name.
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthTokenStore> tokenStore;

/**
 Creates an instance of SDK and initializes it with given configuration objects.
 
 @param configuration to be used for initialization.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then `PowerAuthKeychainConfiguration.sharedInstance()` is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then `PowerAuthClientConfiguration.sharedInstance()` is used.
 
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
						  keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
							clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration;

/**
 Creates an instance of SDK and initializes it with given configuration.
 The appropriate shared configs are used for object's `clientConfiguration` and `keychainConfiguration` properties.
	 
 @param configuration to be used for initialization.
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration;

/**
 Creates a default shared instance and initializes it with given configuration.
 The appropriate shared configs are used for shared instance's `clientConfiguration` and `keychainConfiguration` properties.
 
 @param configuration to be used for initialization.
 */
+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration;

/**
 Creates a default shared instance and initializes it with given configuration objects.
 
 @param configuration to be used for initialization.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then `PowerAuthKeychainConfiguration.sharedInstance()` is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then `PowerAuthClientConfiguration.sharedInstance()` is used.
 */
+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration
	  keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
		clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration;

/** Return the default shared instance of the PowerAuth SDK.
 
 @return Shared instance of the PowerAuth SDK.
 */
+ (nonnull PowerAuthSDK*) sharedInstance;

/** Restore the PowerAuth session state using the provided configuration.
 
 @return YES if session was restored, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) restoreState;

/**
 Create a new activation.
 
 @param activation A PowerAuthActivation object containg all information required for the activation creation.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) createActivation:(nonnull PowerAuthActivation*)activation
												callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;

/**
 Create a new standard activation with given name and activation code.
 
 @param name Activation name, for example "John's iPhone".
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
												  activationCode:(nonnull NSString*)activationCode
														callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;

/**
 Create a new standard activation with given name, activation code and additional extras information.
 
 @param name Activation name, for example "John's iPhone".
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system).
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
												  activationCode:(nonnull NSString*)activationCode
														  extras:(nullable NSString*)extras
														callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;
/**
 Create a new custom activation with given name and custom activation.
 
 @param name Activation name, for example "John's iPhone".
 @param identityAttributes Custom activation parameters that are used to prove identity of a user.
 @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system).
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
											  identityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
														  extras:(nullable NSString*)extras
														callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;

/**
 Create a new recovery activation with given name, recovery code, puk and additional extras information.
 
 @param name Activation name, for example "John's iPhone".
 @param recoveryCode Recovery code, obtained either via QR code scanning or by manual entry.
 @param puk PUK obtained by manual entry.
 @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system).
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
													recoveryCode:(nonnull NSString*)recoveryCode
															 puk:(nonnull NSString*)puk
														  extras:(nullable NSString*)extras
														callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;

/**
 Commit activation that was created and store related data using provided authentication instance.
 
 @param authentication An authentication instance specifying what factors should be stored.
 @param error Error reference in case some error occurs.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) commitActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
									  error:(NSError * _Nullable * _Nullable)error;

/** Commit activation that was created and store related data using default authentication instance setup with provided password.
 
 Calling this method is equivalent to commitActivationWithAuthentication:error: with authentication object set to use all factors and provided password.
 
 @param password Password to be used for the knowledge related authentication factor.
 @param error Error reference in case some error occurs.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) commitActivationWithPassword:(nonnull NSString*)password
								error:(NSError * _Nullable * _Nullable)error;

/**
 Read only property contains activation identifier or nil if object has no valid activation.
 */
@property (nonatomic, strong, nullable, readonly) NSString *activationIdentifier;

/**
 Read only property contains fingerprint calculated from device's public key or nil if object has no valid activation.
 */
@property (nonatomic, strong, nullable, readonly) NSString *activationFingerprint;


/** Fetch the activation status for current activation.
 
 If server returns custom object, it is returned in the callback as NSDictionary.
 
 @param callback A callback with activation status result - it contains status information in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) fetchActivationStatusWithCallback:(nonnull void(^)(PowerAuthActivationStatus * _Nullable status, NSDictionary * _Nullable customObject, NSError * _Nullable error))callback;

/**
 Read only property contains last activation status object received from the server.
 You have to call `fetchActivationStatus()` method to update this value.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthActivationStatus * lastFetchedActivationStatus;

/**
 Read only property contains last custom object received from the server, together with the activation status.
 Note that the value is optional and PowerAuth Application Server must support this custom object.
 You have to call `fetchActivationStatus()` method to update this value.
 */
@property (nonatomic, strong, nullable, readonly) NSDictionary<NSString*, NSObject*>* lastFetchedCustomObject;


/** Remove current activation by calling a PowerAuth Standard RESTful API endpoint '/pa/activation/remove'.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param callback A callback with activation removal result - in case of an error, an error instance is not 'nil'.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) removeActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
																  callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Removes existing activation from the device.
 
 This method removes the activation session state and biometry factor key. Cached possession related key remains intact.
 Unlike the `removeActivationWithAuthentication`, this method doesn't inform server about activation removal. In this case
 user has to remove the activation by using another channel (typically internet banking, or similar web management console)

 @exception NSException thrown in case configuration is not present.
 */
- (void) removeActivationLocal;

/** Compute the HTTP signature header for GET HTTP method, URI identifier and HTTP query parameters using provided authentication information.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param uriId URI identifier.
 @param params HTTP query params.
 @param error Error reference in case some error occurs.
 @return HTTP header with PowerAuth authorization signature. In case of error, this method return 'nil'.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PowerAuthAuthorizationHttpHeader*) requestGetSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
																			   uriId:(nonnull NSString*)uriId
																			  params:(nullable NSDictionary<NSString*, NSString*>*)params
																			   error:(NSError * _Nullable * _Nullable)error;

/** Compute the HTTP signature header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param method HTTP method used for the signature computation.
 @param uriId URI identifier.
 @param body HTTP request body.
 @param error Error reference in case some error occurs.
 @return HTTP header with PowerAuth authorization signature. In case of error, this method return 'nil'.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PowerAuthAuthorizationHttpHeader*) requestSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
																		   method:(nonnull NSString*)method
																			uriId:(nonnull NSString*)uriId
																			 body:(nullable NSData*)body
																			error:(NSError * _Nullable * _Nullable)error;

/** Compute the offline signature for given HTTP method, URI identifier and HTTP request body using provided authentication information.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request. The possession and knowledge is recommended.
 @param uriId URI identifier.
 @param body HTTP request body.
 @param nonce NONCE in Base64 format.
 @param error Error reference in case some error occurs.
 @return String representing a calculated signature for all involved factors. In case of error, this method return 'nil'.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable NSString*) offlineSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
													uriId:(nonnull NSString*)uriId
													 body:(nullable NSData*)body
													nonce:(nonnull NSString*)nonce
													error:(NSError * _Nullable * _Nullable)error;
/**
 Validates whether the data has been signed with master server private key or personalized server's private key.
 @param data An arbitrary data
 @param signature A signature calculated for data, in Base64 format
 @param masterKey If YES, then master server public key is used for validation, otherwise personalized server's public key.
 */
- (BOOL) verifyServerSignedData:(nonnull NSData*)data
					  signature:(nonnull NSString*)signature
					  masterKey:(BOOL)masterKey;

/** Change the password using local re-encryption, do not validate old password by calling any endpoint.
 
 You are responsible for validating the old password against some server endpoint yourself before using it in this method.
 If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
 existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @return Returns YES in case password was changed without error, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) unsafeChangePasswordFrom:(nonnull NSString*)oldPassword
							   to:(nonnull NSString*)newPassword;

/** Change the password, validate old password by calling a PowerAuth Standard RESTful API endpoint '/pa/signature/validate'.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @param callback The callback method with the password change result.
 @return PowerAuthOperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable id<PowerAuthOperationTask>) changePasswordFrom:(nonnull NSString*)oldPassword
														to:(nonnull NSString*)newPassword
												  callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Regenerate a biometry related factor key.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 
 @param password Password used for authentication during vault unlocking call.
 @param callback The callback method with the biometry key adding operation result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) addBiometryFactor:(nonnull NSString*)password
												 callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Checks if a biometry related factor is present.
 
 This method returns the information about the key value being present in keychain. To check if biometric suppoty is present and enabled on the device, use `PowerAuthKeychain.canUseBiometricAuthentication` property.
 
 @return YES if there is a biometry factor present in the keychain, NO otherwise.
 */
- (BOOL) hasBiometryFactor;

/** Remove the biometry related factor key.
 
 @return YES if the key was successfully removed, NO otherwise.
 */
- (BOOL) removeBiometryFactor;

/** Prepare PowerAuthAuthentication object for future PowerAuth signature calculation with a biometry and possession factors involved.
 
 The method is useful for situations where business processes require compute two or more different PowerAuth biometry signatures in one interaction with the user. To achieve this, the application must acquire the custom-created PowerAuthAuthentication object first and then use it for the required signature calculations. It's recommended to keep this instance referenced only for a limited time, required for all future signature calculations.
  
 Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.
 
 @param prompt A prompt displayed in TouchID or FaceID authentication dialog.
 @param callback A callback with result, always executed on the main thread.
 */
- (void) authenticateUsingBiometryWithPrompt:(nonnull NSString *)prompt
									callback:(nonnull void(^)(PowerAuthAuthentication * _Nullable authentication, NSError * _Nullable error))callback;

/** Unlock all keys stored in a biometry related keychain and keeps them cached for the scope of the block.
 
 There are situations where biometry related keys from different PowerAuthSDK instances are needed in a single business process. For example, when having a master-child activation pair, computing signature in the child activation requires master activation to use vault unlock first and then, after the request is completed, child activation can compute the signature. This would normally trigger biometry dialog twice. To avoid that, all biometry related keys are fetched at once and cached for a limited amount of time.
 */
- (void) unlockBiometryKeysWithPrompt:(nonnull NSString*)prompt
							withBlock:(nonnull void(^)(NSDictionary<NSString*, NSData*> * _Nullable keys, BOOL userCanceled))block;

/** Generate an derived encryption key with given index.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for subsequent key derivation using given index.
 
 @param authentication Authentication used for vault unlocking call.
 @param index Index of the derived key using KDF.
 @param callback The callback method with the derived encryption key.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) fetchEncryptionKey:(nonnull PowerAuthAuthentication*)authentication
													 index:(UInt64)index
												  callback:(nonnull void(^)(NSData * _Nullable encryptionKey, NSError * _Nullable error))callback;

/** Sign given data with the original device private key (asymetric signature).
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for private key decryption. Data is then signed using ECDSA algorithm with this key and can be validated on the server side.
 
 @param authentication Authentication used for vault unlocking call.
 @param data Data to be signed with the private key.
 @param callback The callback method with the data signature.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) signDataWithDevicePrivateKey:(nonnull PowerAuthAuthentication*)authentication
																data:(nullable NSData*)data
															callback:(nonnull void(^)(NSData * _Nullable signature, NSError * _Nullable error))callback;

/** Validate a user password.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/signature/validate' to validate the signature value.
 
 @param password Password to be verified.
 @param callback The callback method with error associated with the password validation.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) validatePasswordCorrect:(nonnull NSString*)password
													   callback:(nonnull void(^)(NSError * _Nullable error))callback;

@end


#pragma mark - End-2-End Encryption

@interface PowerAuthSDK (E2EE)

/**
 Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes. The returned encryptor is
 cryptographically bounded to the PowerAuth configuration, so it can be used with or without a valid activation. The encryptor also contains
 an associated `PowerAuthCoreEciesMetaData` object, allowing you to properly setup HTTP header for the request.
 
 @return New instance of `PowerAuthCoreEciesEncryptor` object or nil if `PowerAuthConfiguration` contains an invalid data.
 */
- (nullable PowerAuthCoreEciesEncryptor*) eciesEncryptorForApplicationScope;

/**
 Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes. The returned encryptor is
 cryptographically bounded to a device's activation, so it can be used only when this instance has a valid activation. The encryptor also contains
 an associated `PowerAuthCoreEciesMetaData` object, allowing you to properly setup HTTP header for the request.
 
 Note that the created encryptor has no reference to this instance of `PowerAuthSDK`. This means that if the `PowerAuthSDK` will loose its
 activation in future, then the encryptor will still be capable to encrypt, or decrypt the data. This is an expected behavior, so if you
 plan to keep the encryptor for multiple requests, then it's up to you to release its instance after you change the state of PowerAuthSDK.
 
 @return New instance of `PowerAuthCoreEciesEncryptor` object or nil if there's no valid activation.
 */
- (nullable PowerAuthCoreEciesEncryptor*) eciesEncryptorForActivationScope;

@end

// -----------------------------------------------------------------------
#if defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------
#pragma mark - Apple Watch support

/**
 The WatchSupport category provides simple interface for sending activation status to paired Apple Watch.
 Please read our integration guide (https://github.com/wultra/powerauth-mobile-sdk/docs/PowerAuth-SDK-for-watchOS.md)
 before you start using this interface in your application.
 */
@interface PowerAuthSDK (WatchSupport)

/**
 Sends activation status of this PowerAuthSDK instance to the paired Apple Watch. The watch application must
 be installed on the device. The status transmission is performed with using `WCSession.transferUserInfo()` method,
 so it will be available when IOS decide to transfer that data to the Apple Watch.
 
 Returns YES if transfer has been properly sheduled, or NO if WCSession is not ready for
 such transmission. Check `PowerAuthWCSessionManager.validSession` documentation for details.
 */
- (BOOL) sendActivationStatusToWatch;

/**
 Sends activation status of this PowerAuthSDK instance to the paired Apple Watch. The watch application must
 be installed on the device. The status transmission is performed immediately with using `WCSession.sendMessageData(..)` method,
 so the Apple Watch has to be reachable in the time of the call.
 */
- (void) sendActivationStatusToWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion;

@end
// -----------------------------------------------------------------------
#endif // defined(PA2_WATCH_SUPPORT)
// -----------------------------------------------------------------------

#pragma mark - Request synchronization

@interface PowerAuthSDK (RequestSync)

/**
 Executes provided block on an internal, serialized operation queue. This gives application an opportunity to serialize
 its own signed HTTP requests, with requests created in the SDK internally.
 
 @b Why this matters
 
 The PowerAuth SDK is using that executor for serialization of signed HTTP requests, to guarantee, that only one request is processed
 at the time. The PowerAuth signatures are based on a logical counter, so this technique makes that all requests are delivered
 to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
 them with the SDK.
 
 @b Recommended practices
 
 1)  You should calculate PowerAuth signature from the execute block method.
 
 2)  You have to always call `task.cancel()` on provided `PowerAuthOperationTask` object once the operation is finished,
     otherwise the seriali queue will be blocked indefinitely.

 @param execute Block to be executed in the serialized queue.
 @return Cancelable operation task, or nil if there's no activation.
 */
- (nullable id<PowerAuthOperationTask>) executeBlockOnSerialQueue:(void(^ _Nonnull)(id<PowerAuthOperationTask> _Nonnull task))execute;

/**
 Executes provided operation on an internal, serialized operation queue. This gives application an opportunity to serialize
 its own signed HTTP requests, with requests created in the SDK internally.
 
 @b Why this matters
 
 The PowerAuth SDK is using that executor for serialization of signed HTTP requests, to guarantee, that only one request is processed
 at the time. The PowerAuth signatures are based on a logical counter, so this technique makes that all requests are delivered
 to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
 them with the SDK.
 
 @b Recommended practices
 
 You should calculate PowerAuth signature after the operation is started. If you calculate the signature before and after that you add
 that operation to the queue, the logical counter may not be synchronized properly.
 
 

 @param operation Operation to be executed in the serialized queue
 @return YES if operation was added to the queue, or NO if there's no activation.
 */
- (BOOL) executeOperationOnSerialQueue:(nonnull NSOperation *)operation;

@end


#pragma mark - Recovery code

@interface PowerAuthSDK (RecoveryCode)

/**
 Returns YES if underlying session contains an activation recovery data.
 */
- (BOOL) hasActivationRecoveryData;

/**
 Get an activation recovery data.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for private recovery data decryption.
 
 @param authentication Authentication used for vault unlocking call.
 @param callback The callback method with an activation recovery information.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) activationRecoveryData:(nonnull PowerAuthAuthentication*)authentication
													  callback:(nonnull void(^)(PowerAuthActivationRecoveryData * _Nullable recoveryData, NSError * _Nullable error))callback;

/**
 Confirm given recovery code on the server.
 
 The method is useful for situations when user receives a recovery information via OOB channel (for example via postcard). Such
 recovery codes cannot be used without a proper confirmation on the server. To confirm codes, user has to authenticate himself
 with a knowledge factor.
 
 Note that the provided recovery code can contain a `"R:"` prefix, if it's scanned from QR code.
 
 @param recoveryCode Recovery code to confirm
 @param authentication Authentication used for recovery code confirmation
 @param callback The callback method with activation recovery information. 
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) confirmRecoveryCode:(nonnull NSString*)recoveryCode
											 authentication:(nonnull PowerAuthAuthentication*)authentication
												   callback:(nonnull void(^)(BOOL alreadyConfirmed, NSError * _Nullable error))callback;

@end
