/**
 * Copyright 2016 Wultra s.r.o.
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

#import "PowerAuthAuthentication.h"
#import "PowerAuthConfiguration.h"
#import "PowerAuthToken+WatchSupport.h"

#import "PA2Session.h"
#import "PA2EncryptorFactory.h"
#import "PA2ActivationResult.h"
#import "PA2OperationTask.h"
#import "PA2AuthorizationHttpHeader.h"

@class PA2ClientConfiguration, PA2KeychainConfiguration;

@interface PowerAuthSDK : NSObject<PA2SessionStatusProvider>

/** Reference to the low-level PA2Session class.
 
 WARNING
 
 This property is exposed only for the purpose of giving developers full low-level control over the cryptographic algorithm and
 managed activation state. For example, you can call a direct password change method without prior check of the password correctness
 in cooperation with the server API. Be extremely careful when calling any methods of this instance directly. There are very few
 protective mechanisms for keeping the session state actually consistent in the functional (not low level) sense. As a result, you
 may break your activation state (for example, by changing password from incorrect value to some other value).
 */
@property (nonatomic, strong, nonnull, readonly) PA2Session *session;

/** Instance of the encryptor factory, useful for implementing use-cases that leverage end-to-end encryption.
 */
@property (nonatomic, strong, nonnull, readonly) PA2EncryptorFactory *encryptorFactory;
/**
 Instance of configuration, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthConfiguration *configuration;
/**
 Instance of `PA2ClientConfiguration` object, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PA2ClientConfiguration *clientConfiguration;
/**
 Instance of `PA2KeychainConfiguration` object, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PA2KeychainConfiguration *keychainConfiguration;
	
/**
 Instance of the token store object, which provides interface for generating token based authentication headers.
 The current implementation is keeping acquired tokens in the PA2Keychain under the `PA2KeychainConfiguration.keychainInstanceName_TokenStore` service name.
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthTokenStore> tokenStore;

/**
 Creates an instance of SDK and initializes it with given configuration objects.
 
 @param configuration to be used for initialization.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then `PA2KeychainConfiguration.sharedInstance()` is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then `PA2ClientConfiguration.sharedInstance()` is used.
 
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
						  keychainConfiguration:(nullable PA2KeychainConfiguration *)keychainConfiguration
							clientConfiguration:(nullable PA2ClientConfiguration *)clientConfiguration;

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
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then `PA2KeychainConfiguration.sharedInstance()` is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then `PA2ClientConfiguration.sharedInstance()` is used.
 */
+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration
	  keychainConfiguration:(nullable PA2KeychainConfiguration *)keychainConfiguration
		clientConfiguration:(nullable PA2ClientConfiguration *)clientConfiguration;

/** Return the default shared instance of the PowerAuth SDK.
 
 @return Shared instance of the PowerAuth SDK.
 */
+ (nonnull PowerAuthSDK*) sharedInstance;

/** Restore the PowerAuth session state using the provided configuration.
 
 @return YES if session was restored, NO otherwise.
 @exception NSException thrown in case configuration is not present.
 */
- (BOOL) restoreState;

/** Create a new activation with given name and activation code by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/activation/create'.
 
 @param name Activation name, for example "John's iPhone".
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) createActivationWithName:(nullable NSString*)name
										 activationCode:(nonnull NSString*)activationCode
											   callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback;

/** Create a new activation with given name and activation code by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/activation/create'.
 
 @param name Activation name, for example "John's iPhone".
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system).
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) createActivationWithName:(nullable NSString*)name
										 activationCode:(nonnull NSString*)activationCode
												 extras:(nullable NSString*)extras
											   callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback;

/** Create a new activation with given name and custom activation data by calling a custom RESTful API endpoint.
 
 @param name Activation name, for example "John's iPhone".
 @param identityAttributes Custom activation parameters that are used to prove identity of a user.
 @param customSecret Custom OTP used for additional device public key AES encryption.
 @param extras Extra attributes of the activation, used for application specific purposes (for example, info about the client device or system).
 @param customAttributes Custom attributes, that are not related to identity but still need to be sent along with the request.
 @param url Absolute URL to be called with the encrypted activation payload.
 @param httpHeaders HTTP headers used in the server call.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) createActivationWithName:(nullable NSString*)name
									 identityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
										   customSecret:(nonnull NSString*)customSecret
												 extras:(nullable NSString*)extras
									   customAttributes:(nullable NSDictionary<NSString*,NSString*>*)customAttributes
													url:(nonnull NSURL*)url
											httpHeaders:(nullable NSDictionary*)httpHeaders
											   callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback PA2_DEPRECATED(0.19.3);

/** Create a new activation with given name and custom activation data by calling a custom RESTful API endpoint.
 
 @param name Activation name, for example "John's iPhone".
 @param identityAttributes Custom activation parameters that are used to prove identity of a user.
 @param url Absolute URL to be called with the encrypted activation payload.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PA2OperationTask associated with the running request.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) createActivationWithName:(nullable NSString*)name
									 identityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
													url:(nonnull NSURL*)url
											   callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback PA2_DEPRECATED(0.19.3);

/** Commit activation that was created and store related data using provided authentication instance.
 
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
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) fetchActivationStatusWithCallback:(nonnull void(^)(PA2ActivationStatus * _Nullable status, NSDictionary * _Nullable customObject, NSError * _Nullable error))callback;

/** Remove current activation by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/activation/remove'.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param callback A callback with activation removal result - in case of an error, an error instance is not 'nil'.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) removeActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
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
- (nullable PA2AuthorizationHttpHeader*) requestGetSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
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
- (nullable PA2AuthorizationHttpHeader*) requestSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
																	 method:(nonnull NSString*)method
																	  uriId:(nonnull NSString*)uriId
																	   body:(nullable NSData*)body
																	  error:(NSError * _Nullable * _Nullable)error;

/** Compute the HTTP signature header with vault unlock flag for given HTTP method, URI identifier and HTTP request body using provided authentication information.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param vaultUnlock A flag indicating this request is associcate with vault unlock operation.
 @param method HTTP method used for the signature computation.
 @param uriId URI identifier.
 @param body HTTP request body.
 @param error Error reference in case some error occurs.
 @return HTTP header with PowerAuth authorization signature. In case of error, this method return 'nil'.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2AuthorizationHttpHeader*) requestSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
																vaultUnlock:(BOOL)vaultUnlock
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

/** Change the password, validate old password by calling a PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock'.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @param callback The callback method with the password change result.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 @exception NSException thrown in case configuration is not present.
 */
- (nullable PA2OperationTask*) changePasswordFrom:(nonnull NSString*)oldPassword
											   to:(nonnull NSString*)newPassword
										 callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Regenerate a biometry related factor key.
 
 This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 
 @param password Password used for authentication during vault unlocking call.
 @param callback The callback method with the biometry key adding operation result.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 */
- (nullable PA2OperationTask*) addBiometryFactor:(nonnull NSString*)password
										callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Checks if a biometry related factor is present.
 
 This method returns the information about the key value being present in keychain. To check if biometric suppoty is present and enabled on the device, use `PA2Keychain.canUseBiometricAuthentication` property.
 
 @return YES if there is a biometry factor present in the keychain, NO otherwise.
 */
- (BOOL) hasBiometryFactor;

/** Remove the biometry related factor key.
 
 @return YES if the key was successfully removed, NO otherwise.
 */
- (BOOL) removeBiometryFactor;

/** Unlock all keys stored in a biometry related keychain and keeps them cached for the scope of the block.
 
 There are situations where biometry related keys from different PowerAuthSDK instances are needed in a single business process. For example, when having a master-child activation pair, computing signature in the child activation requires master activation to use vault unlock first and then, after the request is completed, child activation can compute the signature. This would normally trigger Touch ID twice. To avoid that, all Touch ID related keys are fetched at once and cached for a limited amount of time.
 */
- (void) unlockBiometryKeysWithPrompt:(nonnull NSString*)prompt withBlock:(nonnull void(^)(NSDictionary<NSString*, NSData*> * _Nullable keys, bool userCanceled))block;

/** Generate an derived encryption key with given index.
 
 This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for subsequent key derivation using given index.
 
 @param authentication Authentication used for vault unlocking call.
 @param index Index of the derived key using KDF.
 @param callback The callback method with the derived encryption key.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 */
- (nullable PA2OperationTask*) fetchEncryptionKey:(nonnull PowerAuthAuthentication*)authentication
											index:(UInt64)index
										 callback:(nonnull void(^)(NSData * _Nullable encryptionKey, NSError * _Nullable error))callback;

/** Sign given data with the original device private key (asymetric signature).
 
 This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for private key decryption. Data is then signed using ECDSA algorithm with this key and can be validated on the server side.
 
 @param authentication Authentication used for vault unlocking call.
 @param data Data to be signed with the private key.
 @param callback The callback method with the data signature.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 */
- (nullable PA2OperationTask*) signDataWithDevicePrivateKey:(nonnull PowerAuthAuthentication*)authentication
													   data:(nullable NSData*)data
												   callback:(nonnull void(^)(NSData * _Nullable signature, NSError * _Nullable error))callback;

/** Validate a user password.
 
 This method calls PowerAuth 2.0 Standard RESTful API endpoint '/pa/vault/unlock' to validate the signature value.
 
 @param password Password to be verified.
 @param callback The callback method with error associated with the password validation.
 @return PA2OperationTask associated with the running request or nil when task was not created.
 */
- (nullable PA2OperationTask*) validatePasswordCorrect:(nonnull NSString*)password
											  callback:(nonnull void(^)(NSError * _Nullable error))callback;

@end



#pragma mark - Apple Watch support

/**
 The WatchSupport category provides simple interface for sending activation status to paired Apple Watch.
 Please read our integration guide (https://github.com/wultra/powerauth-mobile-sdk/wiki/PowerAuth-SDK-for-watchOS)
 before you start using this interface in your application.
 */
@interface PowerAuthSDK (WatchSupport)

/**
 Sends activation status of this PowerAuthSDK instance to the paired Apple Watch. The watch application must
 be installed on the device. The status transmission is performed with using `WCSession.transferUserInfo()` method,
 so it will be available when IOS decide to transfer that data to the Apple Watch.
 
 Returns YES if transfer has been properly sheduled, or NO if WCSession is not ready for
 such transmission. Check `PA2WCSessionManager.validSession` documentation for details.
 */
- (BOOL) sendActivationStatusToWatch;

/**
 Sends activation status of this PowerAuthSDK instance to the paired Apple Watch. The watch application must
 be installed on the device. The status transmission is performed immediately with using `WCSession.sendMessageData(..)` method,
 so the Apple Watch has to be reachable in the time of the call.
 */
- (void) sendActivationStatusToWatchWithCompletion:(void(^ _Nonnull)(NSError * _Nullable error))completion;

@end

