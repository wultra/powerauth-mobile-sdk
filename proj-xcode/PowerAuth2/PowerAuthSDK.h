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
#import <PowerAuth2/PowerAuthProtocolUpgradeResult.h>
#import <PowerAuth2/PowerAuthAuthentication.h>
#import <PowerAuth2/PowerAuthConfiguration.h>
#import <PowerAuth2/PowerAuthClientConfiguration.h>
#import <PowerAuth2/PowerAuthBiometricConfiguration.h>
#import <PowerAuth2/PowerAuthKeychainConfiguration.h>
#import <PowerAuth2/PowerAuthBiometricStatus.h>
#import <PowerAuth2/PowerAuthToken.h>
#import <PowerAuth2/PowerAuthToken+WatchSupport.h>
#import <PowerAuth2/PowerAuthHttpHeader.h>
#import <PowerAuth2/PowerAuthCoreSessionProvider.h>
#import <PowerAuth2/PowerAuthTimeSynchronizationService.h>
#import <PowerAuth2/PowerAuthExternalPendingOperation.h>
#import <PowerAuth2/PowerAuthUserInfo.h>
#import <PowerAuth2/PowerAuthServerStatus.h>
#import <PowerAuth2/PowerAuthSecureVaultKey.h>
#import <PowerAuth2/PowerAuthSignatureTypes.h>
#import <PowerAuth2/PowerAuthPasswordChangeData.h>

// Deprecated
#import <PowerAuth2/PowerAuthDeprecated.h>

// Core classes
@class PowerAuthCoreSession, PowerAuthCorePassword, PowerAuthCoreData, PowerAuthCoreCredentials;
@class PowerAuthCoreEncryptor, PowerAuthCoreEncryptorFactory;

@interface PowerAuthSDK : NSObject<PowerAuthSessionStatusProvider>

/** Reference to an object that provides the low-level PowerAuthCoreSession class.
 
 WARNING
 
 This property is exposed solely for SDK testing purposes. The API defined in the provider may change
 without further notice and may not be mentioned in the release notes or migration guide.
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthCoreSessionProvider> sessionProvider;

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
 Instance of `PowerAuthBiometricConfiguration` object, provided during the object initialization.
 
 Note that the copy of internal object is always returned and thus making changes to the returned object
 doesn't affect this SDK instance.
 */
@property (nonatomic, strong, nonnull, readonly) PowerAuthBiometricConfiguration *biometricConfiguration;
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
 Object providing functions to synchronize time with the server. The time is automatically synchronized with the server
 */
@property (nonatomic, strong, nonnull, readonly) id<PowerAuthTimeSynchronizationService> timeSynchronizationService;

/// Contains current algorithm. If PowerAuthSDK has no activation, then algorithm is equal to algorithm provided in the configuration.
@property (nonatomic, readonly) PowerAuthAlgorithm currentAlgorithm;

/**
 Constructor with no parameters is not available.
 */
- (instancetype _Null_unspecified) init NS_UNAVAILABLE;

/**
 Creates an instance of SDK and initializes it with given configuration objects.
 
 @param configuration to be used for initialization.
 @param biometricConfiguration to be used for biometric configuration. If nil is provided, then the default configuration is applied.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then the default configuration is applied.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then the default configuration is applied.
 @param error Pointer where initialization error is set.
 
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                         biometricConfiguration:(nullable PowerAuthBiometricConfiguration *)biometricConfiguration
                            clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
                          keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                                          error:(NSError*_Nullable*_Nullable)error;

/**
 Creates an instance of SDK and initializes it with given configuration objects.
 
 @param configuration to be used for initialization.
 @param biometricConfiguration to be used for biometric configuration. If nil is provided, then the default configuration is applied.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then the default configuration is applied.
 @param error Pointer where initialization error is set.
 
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                         biometricConfiguration:(nullable PowerAuthBiometricConfiguration *)biometricConfiguration
                            clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
                                          error:(NSError*_Nullable*_Nullable)error;
/**
 Creates an instance of SDK and initializes it with given configuration.
 The default configs are used for object's biometric, keychain and client configurations.
     
 @param configuration to be used for initialization.
 @param error Pointer where initialization error is set.
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                                          error:(NSError*_Nullable*_Nullable)error;

/// Erases local data associated with the `PowerAuthSDK` instance identified by the provided configuration and keychain configuration.
///
/// Use this method when `PowerAuthSDK` initialization fails with an error indicating an unsupported local activation data format
/// and the stored local activation data must be removed before retrying initialization.
///
/// @param configuration The configuration used to identify the instance data.
/// @param keychainConfiguration The keychain configuration used to locate the instance data. If nil, the default configuration is applied.
/// @param error Pointer where error is set in case of failure.
/// @return true in case of success, false otherwise.
+ (BOOL) cleanupInstanceDataForConfiguration:(nonnull PowerAuthConfiguration*)configuration
                       keychainConfiguration:(nullable PowerAuthKeychainConfiguration*)keychainConfiguration
                                       error:(NSError*_Nullable*_Nullable)error
                            NS_SWIFT_NAME(cleanupInstanceData(configuration:keychainConfiguration:));

/// Erases local data associated with the `PowerAuthSDK` instance identified by the provided configuration.
///
/// Use this method when `PowerAuthSDK` initialization fails with an error indicating an unsupported local activation data format
/// and the stored local activation data must be removed before retrying initialization.
///
/// @param configuration The configuration used to identify the instance data.
/// @param error Pointer where error is set in case of failure.
/// @return true in case of success, false otherwise.
+ (BOOL) cleanupInstanceDataForConfiguration:(nonnull PowerAuthConfiguration*)configuration
                                       error:(NSError*_Nullable*_Nullable)error
                            NS_SWIFT_NAME(cleanupInstanceData(configuration:));

/** Creates an instance of SDK and initializes it with given configuration objects.
 
 This constructor is deprecated. Please use one of constructors that takes also `PowerAuthBiometricConfiguration` in parameter.
 
 @param configuration to be used for initialization.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then the default configuration is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then the default configuration is used.
 
 @return Initialized instance.
 */
- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                          keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                            clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
                                PA2_DEPRECATED(2.0.0);

/**
 Creates a default shared instance and initializes it with given configuration.
 The appropriate default configs are used for shared instance's configuration properties.
 
 This static method is deprecated and will be removed in a future release. To ensure better control and flexibility, manage the global instance
 of the `PowerAuthSDK` class within your application code.
 
 @param configuration to be used for initialization.
 */
+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration PA2_DEPRECATED(2.0.0);

/**
 Creates a default shared instance and initializes it with given configuration objects.
 
 This static method is deprecated and will be removed in a future release. To ensure better control and flexibility, manage the global instance
 of the `PowerAuthSDK` class within your application code.
 
 @param configuration to be used for initialization.
 @param keychainConfiguration to be used for keychain configuration. If nil is provided, then `PowerAuthKeychainConfiguration.sharedInstance()` is used.
 @param clientConfiguration to be used for HTTP client configuration. If nil is provided, then `PowerAuthClientConfiguration.sharedInstance()` is used.
 */
+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration
      keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
        clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
            PA2_DEPRECATED(2.0.0);

/** Return the default shared instance of the PowerAuth SDK.
 
 This static method is deprecated and will be removed in a future release. To ensure better control and flexibility, manage the global instance
 of the `PowerAuthSDK` class within your application code.
 
 @return Shared instance of the PowerAuth SDK.
 */
+ (nonnull PowerAuthSDK*) sharedInstance PA2_DEPRECATED(2.0.0);

/**
 Create a new activation.
 
 @param activation A PowerAuthActivation object containg all information required for the activation creation.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) createActivation:(nonnull PowerAuthActivation*)activation
                                                callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;

/**
 Create a new standard activation with given name and activation code.
 
 @param name Activation name, for example "John's iPhone".
 @param activationCode Activation code, obtained either via QR code scanning or by manual entry.
 @param callback A callback called when the process finishes - it contains an activation fingerprint in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
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
 */
- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
                                              identityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
                                                          extras:(nullable NSString*)extras
                                                        callback:(nonnull void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback;


/**
 Persist activation that was created and store related data using provided authentication instance.
 
 @param authentication An authentication instance specifying what factors should be stored.
 @param callback A callback called when the process finishes - it contains an error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) persistActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                   callback:(nonnull void(^)(NSError * _Nullable error))callback;

/**
 Persist activation that was created and store related data using default authentication instance setup with provided password.
  
 @param password Password to be used for the knowledge related authentication factor.
 @param callback A callback called when the process finishes - it contains an error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) persistActivationWithPassword:(nonnull NSString*)password
                                                             callback:(nonnull void(^)(NSError * _Nullable error))callback
                                                                NS_SWIFT_NAME(persistActivation(withPassword:callback:));

/**
 Persist activation that was created and store related data using default authentication instance setup with provided password.
  
 @param password Password to be used for the knowledge related authentication factor.
 @param callback A callback called when the process finishes - it contains an error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) persistActivationWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                                                 callback:(nonnull void(^)(NSError * _Nullable error))callback
                                                                    NS_SWIFT_NAME(persistActivation(withPassword:callback:));

/**
 Persist activation that was created and store related data using provided authentication instance.

 The method is deprecated, please use asynchronous variant of this method as a replacement.
 @param authentication An authentication instance specifying what factors should be stored.
 @param error Error reference in case some error occurs.
 */
- (BOOL) persistActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                       error:(NSError * _Nullable * _Nullable)error
                                        PA2_DEPRECATED(2.0.0);

/** Persist activation that was created and store related data using default authentication instance setup with provided password.
 
 The method is deprecated, please use asynchronous variant of this method as a replacement.
 
 Calling this method is equivalent to `persistActivationWithAuthentication:error:` with authentication object set to use possession and provided password.
 
 @param password Password to be used for the knowledge related authentication factor.
 @param error Error reference in case some error occurs.
 */
- (BOOL) persistActivationWithPassword:(nonnull NSString*)password
                                 error:(NSError * _Nullable * _Nullable)error
                            NS_SWIFT_NAME(persistActivation(withPassword:))
                            PA2_DEPRECATED(2.0.0);

/** Persist activation that was created and store related data using default authentication instance setup with provided password.
 
 The method is deprecated, please use asynchronous variant of this method as a replacement.
 
 Calling this method is equivalent to `persistActivationWithAuthentication:error:` with authentication object set to use possession and provided password.
 
 @param password Password to be used for the knowledge related authentication factor.
 @param error Error reference in case some error occurs.
 */
- (BOOL) persistActivationWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                     error:(NSError * _Nullable * _Nullable)error
                            NS_SWIFT_NAME(persistActivation(withPassword:))
                             PA2_DEPRECATED(2.0.0);

/**
 Read only property contains fingerprint calculated from device's public key or nil if object has no valid activation.
 */
@property (nonatomic, strong, nullable, readonly) NSString *activationFingerprint;

/** Fetch the activation status for current activation.
 
 @param callback A callback with activation status result - it contains status information in case of success and error in case of failure.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) getActivationStatusWithCallback:(nonnull void(^)(PowerAuthActivationStatus * _Nullable status, NSError * _Nullable error))callback
    NS_SWIFT_NAME(fetchActivationStatus(callback:));


/**
 Read only property contains last activation status object received from the server.
 You have to call `fetchActivationStatus()` method to update this value.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthActivationStatus * lastFetchedActivationStatus;

/**
 Start the protocol upgrade process.
 
 @param password Required core password instance used to authenticate the protocol upgrade start.
 @param customBiometryKek Optional parameter. If a biometry factor is configured in the current protocol version
 and no new biometry KEK is provided, one will be automatically generated for the upgraded protocol.
 @param callback A callback called when the upgrade task finishes.
 @return Protocol upgrade task instance.
 */
- (nullable id<PowerAuthOperationTask>) startProtocolUpgradeWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                                           customBiometryKek:(nullable PowerAuthCoreData*)customBiometryKek
                                                                    callback:(nonnull void(^)(PowerAuthProtocolUpgradeResult * _Nullable result, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(startProtocolUpgrade(password:customBiometryKek:callback:));

/**
 Start the protocol upgrade process.
 
 @param password Required password used to authenticate the protocol upgrade start.
 @param customBiometryKek Optional parameter. If a biometry factor is configured in the current protocol version
 and no new biometry KEK is provided, one will be automatically generated for the upgraded protocol.
 @param callback A callback called when the upgrade task finishes.
 @return Protocol upgrade task instance.
 */
- (nullable id<PowerAuthOperationTask>) startProtocolUpgradeWithPassword:(nonnull NSString*)password
                                                       customBiometryKek:(nullable PowerAuthCoreData*)customBiometryKek
                                                                callback:(nonnull void(^)(PowerAuthProtocolUpgradeResult * _Nullable result, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(startProtocolUpgrade(password:customBiometryKek:callback:));

/**
 Start the protocol upgrade process without specifying a new biometry KEK.
 If a biometry factor is configured in the current protocol version,
 a new biometry KEK  will be automatically generated for the upgraded protocol.
 
 @param password Required core password instance used to authenticate the protocol upgrade start.
 @param callback A callback called when the upgrade task finishes.
 @return Protocol upgrade task instance.
 */
- (nullable id<PowerAuthOperationTask>) startProtocolUpgradeWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                                                    callback:(nonnull void(^)(PowerAuthProtocolUpgradeResult * _Nullable result, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(startProtocolUpgrade(password:callback:));

/**
 Start the protocol upgrade process without specifying a new biometry KEK.
 If a biometry factor is configured in the current protocol version,
 a new biometry KEK  will be automatically generated for the upgraded protocol.
 
 @param password Required password used to authenticate the protocol upgrade start.
 @param callback A callback called when the upgrade task finishes.
 @return Protocol upgrade task instance.
 */
- (nullable id<PowerAuthOperationTask>) startProtocolUpgradeWithPassword:(nonnull NSString*)password
                                                                callback:(nonnull void(^)(PowerAuthProtocolUpgradeResult * _Nullable result, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(startProtocolUpgrade(password:callback:));

/** Remove current activation by calling a PowerAuth Standard RESTful API endpoint '/pa/activation/remove'.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param callback A callback with activation removal result - in case of an error, an error instance is not 'nil'.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) removeActivationWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                  callback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Removes existing activation from the device.
 
 This method removes the activation session state and biometry factor key. Cached possession related key remains intact.
 Unlike the `removeActivationWithAuthentication`, this method doesn't inform server about activation removal. In this case
 user has to remove the activation by using another channel (typically internet banking, or similar web management console)
 */
- (void) removeActivationLocal;

/// MARK: - Authentication codes

/**
 Computes the HTTP header containing the authentication code for an HTTP method, URI identifier, and HTTP body using the provided authentication information.

 It is recommended to call this method from the context of the SDK-provided serial queue to avoid counter desynchronization. See the documentation for
 `executeBlock(onSerialQueue:)` or `executeOperation(onSerialQueue:)` methods.

 Be aware that the calling thread may be blocked during biometric authentication if the biometry factor is requested in `PowerAuthAuthentication`.
 To avoid this, use the `authenticateUsingBiometry()` method to authenticate with biometry in advance.
 
 @param authentication An authentication instance specifying which factors should be used to authenticate the request.
 @param method The HTTP method used for the authentication code computation.
 @param uriId The URI identifier.
 @param body The HTTP request body.
 @param error A reference to an error object in case an error occurs.
 @return The HTTP header containing the PowerAuth authentication code. In case of an error, this method returns `nil`.
 */
- (nullable PowerAuthHttpHeader*) authenticationHeaderForRequestWithBodyWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                                    method:(nonnull NSString*)method
                                                                                     uriId:(nonnull NSString*)uriId
                                                                                      body:(nullable NSData*)body
                                                                                     error:(NSError * _Nullable * _Nullable)error;
/**
 Compute the HTTP header containing authentication code for HTTP method, URI identifier and HTTP query parameters using provided authentication information.
 
 It is recommended to call this method from the context of the SDK-provided serial queue to avoid counter desynchronization. See the documentation for
 `executeBlock(onSerialQueue:)` or `executeOperation(onSerialQueue:)` methods.

 Be aware that the calling thread may be blocked during biometric authentication if the biometry factor is requested in `PowerAuthAuthentication`.
 To avoid this, use the `authenticateUsingBiometry()` method to authenticate with biometry in advance.
 
 @param authentication An authentication instance specifying which factors should be used to authenticate the request.
 @param method The HTTP method used for the authentication code computation.
 @param uriId The URI identifier.
 @param params The HTTP query params.
 @param error A reference to an error object in case an error occurs.
 @return The HTTP header containing the PowerAuth authentication code. In case of an error, this method returns `nil`.
 */
- (nullable PowerAuthHttpHeader*) authenticationHeaderForRequestWithParamsWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                                      method:(nonnull NSString*)method
                                                                                       uriId:(nonnull NSString*)uriId
                                                                                      params:(nullable NSDictionary<NSString*, NSString*>*)params
                                                                                       error:(NSError * _Nullable * _Nullable)error;

/**
 Computes the offline authentication code for a given HTTP method, URI identifier, and HTTP request body using the provided authentication information.

 Unlike methods for calculating an authentication header for an online HTTP request, you don't need to authenticate with biometry in advance.
 This method properly handles biometric authentication if the biometric factor is requested.

 @param authentication An authentication instance specifying what factors should be used to sign the request. The possession and knowledge is recommended.
 @param uriId The URI identifier.
 @param body The HTTP request body.
 @param nonce NONCE in Base64 format.
 @param callback A callback that returns the authentication code result or an error in case of failure. The callback is always called on the main thread.
 @return A cancelable operation task associated with the pending biometric authentication.
 */
- (nullable id<PowerAuthOperationTask>) offlineAuthenticationCodeWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                              uriId:(nonnull NSString*)uriId
                                                                               body:(nullable NSData*)body
                                                                              nonce:(nonnull NSString*)nonce
                                                                           callback:(void(^_Nonnull)(NSString * _Nullable authenticationCode, NSError * _Nullable error))callback;

/// MARK: - Deprecated "symmetric signatures"

/** Compute the HTTP authentication header for GET HTTP method, URI identifier and HTTP query parameters using provided authentication information.
 
 The method is deprecated, please use `authenticationHeaderForRequestWithParams(with:method:uriId:params:)` as a replacement.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param uriId URI identifier.
 @param params HTTP query params.
 @param error Error reference in case some error occurs.
 @return HTTP header with PowerAuth authentication code. In case of error, this method return 'nil'.
 */
- (nullable PowerAuthHttpHeader*) requestGetSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                  uriId:(nonnull NSString*)uriId
                                                                 params:(nullable NSDictionary<NSString*, NSString*>*)params
                                                                  error:(NSError * _Nullable * _Nullable)error
                                                                        PA2_DEPRECATED(2.0.0);

/** Compute the HTTP authentication code header for given HTTP method, URI identifier and HTTP request body using provided authentication information.
 
 The method is deprecated, please use `authenticationHeaderForRequestWithBody(with:method:uriId:body:)` as a replacement.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request.
 @param method HTTP method used for the authentication code computation.
 @param uriId URI identifier.
 @param body HTTP request body.
 @param error Error reference in case some error occurs.
 @return HTTP header with PowerAuth authentication code. In case of error, this method return 'nil'.
 */
- (nullable PowerAuthHttpHeader*) requestSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                              method:(nonnull NSString*)method
                                                               uriId:(nonnull NSString*)uriId
                                                                body:(nullable NSData*)body
                                                               error:(NSError * _Nullable * _Nullable)error
                                                                    PA2_DEPRECATED(2.0.0);

/** Compute the offline authentication code for URI identifier and HTTP request body using provided authentication information.
 
 The method is deprecated, please use `offlineAuthenticationCode(with:uriId:body:nonce:callback:)` method as a replacement.
 
 This method may block a main thread - make sure to dispatch it asynchronously.
 
 @param authentication An authentication instance specifying what factors should be used to sign the request. The possession and knowledge is recommended.
 @param uriId URI identifier.
 @param body HTTP request body.
 @param nonce NONCE in Base64 format.
 @param error Error reference in case some error occurs.
 @return String representing a calculated authentication code for all involved factors. In case of error, this method return 'nil'.
 */
- (nullable NSString*) offlineSignatureWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                    uriId:(nonnull NSString*)uriId
                                                     body:(nullable NSData*)body
                                                    nonce:(nonnull NSString*)nonce
                                                    error:(NSError * _Nullable * _Nullable)error
                                                        PA2_DEPRECATED(2.0.0);

// Password management

/// Initiates the first step of a two-step password change operation by validating the user's current password.
///
/// The provided password is used to compute the appropriate authentication header required for password verification.
/// If the verification succeeds, the callback receives a `PowerAuthPasswordChangeData` object required to complete
/// the second step.
///
/// - Parameters:
///   - oldPassword: The user's current (old) password.
///   - callback: A block invoked when the operation completes. The block provides either the
///               password-change data needed for the next step, or an error if verification fails.
/// - Returns: A `PowerAuthOperationTask` associated with the running request, or `nil` if the request cannot be started.
- (nullable id<PowerAuthOperationTask>) beginPasswordChangeWithPassword:(nonnull NSString*)oldPassword
                                                               callback:(nonnull void(^)(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(beginPasswordChange(oldPassword:callback:));

/// Initiates the first step of a two-step password change operation by validating the user's current password.
///
/// The provided password is used to compute the appropriate authentication header required for password verification.
/// If the verification succeeds, the callback receives a `PowerAuthPasswordChangeData` object required to complete
/// the second step.
///
/// - Parameters:
///   - oldPassword: The user's current (old) password.
///   - callback: A block invoked when the operation completes. The block provides either the
///               password-change data needed for the next step, or an error if verification fails.
/// - Returns: A `PowerAuthOperationTask` associated with the running request, or `nil` if the request cannot be started.
- (nullable id<PowerAuthOperationTask>) beginPasswordChangeWithCorePassword:(nonnull PowerAuthCorePassword*)oldPassword
                                                                   callback:(nonnull void(^)(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error))callback
                            NS_SWIFT_NAME(beginPasswordChange(oldPassword:callback:));

/// Completes the second step of a two-step password change operation by submitting a new password.
///
/// The SDK uses the `PowerAuthPasswordChangeData` object obtained in the first step to calculate the necessary
/// authentication header for finalizing the password change.
///
/// - Parameters:
///   - newPassword: The new password to be set for the user.
///   - changeData: The password-change data obtained from the first step (`beginPasswordChange()`).
///   - callback: A block invoked when the operation completes. The block provides an error if the operation fails,
///               or `nil` on success.
/// - Returns: A `PowerAuthOperationTask` associated with the running request, or `nil` if the request cannot be started.
- (nullable id<PowerAuthOperationTask>) finishPasswordChangeWithNewPassword:(nonnull NSString*)newPassword
                                                                 changeData:(nonnull PowerAuthPasswordChangeData*)changeData
                                                                   callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(finishPasswordChange(newPassword:changeData:callback:));

/// Completes the second step of a two-step password change operation by submitting a new password.
///
/// The SDK uses the `PowerAuthPasswordChangeData` object obtained in the first step to calculate the necessary
/// authentication header for finalizing the password change.
///
/// - Parameters:
///   - newPassword: The new password to be set for the user.
///   - changeData: The password-change data obtained from the first step (`beginPasswordChange()`).
///   - callback: A block invoked when the operation completes. The block provides an error if the operation fails,
///               or `nil` on success.
/// - Returns: A `PowerAuthOperationTask` associated with the running request, or `nil` if the request cannot be started.
- (nullable id<PowerAuthOperationTask>) finishPasswordChangeWithNewCorePassword:(nonnull PowerAuthCorePassword*)newPassword
                                                                     changeData:(nonnull PowerAuthPasswordChangeData*)changeData
                                                                       callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(finishPasswordChange(newPassword:changeData:callback:));

// Password management (deprecated)

/** Change the password using local re-encryption, do not validate old password by calling any endpoint.
 
 You are responsible for validating the old password against some server endpoint yourself before using it in this method.
 If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
 existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
 
 Method is deprecated and you should use new `beginPasswordChange()` and `finishPasswordChange()` functions instead.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @return Returns YES in case password was changed without error, NO otherwise.
 */
- (BOOL) unsafeChangePasswordFrom:(nonnull NSString*)oldPassword
                               to:(nonnull NSString*)newPassword
                        NS_SWIFT_NAME(unsafeChangePassword(from:to:))
                        PA2_DEPRECATED(2.0.0);

/** Change the password using local re-encryption, do not validate old password by calling any endpoint.
 
 Method is deprecated and you should use new `beginPasswordChange()` and `finishPasswordChange()` functions instead.
 
 You are responsible for validating the old password against some server endpoint yourself before using it in this method.
 If you do not validate the old password to make sure it is correct, calling this method will corrupt the local data, since
 existing data will be decrypted using invalid PIN code and re-encrypted with a new one.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @return Returns YES in case password was changed without error, NO otherwise.
 */
- (BOOL) unsafeChangeCorePasswordFrom:(nonnull PowerAuthCorePassword*)oldPassword
                                   to:(nonnull PowerAuthCorePassword*)newPassword
                        NS_SWIFT_NAME(unsafeChangePassword(from:to:))
                        PA2_DEPRECATED(2.0.0);

/** Change the password.
 
 Method is deprecated and you should use new `beginPasswordChange()` and `finishPasswordChange()` functions instead.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @param callback The callback method with the password change result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) changePasswordFrom:(nonnull NSString*)oldPassword
                                                        to:(nonnull NSString*)newPassword
                                                  callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(changePassword(from:to:callback:))
                            PA2_DEPRECATED(2.0.0);

/** Change the password.
 
 Method is deprecated and you should use new `beginPasswordChange()` and `finishPasswordChange()` functions instead.
 
 @param oldPassword Old password, currently set to store the data.
 @param newPassword New password, to be set in case authentication with old password passes.
 @param callback The callback method with the password change result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) changeCorePasswordFrom:(nonnull PowerAuthCorePassword*)oldPassword
                                                            to:(nonnull PowerAuthCorePassword*)newPassword
                                                      callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(changePassword(from:to:callback:))
                            PA2_DEPRECATED(2.0.0);

/** Validate a user password.
 
 Method is deprecated and has no direct replacement. If your application requires password validation here, that indicates a deeper
 architectural issue that may introduce security vulnerabilities.
 
 @param password Password to be verified.
 @param callback The callback method with error associated with the password validation.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) validateCorePassword:(nonnull PowerAuthCorePassword*)password
                                                    callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(validatePassword(password:callback:))
                            PA2_DEPRECATED(2.0.0);

/** Validate a user password.
 
 Method is deprecated and has no direct replacement. If your application requires password validation here, that indicates a deeper
 architectural issue that may introduce security vulnerabilities.
 
 @param password Password to be verified.
 @param callback The callback method with error associated with the password validation.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) validatePassword:(nonnull NSString*)password
                                                callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(validatePassword(password:callback:))
                            PA2_DEPRECATED(2.0.0);

// Biometry key management

/// If `true`, biometric authentication is fully available and you can call methods
/// that accept a `PowerAuthAuthentication` object configured for biometrics.
@property (nonatomic, readonly) BOOL isAuthenticationWithBiometricsAvailable;

/// Contains information about the current state of the biometry.
@property (nonatomic, strong, readonly, nonnull) PowerAuthBiometricStatus * biometricStatus;

/** Regenerate a biometry related factor key.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 The method is deprecated in favor of `addBiometryFactor(password:callback:)` variant.
 
 @param password Password used for authentication during vault unlocking call.
 @param callback The callback method with the biometry key adding operation result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) addBiometryFactorWithPassword:(nonnull NSString*)password
                                                             callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(addBiometryFactor(password:callback:));

/** Regenerate a biometry related factor key. In this variant, you can provide your own KEK protecting the biometric factor.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 The method is deprecated in favor of `addBiometryFactor(password:callback:)` variant.
 
 @param password Password used for authentication during vault unlocking call.
 @param customBiometryKek Custom key encryption key protecting the biometric factor. If nil is provided, then new KEK is generated internally.
 @param callback The callback method with the biometry key adding operation result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) addBiometryFactorWithPassword:(nonnull NSString*)password
                                                    customBiometryKek:(nullable PowerAuthCoreData*)customBiometryKek
                                                             callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(addBiometryFactor(password:customBiometryKek:callback:));

/** Regenerate a biometry related factor key.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 The method is deprecated in favor of `addBiometryFactor(password:callback:)` variant.
 
 @param password Password used for authentication during vault unlocking call.
 @param callback The callback method with the biometry key adding operation result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) addBiometryFactorWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                                                 callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(addBiometryFactor(password:callback:));

/** Regenerate a biometry related factor key. In this variant, you can provide your own KEK protecting the biometric factor.
 
 This method calls PowerAuth Standard RESTful API endpoint '/pa/vault/unlock' to obtain the vault encryption key used for original private key decryption.
 The method is deprecated in favor of `addBiometryFactor(password:callback:)` variant.
 
 @param password Password used for authentication during vault unlocking call.
 @param customBiometryKek Custom key encryption key protecting the biometric factor. If nil is provided, then new KEK is generated internally.
 @param callback The callback method with the biometry key adding operation result.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) addBiometryFactorWithCorePassword:(nonnull PowerAuthCorePassword*)password
                                                        customBiometryKek:(nullable PowerAuthCoreData*)customBiometryKek
                                                                 callback:(nonnull void(^)(NSError * _Nullable error))callback
                            NS_SWIFT_NAME(addBiometryFactor(password:customBiometryKek:callback:));


/** Checks if a biometry related factor is present.
 
 This method returns the information about the key value being present in keychain. To check if biometric suppoty is present and enabled on the device, use `PowerAuthKeychain.canUseBiometricAuthentication` property.
 
 @return YES if there is a biometry factor present in the keychain, NO otherwise.
 */
- (BOOL) hasBiometryFactor;

/** Remove the biometry related factor key.
 
 The method is deprecated, use asynchronous method with callback as a replacement.
 
 @return YES if the key was successfully removed, NO otherwise.
 */
- (BOOL) removeBiometryFactor PA2_DEPRECATED(2.0.0);

/**
 Remove the biometry related factor key.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) removeBiometryFactorWithCallback:(nonnull void(^)(NSError * _Nullable error))callback;

/** Prepare PowerAuthAuthentication object for future PowerAuth authentication code calculation with a biometry and possession factors involved.
 
 The method is also useful for situations where business processes require compute two or more different PowerAuth biometry authentication codes in one interaction with the user. To achieve this, the application must acquire the custom-created PowerAuthAuthentication object first and then use it for the required authentication code calculations. It's recommended to keep this instance referenced only for a limited time, required for all future authentication code calculations.
  
 Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.
 
 @param prompt A prompt displayed in TouchID or FaceID authentication dialog.
 @param callback A callback with result, always executed on the main thread.
 @return PowerAuthOperationTask associated with the pending biometric authentication.
 */
- (nonnull id<PowerAuthOperationTask>) authenticateUsingBiometryWithPrompt:(nonnull NSString *)prompt
                                                                  callback:(nonnull void(^)(PowerAuthAuthentication * _Nullable authentication, NSError * _Nullable error))callback
                                                                NS_SWIFT_NAME(authenticateUsingBiometry(withPrompt:callback:))
                                                                API_UNAVAILABLE(tvos);

/** Prepare PowerAuthAuthentication object for future PowerAuth authentication code calculation with a biometry and possession factors involved.
 
 The method is also useful for situations where business processes require compute two or more different PowerAuth biometry authentication codes in one interaction with the user. To achieve this, the application must acquire the custom-created PowerAuthAuthentication object first and then use it for the required authentication code calculations. It's recommended to keep this instance referenced only for a limited time, required for all future authentication code calculations.
  
 Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.
 
 @param context A local authentication context that can affect a biometry authentication dialog.
 @param callback A callback with result, always executed on the main thread.
 @return PowerAuthOperationTask associated with the pending biometric authentication. If you cancel this task, then the provided `LAContext` is invalidated.
 */
- (nonnull id<PowerAuthOperationTask>) authenticateUsingBiometryWithContext:(nonnull LAContext *)context
                                                                   callback:(nonnull void(^)(PowerAuthAuthentication * _Nullable authentication, NSError * _Nullable error))callback
                                                                NS_SWIFT_NAME(authenticateUsingBiometry(withContext:callback:))
                                                                API_UNAVAILABLE(tvos);

/** Unlock all keys stored in a biometry related keychain and keeps them cached for the scope of the block.
 
 There are situations where biometry related keys from different PowerAuthSDK instances are needed in a single business process. For example, when having a master-child activation pair, computing authentication code in the child activation requires master activation to use vault unlock first and then, after the request is completed, child activation can compute the authentication code. This would normally trigger biometry dialog twice. To avoid that, all biometry related keys are fetched at once and cached for a limited amount of time.
 */
- (void) unlockBiometryKeysWithPrompt:(nonnull NSString*)prompt
                            withBlock:(nonnull void(^)(NSDictionary<NSString*, NSData*> * _Nullable keys, BOOL userCanceled))block
                         NS_SWIFT_NAME(unlockBiometryKeys(withPrompt:callback:))
                         API_UNAVAILABLE(tvos);

/** Unlock all keys stored in a biometry related keychain and keeps them cached for the scope of the block.
 
 There are situations where biometry related keys from different PowerAuthSDK instances are needed in a single business process. For example, when having a master-child activation pair, computing authentication code in the child activation requires master activation to use vault unlock first and then, after the request is completed, child activation can compute the authentication code. This would normally trigger biometry dialog twice. To avoid that, all biometry related keys are fetched at once and cached for a limited amount of time.
 */
- (void) unlockBiometryKeysWithContext:(nonnull LAContext*)context
                             withBlock:(nonnull void(^)(NSDictionary<NSString*, NSData*> * _Nullable keys, BOOL userCanceled))block
                          NS_SWIFT_NAME(unlockBiometryKeys(withContext:callback:))
                          API_UNAVAILABLE(tvos);
@end


@interface PowerAuthSDK (VaultEncryption)

/**
 Generate an derived encryption key with given index. The method is effective only if PowerAuthSDK is running at protocol version 3.3
 
 Be aware that the method is subject to remove once PowerAuth Mobile SDK drops support of old protocol version.
 
 @param authentication Authentication used for vault unlocking call.
 @param index Index of the derived key using KDF.
 @param callback The callback method with the derived encryption key.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) fetchEncryptionKey:(nonnull PowerAuthAuthentication*)authentication
                                                     index:(UInt64)index
                                                  callback:(nonnull void(^)(PowerAuthCoreData * _Nullable encryptionKey, NSError * _Nullable error))callback;

/// Get a vault encryption key from the server. This method is effective only if PowerAuthSDK is running
/// at protocol version 4.0 and higher.
///
/// @param authentication Authentication used for vault unlocking call.
/// @param keyIdentifier Vault encryption key identifier.
/// @param callback The callback method with the provided vault key.
/// @return `PowerAuthOperationTask` associated with the running request. If `nil` is returned, then function failed at input validations.
- (nullable id<PowerAuthOperationTask>) fetchSecureVaultKey:(nonnull PowerAuthAuthentication*)authentication
                                              keyIdentifier:(PowerAuthSecureVaultKeyId)keyIdentifier
                                                   callback:(nonnull void(^)(PowerAuthSecureVaultKey * _Nullable vaultKey, NSError *_Nullable error))callback
                                        NS_SWIFT_NAME(fetchSecureVaultKey(authentication:keyIdentifier:callback:));
@end

@interface PowerAuthSDK (DigitalSignatures)

/// Export device public key into the specified format.
/// - Parameters:
///   - format: Required format of the output public key data.
///   - error: Pointer where error is set in case of failure.
/// - Returns: Array of `PowerAuthDevicePublicKeyData` objects or `nil` in case of failure.
- (nullable NSArray<PowerAuthDevicePublicKeyData*>*) exportDevicePublicKeysToFormat:(PowerAuthDevicePublicKeyFormat)format
                                                                              error:(NSError*_Nullable*_Nullable)error
                                        NS_SWIFT_NAME(exportDevicePublicKeys(format:));

/// Verifies a digital signature for the given data using the key specified by its identifier.
///
/// If the selected key identifier represents multiple key types, an error is reported.
/// Hybrid signatures are not supported in this version of the library.
///
/// - Parameters:
///   - signature: The digital signature calculated for the data.
///   - signedData: The data that was signed.
///   - keyIdentifier: The identifier of the key used for verification.
///   - error: A pointer to an error object that is set in case of failure.
/// - Returns: `YES` if the signature is valid; otherwise, `NO`.
- (BOOL) verifyDigitalSignature:(nonnull NSData*)signature
                     signedData:(nullable NSData*)signedData
                  keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                          error:(NSError*_Nullable*_Nullable)error
            NS_SWIFT_NAME(verifyDigitalSignature(signature:forData:withKey:));

/// Verifies JWS or JWT signed data using the key specified by its identifier.
///
/// If the selected key identifier represents multiple key types, compact format cannot be used.
///
/// - Parameters:
///   - signature: A string containing JWS or JWT signed data.
///   - compact: If `YES`, the input string is a compact JWT; otherwise, a full JWS object is expected.
///   - strict: If `YES`, all provided keys must be used to successfully verify their corresponding signatures.
///             If `NO`, verification succeeds when at least one provided key matches a valid signature; however,
///             invalid or mismatched signatures still result in an error.
///   - keyIdentifier: The identifier of the key used for verification.
///   - error: A pointer to an error object that is set in case of failure.
/// - Returns: `YES` if the signature is valid; otherwise, `NO`.
- (BOOL) verifyJwsSignature:(nonnull NSString*)signature
                    compact:(BOOL)compact
                     strict:(BOOL)strict
              keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                      error:(NSError*_Nullable*_Nullable)error
            NS_SWIFT_NAME(verifyJwsSignature(signature:compact:strict:withKey:));

/// Calculates a digital signature for the given data using the key specified by its identifier.
///
/// The selected key must support signature calculation; otherwise, an error is reported.
/// If the key identifier represents multiple key types, an error is also reported.
/// Hybrid signatures are not supported in this version of the library.
///
/// - Parameters:
///   - authentication: The authentication object used for vault unlocking.
///   - dataToSign: The data to sign.
///   - keyIdentifier: The identifier of the key used for signature calculation.
///   - callback: The callback invoked with the resulting signature or an error.
/// - Returns: A `PowerAuthOperationTask` associated with the running request,
///            or `nil` if input validation fails.
- (nullable id<PowerAuthOperationTask>) calculateDigitalSignature:(nonnull PowerAuthAuthentication*)authentication
                                                       dataToSign:(nullable NSData*)dataToSign
                                                    keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                         callback:(nonnull void(^)(NSData * _Nullable signature, NSError * _Nullable error))callback
            NS_SWIFT_NAME(calculateDigitalSignature(authentication:forData:withKey:callback:));

/// Calculates a JWS signature for the given data using the key specified by its identifier.
///
/// The selected key must support signature calculation; otherwise, an error is reported.
/// If the key identifier represents multiple key types, compact format cannot be used for output.
///
/// - Parameters:
///   - authentication: The authentication object used for vault unlocking.
///   - dataToSign: The data to sign.
///   - dataType: Data type set to JOSE header. Use `"JWT"` or `nil` if no type is set.
///   - compact: If `YES`, the output string is a compact JWT; otherwise, a full JWS object is returned.
///   - keyIdentifier: The identifier of the key used for signature calculation.
///   - callback: The callback invoked with the resulting signature or an error.
/// - Returns: A `PowerAuthOperationTask` associated with the running request,
///            or `nil` if input validation fails.
- (nullable id<PowerAuthOperationTask>) calculateJwsSignature:(nonnull PowerAuthAuthentication*)authentication
                                                   dataToSign:(nullable NSData*)dataToSign
                                                     dataType:(nullable NSString*)dataType
                                                      compact:(BOOL)compact
                                                keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                     callback:(nonnull void(^)(NSString * _Nullable jws, NSError * _Nullable error))callback
            NS_SWIFT_NAME(calculateJwsSignature(authentication:forData:dataType:compact:withKey:callback:));

/// Creates X.509 CSR (Certificate Signing Request) with given Distinguished Names and optional Subject Alternative Names,
/// embedded device public key and signed with the device private key.
///
/// - Parameters:
///   - authentication: The authentication object used for vault unlocking.
///   - distinguishedNames: Distinguished Names (DN) to be embedded in the CSR. The dictionary keys are DN types (like "CN", "O", etc.) and values are corresponding DN values.
///   - subjectAltNames: Optional array of Subject Alternative Names (SAN)
///   - keyIdentifier: The identifier of the key used for the signature calculation.
///   - callback: The callback method with the CSR in PEM format.
/// - Returns: A `PowerAuthOperationTask` associated with the running request,
///            or `nil` if input validation fails.
- (nullable id<PowerAuthOperationTask>) createCertificateSigningRequestWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                       distinguishedNames:(nonnull NSDictionary<NSString*, NSString*>*)distinguishedNames
                                                                          subjectAltNames:(nullable NSArray<NSString*>*)subjectAltNames
                                                                            keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                                                 callback:(nonnull void(^)(NSString * _Nullable csr, NSError * _Nullable error))callback
            NS_SWIFT_NAME(createCertificateSigningRequest(authentication:distinguishedNames:subjectAltNames:keyIdentifier:callback:));

// Deprecated methods

/**
 Sign given data with the original device private key (asymmetric signature).
 
 The method is deprecated, use `calculateDigitalSignature(authentication:forData:withKey:callback:)` as a replacement.
 
 @param authentication Authentication used for vault unlocking call.
 @param data Data to be signed with the private key.
 @param callback The callback method with the data signature.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) signDataWithDevicePrivateKey:(nonnull PowerAuthAuthentication*)authentication
                                                                data:(nullable NSData*)data
                                                            callback:(nonnull void(^)(NSData * _Nullable signature, NSError * _Nullable error))callback
                                                                PA2_DEPRECATED(2.0.0);

/**
 Sign provided claims with the original device private key (asymmetric signature).
 
 The method is deprecated, use `calculateJwsSignature(authentication:forData:dataType:compact:withKey:callback:)` as a replacement.
 
 @param authentication Authentication used for vault unlocking call.
 @param claims Claims to be signed with the private key.
 @param callback The callback method with the signed JWT.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) signJwtWithDevicePrivateKey:(nonnull PowerAuthAuthentication*)authentication
                                                             claims:(nonnull NSDictionary<NSString*, NSObject*>*)claims
                                                           callback:(nonnull void(^)(NSString * _Nullable jwt, NSError * _Nullable error))callback
                                                                PA2_DEPRECATED(2.0.0);
/**
 Validates whether the data has been signed with master server private key or personalized server's private key.
 
 The method is deprecated, use `verifyDigitalSignature(signature:forData:withKey:)` as replacement.
 
 @param data An arbitrary data
 @param signature A signature calculated for data, in Base64 format
 @param masterKey If YES, then master server public key is used for validation, otherwise personalized server's public key.
 */
- (BOOL) verifyServerSignedData:(nonnull NSData*)data
                      signature:(nonnull NSString*)signature
                      masterKey:(BOOL)masterKey
                        PA2_DEPRECATED(2.0.0);

/** Creates X.509 CSR (Certificate Signing Request) with given Distinguished Names and optional Subject Alternative Names, embedded device public key and signed with the device private key.
 
 @param authentication Authentication used for vault unlocking call.
 @param distinguishedNames Distinguished Names (DN) to be embedded in the CSR. The dictionary keys are DN types (like "CN", "O", etc.) and values are corresponding DN values.
 @param subjectAltNames Optional array of Subject Alternative Names (SAN)
 @param callback The callback method with the CSR in PEM format with lines separated by `\n` (including `-----BEGIN CERTIFICATE REQUEST`----- and `-----END CERTIFICATE REQUEST-----` lines).
 @return PowerAuthOperationTask associated with the running request.
 @deprecated Use `createCertificateSigningRequest(with:distinguishedNames:subjectAltNames:keyIdentifier:callback:)` as replacement.
 */
- (nullable id<PowerAuthOperationTask>) createSignedCSRWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                       distinguishedNames:(nonnull NSDictionary<NSString*, NSString*>*)distinguishedNames
                                                          subjectAltNames:(nullable NSArray<NSString*>*)subjectAltNames
                                                                 callback:(nonnull void(^)(NSString * _Nullable csr, NSError * _Nullable error))callback
                                                                    PA2_DEPRECATED(2.0.0);

@end


#pragma mark - End-2-End Encryption

@interface PowerAuthSDK (E2EE)

/**
 Creates a new instance of encryptor suited for application's general end-to-end encryption purposes. The returned encryptor is
 cryptographically bound to the PowerAuth configuration, so it can be used with or without a valid activation. The encryptor also contains
 an associated `PowerAuthCoreEciesMetaData` object, allowing you to properly setup HTTP header for the request.
 
 @return PowerAuthOperationTask associated with the running request or nil if the result of the function is available immediately.
 */
- (nullable id<PowerAuthOperationTask>) encryptorForApplicationScopeWithCallback:(nonnull void(^)(PowerAuthCoreEncryptor * _Nullable encryptor, NSError * _Nullable error))callback;

/**
 Creates a new instance of ECIES encryptor suited for application's general end-to-end encryption purposes. The returned encryptor is
 cryptographically bound to a device's activation, so it can be used only when this instance has a valid activation.
  
 @return PowerAuthOperationTask associated with the running request or nil if the result of the function is available immediately.
 */
- (nullable id<PowerAuthOperationTask>) encryptorForActivationScopeWithCallback:(nonnull void(^)(PowerAuthCoreEncryptor * _Nullable encryptor, NSError * _Nullable error))callback;

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
 at the time. The PowerAuth authentication codes are based on a logical counter, so this technique makes that all requests are delivered
 to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
 them with the SDK.
 
 @b Recommended practices
 
 1)  You should calculate PowerAuth authentication code from the execute block method.
 
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
 at the time. The PowerAuth authentication codes are based on a logical counter, so this technique makes that all requests are delivered
 to the server in the right order. So, if the application is creating its own signed requests, then it's recommended to synchronize
 them with the SDK.
 
 @b Recommended practices
 
 You should calculate PowerAuth authentication code after the operation is started. If you calculate the authentication code before and after that you add
 that operation to the queue, the logical counter may not be synchronized properly.
 
 

 @param operation Operation to be executed in the serialized queue
 @return YES if operation was added to the queue, or NO if there's no activation.
 */
- (BOOL) executeOperationOnSerialQueue:(nonnull NSOperation *)operation;

@end

#pragma mark - Activation data sharing

@interface PowerAuthSDK (ActivationDataSharing)

/**
 If activation data sharing via app group is enabled for this instance of PowerAuthSDK, then this property may contain
 an information about pending sensitive operation, currently running in an external application. Your application should
 instruct user to switch to this application to complete the task.
 */
@property (nonatomic, strong, readonly, nullable) PowerAuthExternalPendingOperation * externalPendingOperation;

@end


#pragma mark - External Encryption Key

@interface PowerAuthSDK (EEK)

/// Contains YES if factor keys in a legacy activation are still protected with EEK.
@property (nonatomic, readonly) BOOL hasExternalEncryptionKey;

/// Remove EEK if factor keys are still protected with EEK. The method returns an error
/// if activation is not present, or if factor keys are not protected with EEK.
///
/// - Parameters:
///   - externalEncryptionKey: EEK previously used for the factor keys protection.
///   - error: Pointer where error is set in case of failure.
/// - Returns: YES in case of success, NO otherwise.
- (BOOL) removeExternalEncryptionKey:(nonnull PowerAuthCoreData *)externalEncryptionKey
                               error:(NSError * _Nullable * _Nullable)error;

/// Add external encryption key for testing purposes. The method should not be used in the
/// release build. The legacy activation must be present and the size of EEK must match the size
/// of factor keys used in V3.3 protocol version (e.g. 16 bytes).
///
/// - Parameters:
///   - eek: EEK to apply
///   - error: Pointer where error is set in case of failure.
/// - Returns: YES in case of success, NO otherwise.
- (BOOL) addExternalEncryptionKeyForTest:(nonnull PowerAuthCoreData *)externalEncryptionKey
                                   error:(NSError * _Nullable * _Nullable)error;

@end

#pragma mark - User Info

@interface PowerAuthSDK (UserInfo)

/**
 Retrieve last fetched user info cached in the Session Data.
 The value is updated during the activation process or by calling `fetchUserInfo()` function.
 */
@property (nonatomic, readonly, nullable) PowerAuthUserInfo * lastFetchedUserInfo;

/**
 Fetch information about the user from the server. If operation succeed, then the claims are also stored
 to the Session Data and accessible via the `lastFetchedUserInfo`.
 @param callback The callback method with an user info data.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) fetchUserInfo:(nonnull void(^)(PowerAuthUserInfo * _Nullable userInfo, NSError * _Nullable error))callback
                        NS_SWIFT_NAME(fetchUserInfo(callback:));

@end

#pragma mark - Server Status

@interface PowerAuthSDK (ServerStatus)

/**
 Fetch status of the server from the server.
 @param callback The callback method with a server status object.
 @return PowerAuthOperationTask associated with the running request.
 */
- (nullable id<PowerAuthOperationTask>) fetchServerStatus:(nonnull void(^)(PowerAuthServerStatus * _Nullable status, NSError * _Nullable error))callback
                        NS_SWIFT_NAME(fetchServerStatus(callback:));

@end
