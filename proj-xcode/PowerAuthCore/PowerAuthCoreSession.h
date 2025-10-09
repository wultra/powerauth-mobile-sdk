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
#import <PowerAuthCore/PowerAuthCoreConfig.h>
#import <PowerAuthCore/PowerAuthCoreError.h>
#import <PowerAuthCore/PowerAuthCoreTask.h>
#import <PowerAuthCore/PowerAuthCoreTimeService.h>
#import <PowerAuthCore/PowerAuthCoreEncryptorFactory.h>
#import <PowerAuthCore/PowerAuthCoreCredentials.h>


/// The `PowerAuthCoreSessionDelegate` provide interface required for interaction
/// with the low level C++ session.
@protocol PowerAuthCoreSessionDelegate <NSObject>
@required
/// Called when session require read access to the activation data.
/// The implementation must validate whether the read access is granted.
/// If access is not granted, then return NO.
- (BOOL) requireReadAccess;

/// Called when session require write access to the activation data.
/// The implementation must validate whether the write access is granted.
/// If access is not granted, then return NO.
- (BOOL) requireWriteAccess;

@end

/// The `PowerAuthCoreSession` provides Objective-C interface to the low-level
/// C++ Session implementation.
@interface PowerAuthCoreSession : NSObject

#pragma mark -  Initialization / Reset

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Create session object with provided configuration  You have to provide a valid
/// `PowerAuthCoreConfig` object and optional delegate. The delegate is  required in
/// case the PowerAuth SDK is configured to share the activation data between
/// multiple applications.
///
/// - Parameters:
///   - configuration: Session's configuration.
///   - delegate: Interface to Session's delegate. The weak reference is stored internally.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Configured instance of `PowerAuthCoreSession` object.
/// - Throws: `NSException` in case of failure.
+ (nullable instancetype) createWithConfiguration:(nonnull PowerAuthCoreConfig*)configuration
                                         delegate:(nullable id<PowerAuthCoreSessionDelegate>)delegate
                                            error:(NSError*_Nullable*_Nullable)error;

/// Create session object with provided configuration  You have to provide a valid
/// `PowerAuthCoreConfig` object. This method is useful in situations, when activation
/// data is not shared between multiple applications.
///
/// - Parameters:
///   - configuration: Session's configuration.
///   - error: Pointer where the error will be stored in case of failure.
/// - Returns: Configured instance of `PowerAuthCoreSession` object or `nil` in case of failure.
+ (nullable instancetype) createWithConfiguration:(nonnull PowerAuthCoreConfig*)configuration
                                            error:(NSError*_Nullable*_Nullable)error;

/// Resets session into its initial state. The existing session's configuration is preserved
/// after the call.
///
/// This function changes the session's state, so write access must be guaranteed.
- (void) resetSession;

/// Contains pointer to an internal `PowerAuthCoreConfig` object.
///
/// This property doesn't use shared data, so no exclusive access is required.
@property (nonatomic, strong, readonly, nullable) PowerAuthCoreConfig * configuration;

/// Contains `APPLICATION_KEY` read from the configuration object object.
///
/// This property doesn't use shared data, so no exclusive access is required.

@property (nonatomic, strong, readonly, nonnull) NSString * applicationKey;

/// Contains instance identifier provided in configuration.
///
/// This property doesn't use shared data, so no exclusive access is required.
@property (nonatomic, strong, readonly, nonnull) NSString* instanceId;

/// Contains weak reference to delegate.
@property (nonatomic, weak, nullable) id<PowerAuthCoreSessionDelegate> delegate;

/// Contains current effective algorithm used in the session. If there's no activation, then returns
/// algorithm provided in the configuration.
@property (nonatomic, readonly) PowerAuthCoreAlgorithm currentAlgorithm;

#pragma mark - Session state

/**
 Contains YES if the session is in state where it's possible to create a new activation.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL canCreateActivation;
/**
 Contains YES if the session has pending activation create.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL hasPendingCreateActivation;
/**
 Contains YES if the session has valid activation and the shared secret between the client and
 the server has been established. You can sign data in this state.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL hasValidActivationData;
/**
 Checks if there's a valid activation that requires a protocol upgrade. Contains NO once the upgrade
 process is started. The application should fetch the activation's status to do the upgrade.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL hasProtocolUpgradeAvailable;
/**
 Contains YES if the session has pending upgrade to newer protocol version.
 Some operations may be temporarily blocked during the upgrade process.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL hasPendingProtocolUpgrade;
/**
 Contains version of protocol in which the session currently operates. If session has no activation,
 then the most up to date version is returned.
 
 This property access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) PowerAuthCoreProtocolVersion protocolVersion;

@property (nonatomic, assign, readonly, nonnull) NSDictionary<NSString*, NSObject*>* lastUserInfo;


#pragma mark - Serialization

/// Save the state of session into the sequence of bytes.
///
/// Note that saving a state during the pending activation has no effect. In this case,
/// the returned byte sequence represents the state of the session before the activation
/// process is started.
///
/// This function access the session's state, so read access must be guaranteed.
- (nullable NSData*) serializedState:(NSError*_Nullable*_Nullable)error;

/// Loads state of session from previously saved sequence of bytes. If the serialized state is
/// invalid then the session ends in empty, uninitialized state.
///
/// Returns YES if operation succeeds. In case of failure, you can determine the failure reason from
/// DEBUG log.
///
/// This function changes the session's state, so write access must be guaranteed.
///
/// - Parameter state: Previously saved state.
/// - Parameter error: Pointer where error is stored in case of failure.
/// - Returns: YES in case of success.
- (BOOL) deserializeState:(nonnull NSData *)state
                    error:(NSError*_Nullable*_Nullable)error;

/// Indicate that session has modified internal state that needs to be saved to the persistent storage.
@property (nonatomic, readonly) BOOL isModifiedState;

#pragma mark - Activation

/// If the session has valid activation, then returns the activation identifier.
/// Otherwise returns nil.
///
/// This property access the session's state, so read access must be guaranteed.
@property (nonatomic, strong, readonly, nullable) NSString * activationIdentifier;

/// If the session has valid activation, then returns decimalized fingerprint, calculated
/// from device's public key. Otherwise returns nil.
///
/// This property access the session's state, so read access must be guaranteed.
@property (nonatomic, strong, readonly, nullable) NSString * activationFingerprint;


/// Starts a new activation process. Once the activation is started you have to complete
/// whole activation sequence or reset a whole session.
///
/// This function changes the session's state, so write access must be guaranteed.
/// - Parameters:
///   - L1Data: JSON representation with L1 activation data
///   - L2Data: JSON representation with L2 activation data
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request object containing all required information for activation creation.
- (nullable PowerAuthCoreRequest*) createActivation:(nonnull NSDictionary*)L1Data
                                         withL2Data:(nonnull NSDictionary*)L2Data
                                              error:(NSError*_Nullable*_Nullable)error;

/// Fetch activation status from the server.
///
/// This function doesn't change the session's state, so read access must be guaranteed.
///
/// - Parameter error: Pointer where error is stored in case of failure.
/// - Returns: Core task for getting activation status.
- (nullable PowerAuthCoreTask*) fetchActivationStatus:(NSError*_Nullable*_Nullable)error;

/// Confirm activation and complete the activation process with user's password.
///
/// This function changes the session's state, so write access must be guaranteed.
///
/// - Parameters:
///   - password: User's password.
///   - biometryKek: Optional biometric factor KEK. If `nil` then this session will not have biometry configured.
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request object containing all required information for activation confirmation.
- (nullable PowerAuthCoreRequest*) confirmActivationWithPassword:(nonnull PowerAuthCorePassword*)password
                                                 withBiometryKek:(nullable PowerAuthCoreData*)biometryKek
                                                           error:(NSError*_Nullable*_Nullable)error;

/// Remove activation from the server.
///
/// This function doesn't change the session's state, so read access must be guaranteed.
///
/// - Parameters:
///   - credentials: Credentials with at least two factors.
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request object containing all required information for activation remove.
- (nullable PowerAuthCoreRequest*) removeActivationWithCredentials:(nonnull PowerAuthCoreCredentials*)credentials
                                                             error:(NSError*_Nullable*_Nullable)error;

#pragma mark - User info

- (nullable PowerAuthCoreRequest*) fetchUserInfo:(NSError*_Nullable*_Nullable)error;

#pragma mark - Signature keys management

/// Verify user's password on the server.
///
/// This function doesn't change the session's state, so read access must be guaranteed.
///
/// - Parameters:
///   - password: User's password.
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request object containing all required information for password verify.
- (nullable PowerAuthCoreRequest*) verifyPassword:(nonnull PowerAuthCorePassword*)password
                                            error:(NSError*_Nullable*_Nullable)error;

/// Change user's password.
///
/// This function may change the session's state, so write access must be guaranteed.
///
/// - Parameters:
///   - oldPassword: Old password.
///   - newPassword: New password.
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request in case that operation require communication with the server, or `nil` in case the
///            password has been changed synchronously. Check the returned error to distinguish between the success
///            and the failure.
- (nullable PowerAuthCoreRequest*) changePassword:(nonnull PowerAuthCorePassword*)oldPassword
                                       toPassword:(nonnull PowerAuthCorePassword*)newPassword
                                            error:(NSError*_Nullable*_Nullable)error;

/// Returns `YES` in case the biometric factor is set.
///
/// This function doesn't change the session's state, so read access must be guaranteed.
- (BOOL) hasBiometryFactor;

/// Add biometry factor.
///
/// This function doesn't change the session's state, so read access must be guaranteed.
///
/// - Parameters:
///   - password: User's password.
///   - biometryKek: New biometry KEK.
///   - error: Pointer where error is stored in case of failure.
/// - Returns: Core request object containing all required information for biometry add.
- (nullable PowerAuthCoreRequest*) addBiometryFactorWithPassword:(nonnull PowerAuthCorePassword*)password
                                                 withBiometryKek:(nonnull PowerAuthCoreData*)biometryKek
                                                           error:(NSError*_Nullable*_Nullable)error;
/// Remove biometry factor.
///
/// This function may change the session's state, so write access must be guaranteed.
///
/// - Parameter error: Pointer where error is stored in case of failure.
/// - Returns: Core request in case that operation require communication with the server, or `nil` in case the
///            biometry has been removed synchronously. Check the returned error to distinguish between the success
///            and the failure.
- (nullable PowerAuthCoreRequest*) removeBiometryFactor:(NSError*_Nullable*_Nullable)error;


#pragma mark - Authentication

/// Calculate online authentication header for HTTP request.
/// - Parameters:
///   - credentials: Credentials used for authentication.
///   - uriIdentifier: URI identfier
///   - httpMethod: HTTP method
///   - requestBody: Request body.
///   - error: Pointer where error is set in case of failure.
/// - Returns: `PowerAuthCoreHttpHeader` object if succeeds.
- (nullable PowerAuthCoreHttpHeader*) calculateOnlineAuthenticationHeader:(nonnull PowerAuthCoreCredentials*)credentials
                                                            uriIdentifier:(nonnull NSString*)uriIdentifier
                                                               httpMethod:(nonnull NSString*)httpMethod
                                                              requestBody:(nullable NSData*)requestBody
                                                                    error:(NSError *_Nullable*_Nullable)error;

/// Calculate human readable authentication code for offline authentication.
/// - Parameters:
///   - credentials: Credentials used for authentication.
///   - uriIdentifier: URI identifier.
///   - offlineNonce: Offline nonce.
///   - codeLength: Length of calculated code.
///   - error: Pointer where error is set in case of failure.
/// - Returns: Human readable authentication code if succeeds.
- (nullable NSString*) calculateOfflineAuthenticationCode:(nonnull PowerAuthCoreCredentials*)credentials
                                            uriIdentifier:(nonnull NSString*)uriIdentifier
                                             offlineNonce:(nonnull NSString*)offlineNonce
                                               codeLength:(NSUInteger)codeLength
                                                     data:(nullable NSData*)data
                                                    error:(NSError *_Nullable*_Nullable)error;

/// Normalize parameters of GET HTTP request into data suitable for function that calculate online authentication header.
/// - Parameters:
///   - parameters: Dictionary with get parameters.
///   - error: Pointer where error is set in case of failure.
/// - Returns: Normalized data.
- (nullable NSData*) normalizeGetRequestParameters:(nonnull NSDictionary<NSString*, NSString*>*)parameters
                                             error:(NSError *_Nullable*_Nullable)error;

#pragma mark - Tokens

- (nullable PowerAuthCoreHttpHeader*) calculateTokenHeader:(nonnull NSString *)tokenIdentifier
                                               tokenSecret:(nonnull NSData*)tokenSecret
                                                     error:(NSError *_Nullable*_Nullable)error;

- (nullable PowerAuthCoreRequest*) createAccessToken:(nonnull PowerAuthCoreCredentials*)credentials
                                               error:(NSError *_Nullable*_Nullable)error;

- (nullable PowerAuthCoreRequest*) removeAccessToken:(nonnull NSString *)tokenIdentifier
                                               error:(NSError *_Nullable*_Nullable)error;

#pragma mark - Vault operations

#pragma mark - External Encryption Key

/**
 Returns YES if EEK (external encryption key) is set.
 
 This function access the session's state, so read access must be guaranteed.
 */
@property (nonatomic, assign, readonly) BOOL hasExternalEncryptionKey;

#pragma mark - Services

/// Contains reference to time synchronization service.
@property (nonatomic, readonly, strong, nonnull) PowerAuthCoreTimeService * timeSynchronizationService;

/// Contains reference to encryptor factory.
@property (nonatomic, readonly, strong, nonnull) PowerAuthCoreEncryptorFactory * encryptorFactory;

#pragma mark - Utilities

/// Generate new factor KEK. The size of KEK depends on the current protocol version.
///
/// This function access the session's state, so read access must be guaranteed.
/// - Parameter error: Pointer to output error.
/// - Returns: New KEK or `nil` in case of failure.
- (nullable PowerAuthCoreData*) generateFactorKek:(NSError*_Nullable*_Nullable)error;

/// Generate new factor KEK for selected protocol version.
/// - Parameters:
///   - protocolVersion: Protocol version.
///   - error: Pointer to output error.
/// - Returns: New KEK or `nil` in case of failure.
+ (nullable PowerAuthCoreData*) generateFactorKekForProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
                                                              error:(NSError*_Nullable*_Nullable)error;

/// Returns textual representation for given protocol version. For example, for `PowerAuthCoreProtocolVersion_V3`
/// returns "3.3". You can use `PowerAuthCoreProtocolVersion_NA` to get the value for the latest supported version.
+ (nonnull NSString*) maxSupportedHttpProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion;

@end
