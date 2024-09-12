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

#import <PowerAuth2/PowerAuthSDK.h>
#import <PowerAuth2/PowerAuthKeychain.h>
#import <PowerAuth2/PowerAuthSystem.h>
#import <PowerAuth2/PowerAuthLog.h>

#import "PowerAuthSDK+Private.h"

#import "PA2HttpClient.h"
#import "PA2RestApiObjects.h"
#import "PA2AsyncOperation.h"
#import "PA2ObjectSerialization.h"

#import "PA2TimeSynchronizationService.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateHttpTokenProvider.h"
#import "PA2PrivateMacros.h"
#import "PA2PrivateEncryptorFactory.h"
#import "PA2DefaultSessionInterface.h"
#import "PA2SharedSessionInterface.h"
#import "PA2SessionDataProvider.h"
#import "PA2AppGroupContainer.h"
#import "PA2CompositeTask.h"
#import "PA2Result.h"

#if defined(PA2_WATCH_SUPPORT)
#import "PowerAuthWCSessionManager+Private.h"
#endif

#import <UIKit/UIKit.h>

#pragma mark - Constants

/** In case a config is missing, exception with this identifier is thrown. */
NSString *const PowerAuthExceptionMissingConfig = @"PowerAuthExceptionMissingConfig";

#pragma mark - PowerAuth SDK implementation

@implementation PowerAuthSDK
{
    id<NSLocking> _lock;
    
    id<PA2SessionInterface> _sessionInterface;
    PowerAuthCoreSession * _coreSession;
    PowerAuthConfiguration * _configuration;
    PowerAuthKeychainConfiguration * _keychainConfiguration;
    PowerAuthClientConfiguration * _clientConfiguration;
    
    PA2TimeSynchronizationService * _timeSynchronizationService;
    id<PowerAuthPrivateTokenStore> _tokenStore;
    PA2HttpClient *_client;
    NSString *_biometryKeyIdentifier;
    PowerAuthKeychain *_statusKeychain;
    PowerAuthKeychain *_sharedKeychain;
    PowerAuthKeychain *_biometryOnlyKeychain;
    PA2PrivateHttpTokenProvider * _remoteHttpTokenProvider;
    
    /// Current pending status task.
    PA2GetActivationStatusTask * _getActivationStatusTask;
    PowerAuthActivationStatus * _lastFetchedActivationStatus;
    // Current pending system status task
    PA2GetSystemStatusTask * _getSystemStatusTask;
    /// User info
    PowerAuthUserInfo * _lastFetchedUserInfo;
}

#pragma mark - Private methods

- (void) initializeWithConfiguration:(PowerAuthConfiguration*)configuration
               keychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration
                 clientConfiguration:(PowerAuthClientConfiguration*)clientConfiguration
{
    
    // Check if the configuration was nil
    if (configuration == nil) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
    
    // Validate that the configuration was set up correctly
    if (![configuration validateConfiguration]) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
    
    // Exclusive lock
    _lock = [[NSRecursiveLock alloc] init];
    
    // Make copy of configuration objects
    _configuration = [configuration copy];
    _keychainConfiguration = [(keychainConfiguration ? keychainConfiguration : [PowerAuthKeychainConfiguration sharedInstance]) copy];
    _clientConfiguration = [(clientConfiguration ? clientConfiguration : [PowerAuthClientConfiguration sharedInstance]) copy];
    
    // Prepare identifier for biometry related keys - use instanceId by default, or a custom value if set
    _biometryKeyIdentifier = _configuration.keychainKey_Biometry ? _configuration.keychainKey_Biometry : _configuration.instanceId;
    
    // Alter keychain in case that PowerAuthSharingConfiguration is used
    PowerAuthSharingConfiguration * sharingConfiguration = _configuration.sharingConfiguration;
    NSString * biometryKeychainAccessGroup = nil;
    if (sharingConfiguration != nil) {
        _keychainConfiguration.keychainAttribute_UserDefaultsSuiteName = sharingConfiguration.appGroup;
        _keychainConfiguration.keychainAttribute_AccessGroup = sharingConfiguration.keychainAccessGroup;
        biometryKeychainAccessGroup = sharingConfiguration.keychainAccessGroup;
    }
    // Prepare time synchronization sevice.
    //
    // Note that we're using instance of PowerAuthSDK as a status provider. To prevent the cirtular object reference, the
    // time service keeps weak reference to the status provider (e.g. to PowerAuthSDK)
    _timeSynchronizationService = [[PA2TimeSynchronizationService alloc] initWithStatusProvider:self sharedLock:_lock];
    [_timeSynchronizationService subscribeForSystemNotifications];

    // Create session setup parameters
    PowerAuthCoreSessionSetup *setup = [[PowerAuthCoreSessionSetup alloc] initWithConfiguration:_configuration.configuration];
    setup.externalEncryptionKey = _configuration.externalEncryptionKey;
    
    // Create a new session
    _coreSession = [[PowerAuthCoreSession alloc] initWithSessionSetup:setup timeService:_timeSynchronizationService];
    if (_coreSession == nil || ![_coreSession hasValidSetup]) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
    
    // Create a new keychain instances
    _statusKeychain         = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Status
                                                                accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
    _sharedKeychain         = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Possession
                                                                accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
    _biometryOnlyKeychain   = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Biometry
                                                                accessGroup:biometryKeychainAccessGroup];
    
    // Initialize token store with its own keychain as a backing storage and remote token provider.
    PowerAuthKeychain * tokenStoreKeychain = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_TokenStore
                                                                               accessGroup:_keychainConfiguration.keychainAttribute_AccessGroup];
    // Make sure to reset keychain data after app re-install.
    // Important: This deletes all Keychain data in all PowerAuthSDK instances!
    // By default, the code uses standard user defaults, use `PowerAuthKeychainConfiguration.keychainAttribute_UserDefaultsSuiteName` to use `NSUserDefaults` with a custom suite name.
    NSUserDefaults *userDefaults = nil;
    if (_keychainConfiguration.keychainAttribute_UserDefaultsSuiteName != nil) {
        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:_keychainConfiguration.keychainAttribute_UserDefaultsSuiteName];
    } else {
        userDefaults = [NSUserDefaults standardUserDefaults];
    }
    if ([userDefaults boolForKey:PowerAuthKeychain_Initialized] == NO) {
        [_statusKeychain deleteAllData];
        [_sharedKeychain deleteAllData];
        [_biometryOnlyKeychain deleteAllData];
        [tokenStoreKeychain deleteAllData];
        [userDefaults setBool:YES forKey:PowerAuthKeychain_Initialized];
        [userDefaults synchronize];
    }
    
    // Initialize session data provider and session interface.
    PA2SessionDataProvider * sessionDataProvider = [[PA2SessionDataProvider alloc] initWithKeychain:_statusKeychain statusKey:_configuration.instanceId];
    if (sharingConfiguration == nil) {
        // This instance will not use the session sharing.
        _sessionInterface = [[PA2DefaultSessionInterface alloc] initWithSession:_coreSession dataProvider:sessionDataProvider];
    } else {
        // This instance will use the session sharing.
        // At first, try to determine shared memory identifier.
        NSString * instanceId = _configuration.instanceId;
        NSString * shortSharedMemoryId = _configuration.sharingConfiguration.sharedMemoryIdentifier;
        if (!shortSharedMemoryId) {
            shortSharedMemoryId = [PA2AppGroupContainer shortSharedMemoryIdentifier:instanceId];
            // Store automatically calculated identifier to configuration.
            _configuration.sharingConfiguration.sharedMemoryIdentifier = shortSharedMemoryId;
        }
        // Now prepare PA2AppGroupContainer and build various identifiers.
        PA2AppGroupContainer * appGroupContainer = [PA2AppGroupContainer containerWithAppGroup:_configuration.sharingConfiguration.appGroup];
        NSString * sharedMemoryId = [appGroupContainer sharedMemoryIdentifier:shortSharedMemoryId];
        NSString * statusLockPath = [appGroupContainer pathToFileLockWithIdentifier:[@"statusLock:" stringByAppendingString:instanceId]];
        NSString * operationLockPath = [appGroupContainer pathToFileLockWithIdentifier:[@"operationLock:" stringByAppendingString:instanceId]];
        NSString * queueLockPath = [appGroupContainer pathToFileLockWithIdentifier:[@"queueLock:" stringByAppendingString:instanceId]];
        if (!sharedMemoryId || !statusLockPath || !queueLockPath || !operationLockPath) {
            [PowerAuthSDK throwInvalidConfigurationException];
        }
        // Finally, construct the shared session provider.
        _sessionInterface = [[PA2SharedSessionInterface alloc] initWithSession:_coreSession
                                                                 dataProvider:sessionDataProvider
                                                                   instanceId:instanceId
                                                                applicationId:_configuration.sharingConfiguration.appIdentifier
                                                               sharedMemoryId:sharedMemoryId
                                                               statusLockPath:statusLockPath
                                                             operationLockPath:operationLockPath
                                                                 queueLockPath:queueLockPath];
    }
    // Throw a failure if session provider is not available.
    if (!_sessionInterface) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
    
    // Create and setup a new HTTP client
    _client = [[PA2HttpClient alloc] initWithConfiguration:_clientConfiguration
                                           completionQueue:dispatch_get_main_queue()
                                                   baseUrl:_configuration.baseEndpointUrl
                                      coreSessionInterface:_sessionInterface
                                               timeService:_timeSynchronizationService
                                                    helper:self];
    
    _remoteHttpTokenProvider = [[PA2PrivateHttpTokenProvider alloc] initWithHttpClient:_client];
    _tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:self.configuration
                                                                     keychain:tokenStoreKeychain
                                                               statusProvider:self
                                                               remoteProvider:_remoteHttpTokenProvider
                                                                  timeService:_timeSynchronizationService
                                                                     dataLock:_sessionInterface
                                                                    localLock:_lock];
#if defined(PA2_WATCH_SUPPORT)
    // Register this instance to handle messages
    [[PowerAuthWCSessionManager sharedInstance] registerDataHandler:self];
#endif
}

- (void) dealloc
{
    [(PA2TimeSynchronizationService*)_timeSynchronizationService unsubscribeForSystemNotifications];
#if defined(PA2_WATCH_SUPPORT)
    // Unregister this instance for processing packets...
    [[PowerAuthWCSessionManager sharedInstance] unregisterDataHandler:self];
#endif
    [self cancelAllPendingTasks];
}


+ (void) throwInvalidConfigurationException {
    [NSException raise:PowerAuthExceptionMissingConfig
                format:@"Invalid PowerAuthSDK configuration. You must set a valid PowerAuthConfiguration to PowerAuthSDK instance using initializer."];
}

- (id<PowerAuthTokenStore>) tokenStore
{
    return _tokenStore;
}

- (id<PowerAuthTimeSynchronizationService>) timeSynchronizationService
{
    return _timeSynchronizationService;
}

- (PowerAuthConfiguration*) configuration
{
    return [_configuration copy];
}

- (PowerAuthClientConfiguration*) clientConfiguration
{
    return [_clientConfiguration copy];
}

- (PowerAuthKeychainConfiguration*) keychainConfiguration
{
    return [_keychainConfiguration copy];
}

- (NSString*) privateInstanceId
{
    // Private getter, used inside the IOS-SDK
    return _configuration.instanceId;
}

/**
 This private method checks for valid PowerAuthCoreSessionSetup and throws a PowerAuthExceptionMissingConfig exception when the provided configuration
 is not correct or is missing.
 */
- (void) checkForValidSetup
{
    // This is OK to directly access _coreSession without a proper locking. Setup depends on runtime configuration,
    // so it's not affected by persistent data.
    if (!_coreSession.hasValidSetup) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
}

#pragma mark - Key management

- (NSData*) deviceRelatedKey
{
    // Cache the possession key in the keychain
    NSData * possessionKey = [_sharedKeychain dataForKey:_keychainConfiguration.keychainKey_Possession status:nil];
    if (nil == possessionKey) {
        NSString *uuidString;
#if TARGET_IPHONE_SIMULATOR
        uuidString = @"ffa184f9-341a-444f-8495-de04d0d490be";
#else
        uuidString = [UIDevice currentDevice].identifierForVendor.UUIDString;
#endif
        NSData *uuidData = [uuidString dataUsingEncoding:NSUTF8StringEncoding];
        possessionKey = [PowerAuthCoreSession normalizeSignatureUnlockKeyFromData:uuidData];
        [_sharedKeychain addValue:possessionKey forKey:_keychainConfiguration.keychainKey_Possession];
    }
    return possessionKey;
}

/// Acquire biometry related key from the keychain.
/// - Parameters:
///   - authentication: Keychain authentication object.
///   - error: Pointer to error object to fill when operation fails.
/// - Returns: Biometry related key or nil.
- (NSData*) biometryRelatedKeyWithAuthentication:(nonnull PowerAuthKeychainAuthentication*)authentication error:(NSError **)error
{
#if PA2_HAS_LACONTEXT
    //
    // LAContext is available on this platform
    //
    __block NSData *key = nil;
    __block OSStatus status;
    BOOL executed = [PowerAuthKeychain tryLockBiometryAndExecuteBlock:^{
        key = [_biometryOnlyKeychain dataForKey:_biometryKeyIdentifier status:&status authentication:authentication];
    }];
    if (key) {
        // Key has been successfully retrieved.
        status = errSecSuccess;
    } else if (!executed) {
        // Failed to acquire biometric lock. Simulate cancel in this case.
        status = errSecUserCanceled;
    }
    if (status != errSecSuccess) {
        NSError * localError;
        PowerAuthLog(@"ERROR: Getting key for biometric authentication failed with OSStatus = %@.", @(status));
        // The key was not fetched, try to translate OSStatus to a reasonable meaning.
        if (status == errSecUserCanceled) {
            // User canceled the operation.
            localError = PA2MakeError(PowerAuthErrorCode_BiometryCancel, nil);
        } else if (status == errSecItemNotFound) {
            // Biometric key was not found.
            // Note, that previously we treated this as an authentication error, but this might be
            // an issue in application logic. For example, if app try to authenticate and immediately
            // remove the biometry key.
            localError = PA2MakeError(PowerAuthErrorCode_BiometryFailed, @"Biometric key not found");
        } else if (status == errSecInvalidContext) {
            // Invalid LAContext provided.
            // Be aware that this code is generated in our keychain impl. Don't be confused with the naming,
            // if LAContext is already invalidated, then general `errSecAuthFailed` is returned.
            localError = PA2MakeError(PowerAuthErrorCode_BiometryFailed, @"Invalid LAContext");
        } else if (status == errSecUnimplemented) {
            // PowerAuthKeychainAuthentication was provided on platform that doesn't support it.
            // This may happen only if tvOS application proactively create biometric key in the biometry keychain.
            // In regular and expected setup, accessing biometry protected item on tvOS fails with errSecItemNotFound.
            localError = PA2MakeError(PowerAuthErrorCode_BiometryFailed, @"PowerAuthKeychainAuthentication not supported");
        } else {
            localError = nil;
        }
        // If localError variable is set, then we need to report an error.
        if (localError) {
            if (error) { *error = localError; }
            return nil;
        }
        // No error generated, so create a fake biometry key to fail on the server.
        key = [self generateInvalidBiometricKey];
    } else if (error) {
        // Success, so we should reset object at error pointer.
        *error = nil;
    }

    if (key && _keychainConfiguration.invalidateLocalAuthenticationContextAfterUse) {
        [authentication.context invalidate];
    }
    return key;
#else
    //
    // LAContext is not available on this platform
    //
    if (error) {
        *error = PA2MakeError(PowerAuthErrorCode_BiometryNotAvailable, nil);
    }
    return nil;
#endif
}


- (PowerAuthCoreSignatureUnlockKeys*) signatureKeysForAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                               error:(NSError **)error
{
    // Validate authentication object usage
    [authentication validateUsage:NO];
    
    // Generate signature key encryption keys
    NSData *possessionKey = nil;
    NSData *biometryKey = nil;
    if (authentication.usePossession) {
        if (authentication.overridenPossessionKey) {
            possessionKey = authentication.overridenPossessionKey;
        } else {
            possessionKey = [self deviceRelatedKey];
        }
    }
    if (authentication.useBiometry) {
        if (authentication.overridenBiometryKey) {
            // application specified a custom biometry key
            biometryKey = authentication.overridenBiometryKey;
        } else {
            // default biometry key should be fetched
            biometryKey = [self biometryRelatedKeyWithAuthentication:authentication.keychainAuthentication error:error];
            if (!biometryKey) {
                return nil;
            }
        }
    }
    
    // Prepare signature unlock keys structure
    PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
    keys.possessionUnlockKey = possessionKey;
    keys.biometryUnlockKey = biometryKey;
    keys.userPassword = authentication.password;
    if (error) { *error = nil; }
    return keys;
}

- (PowerAuthCoreSignatureFactor) determineSignatureFactorForAuthentication:(PowerAuthAuthentication*)authentication
{
    PowerAuthCoreSignatureFactor factor = 0;
    if (authentication.usePossession) {
        factor |= PowerAuthCoreSignatureFactor_Possession;
    }
    if (authentication.password != nil) {
        factor |= PowerAuthCoreSignatureFactor_Knowledge;
    }
    if (authentication.useBiometry) {
        factor |= PowerAuthCoreSignatureFactor_Biometry;
    }
    return factor;
}

- (id<PowerAuthOperationTask>) fetchEncryptedVaultUnlockKey:(PowerAuthAuthentication*)authentication
                                                     reason:(PA2VaultUnlockReason)reason
                                                   callback:(void(^)(NSString * encryptedEncryptionKey, NSError *error))callback
{
    [self checkForValidSetup];
    // Check if there is an activation present
    if (!_sessionInterface.hasValidActivation) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_MissingActivation, nil));
        return nil;
    }
    return [_client postObject:[[PA2VaultUnlockRequest alloc] initWithReason:reason]
                            to:[PA2RestApiEndpoint vaultUnlock]
                          auth:authentication
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        NSString * encryptedEncryptionKey = nil;
                        if (status == PowerAuthRestApiResponseStatus_OK) {
                            PA2VaultUnlockResponse * ro = response;
                            encryptedEncryptionKey = ro.encryptedVaultEncryptionKey;
                        }
                        if (!encryptedEncryptionKey && !error) {
                            // fallback to error
                            error = PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
                        }
                        callback(encryptedEncryptionKey, error);
                    }];
}

#pragma mark - Public methods

#pragma mark Initializers and SDK instance getters

static PowerAuthSDK * s_inst;

- (nullable instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                          keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                            clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
{
    self = [super init];
    if (self) {
        [self initializeWithConfiguration:configuration
                    keychainConfiguration:keychainConfiguration
                      clientConfiguration:clientConfiguration];
    }
    return self;
}

- (instancetype)initWithConfiguration:(PowerAuthConfiguration *)configuration
{
    return [self initWithConfiguration:configuration keychainConfiguration:nil clientConfiguration:nil];
}

+ (void) initSharedInstance:(PowerAuthConfiguration*)configuration
{
    [self initSharedInstance:configuration keychainConfiguration:nil clientConfiguration:nil];
}

+ (void) initSharedInstance:(nonnull PowerAuthConfiguration *)configuration
      keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
        clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_inst = [[PowerAuthSDK alloc] initWithConfiguration:configuration
                                       keychainConfiguration:keychainConfiguration
                                         clientConfiguration:clientConfiguration];
    });
}

+ (PowerAuthSDK*) sharedInstance
{
    if (!s_inst) {
        [PowerAuthSDK throwInvalidConfigurationException];
    }
    return s_inst;
}

#pragma mark Session state management

- (BOOL) canStartActivation
{
    [self checkForValidSetup];
    return _sessionInterface.canStartActivation;
}

- (BOOL) hasPendingActivation
{
    [self checkForValidSetup];
    return _sessionInterface.hasPendingActivation;
}

- (BOOL) hasValidActivation
{
    [self checkForValidSetup];
    return _sessionInterface.hasValidActivation;
}

- (BOOL) hasProtocolUpgradeAvailable
{
    [self checkForValidSetup];
    return _sessionInterface.hasProtocolUpgradeAvailable;
}

- (BOOL) hasPendingProtocolUpgrade
{
    [self checkForValidSetup];
    return _sessionInterface.hasPendingProtocolUpgrade;
}

- (id<PowerAuthCoreSessionProvider>) sessionProvider
{
    return _sessionInterface;
}

- (void) cancelAllPendingTasks
{
    [_getActivationStatusTask cancel];
    [_getSystemStatusTask cancel];
    [_tokenStore cancelAllTasks];
}

#pragma mark - Activation
#pragma mark Creating a new activation

- (id<PowerAuthOperationTask>) createActivation:(PowerAuthActivation*)activation
                                       callback:(void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback
{
    // Input parameters check
    [self checkForValidSetup];
    
    if (!callback) {
        PowerAuthLog(@"Missing callback in createActivation() method.");
        return nil;
    }
    if (!activation) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_WrongParameter, nil));
        return nil;
    }
    NSError * error = [activation validateAndGetError];
    if (error) {
        callback(nil, error);
        return nil;
    }
 
    // Prepare both layers of activation data
    PA2CreateActivationRequest * request = [[PA2CreateActivationRequest alloc] init];
    request.activationType = activation.activationType;
    request.identityAttributes = activation.identityAttributes;
    request.customAttributes = activation.customAttributes;
    
    PA2CreateActivationRequestData * requestData = [[PA2CreateActivationRequestData alloc] init];
    requestData.activationName = activation.name;
    requestData.extras = activation.extras;
    requestData.activationOtp = activation.additionalActivationOtp;
    requestData.platform = [PowerAuthSystem platform];
    requestData.deviceInfo = [PowerAuthSystem deviceInfo];
    
    PowerAuthCoreEciesEncryptor * decryptor = [[_sessionInterface writeTaskWithSession:^id _Nullable(PowerAuthCoreSession * _Nonnull session) {
        return [self prepareActivation:activation
                            forRequest:request
                           requestData:requestData
                               session:session];
    }] extractResult:&error];
    
    if (!decryptor) {
        callback(nil, error);
        return nil;
    }
    
    // The create activation endpoint needs a custom object processing where we encrypt the inner data
    // with a different encryptor. We have to do this in the HTTP client's queue to guarantee that time
    // service is already synchronized.
    PA2RestApiEndpoint * endpoint = [PA2RestApiEndpoint createActivationWithCustomStep:^NSError *{
        // Encrypt payload and put it directly to the request object.
        NSError * localError = nil;
        request.activationData = [PA2ObjectSerialization encryptObject:requestData
                                                             encryptor:decryptor
                                                                 error:&localError];
        return localError;
    }];
    
    // Now it's everything prepared for sending the request
    return [_client postObject:request
                            to:endpoint
                          auth:nil
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        // HTTP request completion
                        PowerAuthActivationResult * result = [[_sessionInterface writeTaskWithSession:^PA2Result<PowerAuthActivationResult*>* (PowerAuthCoreSession * session) {
                            if (status == PowerAuthRestApiResponseStatus_OK) {
                                // Validate response from the server
                                return [self validateActivationResponse:response
                                                              decryptor:decryptor
                                                                session:session];
                            }
                            [session resetSession];
                            return [PA2Result failure:error ? error : PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil)];
                        }] extractResult:&error];
        
                        // Now call back to the application
                        callback(result, error);
                        
                    } cancel:^{
                        // In case of cancel, we need to reset the session. The reset itself is
                        // thread safe, but it's good to issue that to the main thread.
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_sessionInterface resetSession];
                        });
                    }];
}

- (id<PowerAuthOperationTask>) createActivationWithName:(NSString*)name
                                         activationCode:(NSString*)activationCode
                                               callback:(void(^)(PowerAuthActivationResult *result, NSError *error))callback
{
    return [self createActivationWithName:name activationCode:activationCode extras:nil callback:callback];
}

- (id<PowerAuthOperationTask>) createActivationWithName:(NSString*)name
                                         activationCode:(NSString*)activationCode
                                                 extras:(NSString*)extras
                                               callback:(void(^)(PowerAuthActivationResult *result, NSError *error))callback
{
    NSError * error = nil;
    PowerAuthActivation * activation = [[PowerAuthActivation activationWithActivationCode:activationCode name:name error:&error] withExtras:extras];
    if (!activation && callback) {
        // Invalid activation code
        callback(nil, error ? error : PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil));
        return nil;
    }
    return [self createActivation:activation callback:callback];
}

- (id<PowerAuthOperationTask>) createActivationWithName:(NSString*)name
                                     identityAttributes:(NSDictionary<NSString*,NSString*>*)identityAttributes
                                                 extras:(NSString*)extras
                                               callback:(void(^)(PowerAuthActivationResult * result, NSError * error))callback
{
    NSError * error = nil;
    PowerAuthActivation * activation = [[PowerAuthActivation activationWithIdentityAttributes:identityAttributes name:name error:&error] withExtras:extras];
    if (!activation && callback) {
        // Missing identity attributes
        callback(nil, error ? error : PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil));
        return nil;
    }
    return [self createActivation:activation callback:callback];
}

- (nullable id<PowerAuthOperationTask>) createActivationWithName:(nullable NSString*)name
                                                    recoveryCode:(nonnull NSString*)recoveryCode
                                                             puk:(nonnull NSString*)puk
                                                          extras:(nullable NSString*)extras
                                                        callback:(nonnull void(^)(PowerAuthActivationResult * result, NSError * error))callback
{
    NSError * error = nil;
    PowerAuthActivation * activation = [[PowerAuthActivation activationWithRecoveryCode:recoveryCode recoveryPuk:puk name:name error:&error] withExtras:extras];
    if (!activation && callback) {
        // Wrong recovery code or PUK
        callback(nil, error ? error : PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil));
        return nil;
    }
    return [self createActivation:activation callback:callback];
}

#pragma mark Commit

- (BOOL) persistActivationWithPassword:(NSString*)password
                                 error:(NSError**)error
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithPassword:password]
                                               error:error];
}

- (BOOL) persistActivationWithCorePassword:(PowerAuthCorePassword *)password
                                     error:(NSError **)error
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithCorePassword:password]
                                               error:error];
}

- (BOOL) persistActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                       error:(NSError**)error
{
    [self checkForValidSetup];
    
    // Validate authentication object usage
    [authentication validateUsage:YES];
    
    NSError * reportedError = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
        // Check if there is a pending activation present and not an already existing valid activation
        if (!session.hasPendingActivation) {
            return PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
        }
        // Prepare key encryption keys
        NSData *possessionKey = nil;
        NSData *biometryKey = nil;
        if (authentication.usePossession) {
            possessionKey = [self deviceRelatedKey];
        }
        if (authentication.useBiometry) {
            biometryKey = [PowerAuthCoreSession generateSignatureUnlockKey];
        }
        
        // Prepare signature unlock keys structure
        PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
        keys.possessionUnlockKey = possessionKey;
        keys.biometryUnlockKey = biometryKey;
        keys.userPassword = authentication.password;
        
        // Complete the activation
        BOOL result = [session completeActivation:keys];
        // Store keys in Keychain
        if (result) {
            [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
            if (biometryKey) {
                [_biometryOnlyKeychain addValue:biometryKey forKey:_biometryKeyIdentifier access:_keychainConfiguration.biometricItemAccess];
            }
            // Clear TokenStore
            [_tokenStore removeAllLocalTokens];
        }
        return result ? nil : PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
    }];
    if (reportedError && error) {
        *error = reportedError;
    }
    return !reportedError;
}

// PA2_DEPRECATED(1.8.0)
- (BOOL) commitActivationWithPassword:(NSString*)password
                                error:(NSError**)error
{
    return [self persistActivationWithPassword:password error:error];
}

// PA2_DEPRECATED(1.8.0)
- (BOOL) commitActivationWithCorePassword:(PowerAuthCorePassword *)password
                                    error:(NSError **)error
{
    return [self persistActivationWithCorePassword:password error:error];
}

// PA2_DEPRECATED(1.8.0)
- (BOOL) commitActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                      error:(NSError**)error
{
    return [self persistActivationWithAuthentication:authentication error:error];
}


- (NSString*) activationIdentifier
{
    return _sessionInterface.activationIdentifier;
}

- (NSString*) activationFingerprint
{
    return [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session) {
        return session.activationFingerprint;
    }];
}


#pragma mark Private activation

/**
 Private method starts an activation.
 
 The method requires request & request data and if everything's right, then request.activationData
 is prepared and metods returns a new decryptor, required for response decryption.
 */
- (PA2Result<PowerAuthCoreEciesEncryptor*>*) prepareActivation:(PowerAuthActivation*)activation
                                                    forRequest:(PA2CreateActivationRequest*)request
                                                   requestData:(PA2CreateActivationRequestData*)requestData
                                                       session:(PowerAuthCoreSession*)session
{
    BOOL resetState = YES;
    NSError * localError = nil;
    // Check if activation can be started
    if ([session canStartActivation]) {
        // Prepare data for low level code. Note that "activationCode" is optional and may be nil.
        PowerAuthCoreActivationStep1Param * paramStep1 = [[PowerAuthCoreActivationStep1Param alloc] init];
        paramStep1.activationCode = activation.activationCode.coreActivationCode;

        // Begin with the activation
        PowerAuthCoreActivationStep1Result * resultStep1 = [session startActivation:paramStep1];
        if (resultStep1) {
            // Keep device's public key in requestData
            requestData.devicePublicKey = resultStep1.devicePublicKey;

            // Now we need to ecrypt request data with the Layer2 encryptor.
            PowerAuthCoreEciesEncryptor * privateEncryptor = [self encryptorWithId:PA2EncryptorId_ActivationPayload error:&localError];
            if (!localError) {
                // Everything looks OS, so finally, try notify other apps that this instance started the activation.
                localError = [_sessionInterface startExternalPendingOperation:PowerAuthExternalPendingOperationType_Activation];
                if (!localError) {
                    return [PA2Result success:privateEncryptor];
                }
            }
        } else {
            localError = PA2MakeError(PowerAuthErrorCode_InvalidActivationData, nil);
        }
    } else {
        resetState = NO; // Don't reset state, there's already existing or pendign activation
        localError = PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
    }
    if (resetState) {
        [session resetSession];
    }
    return [PA2Result failure:localError];
}

/**
 Private method validates response received from the server.
 In case of success, returns a full activation result object.
 */
- (PA2Result<PowerAuthActivationResult*>*) validateActivationResponse:(PA2CreateActivationResponse*)response
                                                            decryptor:(PowerAuthCoreEciesEncryptor*)decryptor
                                                              session:(PowerAuthCoreSession*)session
{
    NSError * localError = nil;
    PA2CreateActivationResponseData * responseData = [PA2ObjectSerialization decryptObject:response.activationData
                                                                                  forClass:[PA2CreateActivationResponseData class]
                                                                                 decryptor:decryptor
                                                                                     error:&localError];
    if (responseData) {
        // Validate response from the server
        PowerAuthCoreActivationStep2Param * paramStep2 = [[PowerAuthCoreActivationStep2Param alloc] init];
        paramStep2.activationId = responseData.activationId;
        paramStep2.serverPublicKey = responseData.serverPublicKey;
        paramStep2.ctrData = responseData.ctrData;
        PowerAuthActivationRecoveryData * activationRecoveryData = nil;
        if (responseData.activationRecovery) {
            PowerAuthCoreRecoveryData * recoveryData = [[PowerAuthCoreRecoveryData alloc] init];
            recoveryData.recoveryCode = responseData.activationRecovery.recoveryCode;
            recoveryData.puk = responseData.activationRecovery.puk;
            paramStep2.activationRecovery = recoveryData;
            activationRecoveryData = [[PowerAuthActivationRecoveryData alloc] initWithRecoveryData:recoveryData];
        }
        PowerAuthCoreActivationStep2Result * resultStep2 = [session validateActivationResponse:paramStep2];
        if (resultStep2) {
            // Everything looks OK, we can construct result object.
            PowerAuthActivationResult * result = [[PowerAuthActivationResult alloc] init];
            result.activationFingerprint = resultStep2.activationFingerprint;
            result.customAttributes = response.customAttributes;
            result.activationRecovery = activationRecoveryData;
            result.userInfo = [[PowerAuthUserInfo alloc] initWithDictionary:response.userInfo];
            [self setLastFetchedUserInfo:result.userInfo];
            return [PA2Result success:result];
        } else {
            localError = PA2MakeError(PowerAuthErrorCode_InvalidActivationData, @"Failed to verify response from the server");
        }
    }
    // If failure, then reset session and report error.
    [session resetSession];
    return [PA2Result failure:localError];
}


#pragma mark Getting activations state

- (id<PowerAuthOperationTask>) getActivationStatusWithCallback:(void(^)(PowerAuthActivationStatus * status, NSError * error))callback
{
    [self checkForValidSetup];
    // Check for activation
    NSError * stateError = [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session) {
        if (!session.hasValidActivation) {
            NSInteger errorCode = session.hasPendingActivation ? PowerAuthErrorCode_ActivationPending : PowerAuthErrorCode_MissingActivation;
            return PA2MakeError(errorCode, nil);
        }
        return nil;
    }];
    if (stateError) {
        callback(nil, stateError);
        return nil;
    }
    
    [_lock lock];
    //
    id<PowerAuthOperationTask> task = [_getActivationStatusTask createChildTask:callback];
    if (!task) {
        // If there's no grouping task, or task is already finished, then simply create new one with the child task.
        _getActivationStatusTask = [[PA2GetActivationStatusTask alloc] initWithHttpClient:_client
                                                               deviceRelatedKey:[self deviceRelatedKey]
                                                                sessionProvider:_sessionInterface
                                                                       delegate:self
                                                                     sharedLock:_lock
                                                                 disableUpgrade:_configuration.disableAutomaticProtocolUpgrade];
        task = [_getActivationStatusTask createChildTask:callback];
    }
    //
    [_lock unlock];
    return task;
}

- (void) getActivationStatusTask:(PA2GetActivationStatusTask*)task didFinishedWithStatus:(PowerAuthActivationStatus*)status error:(NSError*)error
{
    // [_lock lock] is guaranteed, because this method is called from task's completion while locked with shared lock.
    // So, we can freely mutate objects in this instance.
    if (_getActivationStatusTask == task) {
        _getActivationStatusTask = nil;
        if (status) {
            _lastFetchedActivationStatus = status;
        }
        // This is the reference to task which is going to finish its execution soon.
        // The ivar no longer holds the reference to the task, but we should keep that reference
        // for a little bit longer, to guarantee, that we don't destroy that object during its
        // finalization stage.
        [[NSOperationQueue mainQueue] addOperationWithBlock:^{
            // The following call does nothing, because the old task is no longer stored
            // in the `_getStatusTask` ivar. It just guarantees that the object will be alive
            // during waiting to execute the operation block.
            [self getActivationStatusTask:task didFinishedWithStatus:nil error:nil];
        }];
    }
}

- (PowerAuthActivationStatus*) lastFetchedActivationStatus
{
    [_lock lock];
    PowerAuthActivationStatus * status = _lastFetchedActivationStatus;
    [_lock unlock];
    return status;
}

#pragma mark Removing an activation

- (id<PowerAuthOperationTask>) removeActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                                         callback:(void(^)(NSError *error))callback
{
    [self checkForValidSetup];
    return [_client postObject:nil
                            to:[PA2RestApiEndpoint removeActivation]
                          auth:authentication
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        // Network communication completed correctly
                        if (status == PowerAuthRestApiResponseStatus_OK) {
                            [self removeActivationLocal];
                        }
                        callback(error);
                    }];
}

- (void) removeActivationLocal
{
    [self checkForValidSetup];
    [self cancelAllPendingTasks];
    [self clearCachedData];
    [_sessionInterface writeVoidTaskWithSession:^(PowerAuthCoreSession * session) {
        BOOL error = NO;
        if ([_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier]) {
            error = ![_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        }
        if (error) {
            PowerAuthLog(@"Removing activaton data from keychain failed. We can't recover from this error.");
        }
        [_tokenStore removeAllLocalTokens];
        [session resetSession];
    }];
}

/**
 Clear in-memory cached data.
 */
- (void) clearCachedData
{
    [_lock lock];
    _lastFetchedActivationStatus = nil;
    _lastFetchedUserInfo = nil;
    [_lock unlock];
}

#pragma mark - Computing signatures

- (PowerAuthAuthorizationHttpHeader*) requestGetSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                                                      uriId:(NSString*)uriId
                                                                     params:(NSDictionary<NSString*, NSString*>*)params
                                                                      error:(NSError**)error
{
    NSData *data = [PowerAuthCoreSession prepareKeyValueDictionaryForDataSigning:params];
    return [self requestSignatureWithAuthentication:authentication
                                             method:@"GET"
                                              uriId:uriId
                                               body:data
                                              error:error];
}

- (PowerAuthAuthorizationHttpHeader*) requestSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                                                  method:(NSString*)method
                                                                   uriId:(NSString*)uriId
                                                                    body:(NSData*)body
                                                                   error:(NSError**)error
{
    return [[_sessionInterface readTaskWithSession:^PA2Result<PowerAuthAuthorizationHttpHeader*>* (PowerAuthCoreSession * session) {
        if (session.hasPendingProtocolUpgrade) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_PendingProtocolUpgrade, @"Data signing is temporarily unavailable, due to pending protocol upgrade.")];
        }
        NSError * localError = nil;
        PowerAuthCoreHTTPRequestData * requestData = [[PowerAuthCoreHTTPRequestData alloc] init];
        requestData.body = body;
        requestData.method = method;
        requestData.uri = uriId;
        PowerAuthCoreHTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
                                                                       authentication:authentication
                                                                                error:&localError];
        if (signature) {
            return [PA2Result success:[PowerAuthAuthorizationHttpHeader authorizationHeaderWithValue:signature.authHeaderValue]];
        }
        return [PA2Result failure:localError];
    }] extractResult:error];
}

- (NSString*) offlineSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                           uriId:(NSString*)uriId
                                            body:(NSData*)body
                                           nonce:(NSString*)nonce
                                           error:(NSError**)error
{
    return [[_sessionInterface readTaskWithSession:^PA2Result<NSString*>* (PowerAuthCoreSession * session) {
        NSError * localError = nil;
        if (!nonce) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Nonce parameter is missing.")];
        }
        
        if (session.hasPendingProtocolUpgrade) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_PendingProtocolUpgrade, @"Offline data signing is temporarily unavailable, due to pending protocol upgrade.")];
        }
        
        PowerAuthCoreHTTPRequestData * requestData = [[PowerAuthCoreHTTPRequestData alloc] init];
        requestData.body = body;
        requestData.method = @"POST";
        requestData.uri = uriId;
        requestData.offlineNonce = nonce;
        requestData.offlineSignatureSize = _configuration.offlineSignatureComponentLength;
        PowerAuthCoreHTTPRequestDataSignature * signature = [self signHttpRequestData:requestData
                                                                       authentication:authentication
                                                                                error:&localError];
        if (signature) {
            return [PA2Result success:signature.signature];
        }
        return [PA2Result failure:localError];
    }] extractResult:error];
}


/**
 This private method implements both online & offline signature calculations. Unlike the public interfaces, method accepts
 PA2HTTPRequestData object as a source for data for signing and returns structured PA2HTTPRequestDataSignature object.
 */
- (PowerAuthCoreHTTPRequestDataSignature*) signHttpRequestData:(PowerAuthCoreHTTPRequestData*)requestData
                                                authentication:(PowerAuthAuthentication*)authentication
                                                         error:(NSError**)error
{
    [self checkForValidSetup];
    
    return [[_sessionInterface writeTaskWithSession:^PA2Result<PowerAuthCoreHTTPRequestDataSignature*>* (PowerAuthCoreSession * session) {
        // Check if there is an activation present
        if (!session.hasValidActivation) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_MissingActivation, nil)];
        }
        
        // Determine authentication factor type
        PowerAuthCoreSignatureFactor factor = [self determineSignatureFactorForAuthentication:authentication];
        if (factor == 0) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_WrongParameter, nil)];
        }
        
        // Generate signature key encryption keys
        NSError * localError = nil;
        PowerAuthCoreSignatureUnlockKeys *keys = [self signatureKeysForAuthentication:authentication error:&localError];
        if (keys == nil) { // Unable to fetch Touch ID related record - maybe user or iOS canacelled the operation?
            return [PA2Result failure:localError];
        }
        
        // Compute signature for provided values and return result.
        PowerAuthCoreHTTPRequestDataSignature * signature = [session signHttpRequestData:requestData keys:keys factor:factor];
        if (signature == nil) {
            return [PA2Result failure:PA2MakeError(PowerAuthErrorCode_SignatureError, nil)];
        }
        return [PA2Result success:signature];
        
    }] extractResult:error];
}


- (BOOL) verifyServerSignedData:(nonnull NSData*)data
                      signature:(nonnull NSString*)signature
                      masterKey:(BOOL)masterKey
{
    [self checkForValidSetup];
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        PowerAuthCoreSignedData * signedData = [[PowerAuthCoreSignedData alloc] init];
        signedData.signingDataKey = masterKey ? PowerAuthCoreSigningDataKey_ECDSA_MasterServerKey : PowerAuthCoreSigningDataKey_ECDSA_PersonalizedKey;
        signedData.data = data;
        signedData.signatureBase64 = signature;
        return [session verifyServerSignedData: signedData];
    }];
}


#pragma mark - Password

// PowerAuthCorePassword versions

- (BOOL) unsafeChangeCorePasswordFrom:(PowerAuthCorePassword*)oldPassword
                                   to:(PowerAuthCorePassword*)newPassword
{
    return [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        return [session changeUserPassword:oldPassword newPassword:newPassword];
    }];
}

- (id<PowerAuthOperationTask>) changeCorePasswordFrom:(PowerAuthCorePassword*)oldPassword
                                                   to:(PowerAuthCorePassword*)newPassword
                                             callback:(void(^)(NSError *error))callback
{
    return [self validateCorePassword:oldPassword callback:^(NSError * error) {
        if (!error) {
            error = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
                // Let's change the password
                BOOL result = [session changeUserPassword:oldPassword newPassword:newPassword];
                return result ? nil : PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
            }];
        }
        // Call back to application
        callback(error);
    }];
}

- (id<PowerAuthOperationTask>) validateCorePassword:(PowerAuthCorePassword*)password callback:(void(^)(NSError * error))callback
{
    [self checkForValidSetup];
    return [_client postObject:[PA2ValidateSignatureRequest requestWithReason:@"VALIDATE_PASSWORD"]
                            to:[PA2RestApiEndpoint validateSignature]
                          auth:[PowerAuthAuthentication possessionWithCorePassword:password]
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        callback(error);
                    }];
}

// NSString versions

- (BOOL) unsafeChangePasswordFrom:(NSString*)oldPassword
                               to:(NSString*)newPassword
{
    return [self unsafeChangeCorePasswordFrom:[PowerAuthCorePassword passwordWithString:oldPassword]
                                           to:[PowerAuthCorePassword passwordWithString:newPassword]];
}

- (id<PowerAuthOperationTask>) changePasswordFrom:(NSString*)oldPassword
                                               to:(NSString*)newPassword
                                         callback:(void(^)(NSError *error))callback
{
    return [self changeCorePasswordFrom:[PowerAuthCorePassword passwordWithString:oldPassword]
                                     to:[PowerAuthCorePassword passwordWithString:newPassword]
                               callback:callback];
}

- (id<PowerAuthOperationTask>) validatePassword:(NSString*)password callback:(void (^)(NSError *))callback
{
    return [self validateCorePassword:[PowerAuthCorePassword passwordWithString:password] callback:callback];
}

#pragma mark - Biometry

- (id<PowerAuthOperationTask>) addBiometryFactorWithCorePassword:(PowerAuthCorePassword*)password
                                                        callback:(void(^)(NSError *error))callback
{
    // Check if biometry can be used
    if (![PowerAuthKeychain canUseBiometricAuthentication]) {
        callback(PA2MakeError(PowerAuthErrorCode_BiometryNotAvailable, nil));
        return nil;
    }
    PowerAuthAuthentication * authentication = [PowerAuthAuthentication possessionWithCorePassword:password];
    return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_ADD_BIOMETRY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
        if (!error) {
            // Let's add the biometry key
            PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
            keys.possessionUnlockKey = [self deviceRelatedKey];
            keys.biometryUnlockKey = [PowerAuthCoreSession generateSignatureUnlockKey];
            // Setup biometric factor in session
            error = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
                if ([session addBiometryFactor:encryptedEncryptionKey keys:keys]) {
                    // Update keychain values after each successful calculations
                    [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
                    [_biometryOnlyKeychain addValue:keys.biometryUnlockKey forKey:_biometryKeyIdentifier access:_keychainConfiguration.biometricItemAccess];
                    return nil;
                } else {
                    return PA2MakeError(PowerAuthErrorCode_InvalidActivationState, nil);
                }
            }];
        }
        // Call back to application
        callback(error);
    }];
}

- (id<PowerAuthOperationTask>) addBiometryFactorWithPassword:(NSString *)password callback:(void (^)(NSError *))callback
{
    return [self addBiometryFactorWithCorePassword:[PowerAuthCorePassword passwordWithString:password] callback:callback];
}

- (BOOL) hasBiometryFactor
{
    [self checkForValidSetup];
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        return [_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier] &&
               [session hasBiometryFactor];
    }];
}

- (BOOL) removeBiometryFactor
{
    [self checkForValidSetup];
    return [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        BOOL result = [session removeBiometryFactor];
        if (result) {
            // Update keychain values after each successful calculations
            [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        }
        return result;
    }];
}

#if PA2_HAS_LACONTEXT

// If LAContext is available then we assume that biometry is also available on the platform.

- (void) authenticateUsingBiometryWithPrompt:(NSString *)prompt
                                    callback:(void(^)(PowerAuthAuthentication * authentication, NSError * error))callback
{
    [self authenticateUsingBiometryImpl:[[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt] callback:callback];
}

- (void) unlockBiometryKeysWithPrompt:(NSString*)prompt
                            withBlock:(void(^)(NSDictionary<NSString*, NSData*> *keys, BOOL userCanceled))block
{
    [self unlockBiometryKeysImpl:[[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt] withBlock:block];
}

- (void) authenticateUsingBiometryWithContext:(LAContext *)context
                                     callback:(void (^)(PowerAuthAuthentication *, NSError *))callback
{
    [self authenticateUsingBiometryImpl:[[PowerAuthKeychainAuthentication alloc] initWithContext:context] callback:callback];
}

- (void) unlockBiometryKeysWithContext:(LAContext *)context
                             withBlock:(void (^)(NSDictionary<NSString *,NSData *> *, BOOL))block
{
    [self unlockBiometryKeysImpl:[[PowerAuthKeychainAuthentication alloc] initWithContext:context] withBlock:block];
}

- (void) authenticateUsingBiometryImpl:(PowerAuthKeychainAuthentication *)keychainAuthentication
                              callback:(void(^)(PowerAuthAuthentication * authentication, NSError * error))callback
{
    [self checkForValidSetup];
    
    // Check if activation is present
    if (!_sessionInterface.hasValidActivation) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_MissingActivation, nil));
        return;
    }
    
    // Check biometric status in advance, to do not increase failed attempts counter
    // in case that biometry is already locked out.
    if (![PowerAuthKeychain canUseBiometricAuthentication]) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_BiometryNotAvailable, nil));
        return;
    }
    
    // Use app provided, or create a new LAContext if "prompt" variant is used.
    NSString * prompt = keychainAuthentication.prompt;
    LAContext * context = keychainAuthentication.context;
    if (!context) {
        // No context is provided, so we have to create a new one and re-create keychain authentication
        // to use this context.
        if (!prompt) {
            prompt = @"< missing prompt >";
        }
        context = [[LAContext alloc] init];
        context.localizedReason = prompt;
        context.localizedFallbackTitle = @""; // hide fallback button to match our original behavior
        keychainAuthentication = [[PowerAuthKeychainAuthentication alloc] initWithContext:context];
    } else {
        // Application provided context is available, simply make sure that some prompt is set.
        prompt = context.localizedReason;
        if (!prompt) {
            prompt = @"< missing prompt >";
        }
    }
    // Prepare policy based on keychain configuration.
    LAPolicy policy;
    if (_keychainConfiguration.biometricItemAccess == PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode) {
        // The naming is awkward, but 'LAPolicyDeviceOwnerAuthentication' really means that
        // we're requesting biometry and the device's passcode
        policy = LAPolicyDeviceOwnerAuthentication;
    } else {
        // In this case, only biometry can be used.
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    }
    // Now evaluate the policy
    [context evaluatePolicy:policy localizedReason:prompt reply:^(BOOL success, NSError * _Nullable error) {
        PowerAuthAuthentication * authentication;
        if (success) {
            // The LAContext should be pre-authorized now, so the operation is no longer blocking.
            // Acquire key to unlock biometric factor
            NSData * biometryKey = [self biometryRelatedKeyWithAuthentication:keychainAuthentication error:&error];
            if (biometryKey) {
                // The biometry key is available, so create a new PowerAuthAuthentication object preconfigured
                // with possession+biometry factors.
                authentication = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:biometryKey
                                                                                  customPossessionKey:nil];
                error = nil;
            } else {
                // Otherwise report an error depending on whether the operation was canceled by the user.
                authentication = nil;
            }
        } else {
            // Evaluation failed, we should investigate LAError
            authentication = nil;
            // Embed an original error
            NSDictionary * errorInfo = error ? @{ NSUnderlyingErrorKey: error } : nil;
            if ([error.domain isEqualToString:LAErrorDomain]) {
                switch (error.code) {
                    case LAErrorAuthenticationFailed:   // User failed to provide valid credentials.
                    case LAErrorBiometryLockout:        // Too many failed attempts, biometry is now locked out.
                        // Authentication failed, now it's time to generate the fake key
                        authentication = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:[self generateInvalidBiometricKey]
                                                                                          customPossessionKey:nil];
                        error = nil;
                        break;
                        
                    case LAErrorPasscodeNotSet:
                        // Passcode is not set, so the biometric authentication cannot start.
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryNotAvailable, @"Device's passcode is not set", errorInfo);
                        break;
                        
                    case LAErrorBiometryNotAvailable:
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryNotAvailable, @"Biometry not supported", errorInfo);
                        break;
                        
                    case LAErrorBiometryNotEnrolled:
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryNotAvailable, @"Biometry not enrolled", errorInfo);
                        break;
                    
                    case LAErrorSystemCancel:           // Systme cancel (e.g. user pressed power or home button)
                    case LAErrorAppCancel:              // App cancel, (e.g. application called invalidate on its context)
                    case LAErrorUserCancel:             // User tapped on cancel button
                        // All cancel types leads to our cancel
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryCancel, nil, errorInfo);
                        break;
                        
                    case LAErrorUserFallback:           // Canceled, because user tapped on the fallback button.
                        // All cancel types leads to our cancel
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryFallback, nil, errorInfo);
                        break;
                        
                    case LAErrorNotInteractive:         // App should not set interactionNotAllowed property to true
                    case LAErrorInvalidContext:         // Context is already invalidated
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_WrongParameter, @"LAContext is not valid", errorInfo);
                        break;
                        
                    default:
                        error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryFailed, @"Biometry failed", errorInfo);
                        break;
                }
            } else {
                error = PA2MakeErrorInfo(PowerAuthErrorCode_BiometryFailed, @"Biometry failed with unknown error", errorInfo);
            }
        }
        
        // Report result back to the main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            callback(authentication, error);
        });
    }];
}

- (void) unlockBiometryKeysImpl:(PowerAuthKeychainAuthentication*)keychainAuthentication
                      withBlock:(void(^)(NSDictionary<NSString*, NSData*> *keys, BOOL userCanceled))block
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __block OSStatus status;
        __block NSDictionary *keys;
        BOOL executed = [PowerAuthKeychain tryLockBiometryAndExecuteBlock:^{
            keys = [_biometryOnlyKeychain allItemsWithAuthentication:keychainAuthentication withStatus:&status];
        }];
        BOOL userCanceled = !executed || (status == errSecUserCanceled);
        block(keys, userCanceled);
    });
}

/// Generate new invalid biometric key. The function is used in situations when biometric authentication failed
/// and SDK needs to increase fail attempts count on the server. By generating invalid key we pretend that
/// everything's OK but the final result is that server rejects such signature.
- (NSData*) generateInvalidBiometricKey
{
    PowerAuthLog(@"WARNING: Generating fake biometry key to increase failed attempts counter on the server.");
    return [PowerAuthCoreSession generateSignatureUnlockKey];
}

#endif // PA2_HAS_LACONTEXT

#pragma mark - Secure vault support


- (id<PowerAuthOperationTask>) fetchEncryptionKey:(PowerAuthAuthentication*)authentication
                                            index:(UInt64)index
                                         callback:(void(^)(NSData *encryptionKey, NSError *error))callback
{
    return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_FETCH_ENCRYPTION_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
        NSData * encryptionKey = nil;
        if (!error) {
            // Let's unlock encryption key
            PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
            keys.possessionUnlockKey = [self deviceRelatedKey];
            encryptionKey = [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session) {
                return [session deriveCryptographicKeyFromVaultKey:encryptedEncryptionKey
                                                              keys:keys
                                                          keyIndex:index];
            }];
            if (!encryptionKey) {
                error = PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to derive encryption key");
            }
        }
        // Call back to application
        callback(encryptionKey, error);
    }];
}

#pragma mark - Asymmetric signatures

- (id<PowerAuthOperationTask>) signDataWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
                                                       data:(NSData*)data
                                                     format:(PowerAuthCoreSignatureFormat)format
                                                   callback:(void(^)(NSData *signature, NSError *error))callback
{
    return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_SIGN_WITH_DEVICE_PRIVATE_KEY callback:^(NSString *encryptedEncryptionKey, NSError *error) {
        NSData *signature = nil;
        if (!error) {
            // Let's sign the data
            PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
            keys.possessionUnlockKey = [self deviceRelatedKey];
            signature = [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session) {
                return [session signDataWithDevicePrivateKey:encryptedEncryptionKey
                                                        keys:keys
                                                        data:data
                                                      format:format];
            }];
            // Propagate error
            if (!signature) {
                error = PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to calculate signature");
            }
        }
        // Call back to application
        callback(signature, error);
    }];
}

- (id<PowerAuthOperationTask>) signDataWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
                                                       data:(NSData*)data
                                                   callback:(void(^)(NSData *signature, NSError *error))callback
{
    return [self signDataWithDevicePrivateKey:authentication
                                         data:data
                                       format:PowerAuthCoreSignatureFormat_ECDSA_DER
                                     callback:callback];
}

- (id<PowerAuthOperationTask>) signJwtWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
                                                    claims:(NSDictionary<NSString*, NSObject*>*)claims
                                                  callback:(void(^)(NSString *jwt, NSError *error))callback
{
    // Prepare JWT Header
    NSString * jwtHeader = @"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."; // {"alg":"ES256","typ":"JWT"}
    // Prepare claims data
    NSData * claimsData = [NSJSONSerialization dataWithJSONObject:claims options:0 error:nil];
    // Prepare data for signing
    NSString * signedData = [jwtHeader stringByAppendingString:[claimsData jwtEncodedString]];
    // Calculate signature
    return [self signDataWithDevicePrivateKey:authentication
                                         data:[signedData dataUsingEncoding:NSASCIIStringEncoding]
                                       format:PowerAuthCoreSignatureFormat_ECDSA_JOSE
                                     callback:^(NSData * signature, NSError * error) {
        // Handle error
        if (error) {
            callback(nil, error);
            return;
        }
        // Base64 Encode Signature
        NSString *jwtSignature = [signature jwtEncodedString];
        // Construct JWT
        NSString *jwt = [[signedData stringByAppendingString:@"."] stringByAppendingString:jwtSignature];
        // Call back to application
        callback(jwt, nil);
    }];
}

@end

#pragma mark - End-2-End Encryption

@implementation PowerAuthSDK (E2EE)

- (PowerAuthCoreEciesEncryptor*) eciesEncryptorForApplicationScope
{
    PA2PrivateEncryptorFactory * factory = [[PA2PrivateEncryptorFactory alloc] initWithSessionProvider:_sessionInterface deviceRelatedKey:nil];
    return [factory encryptorWithId:PA2EncryptorId_GenericApplicationScope error:nil];
}

- (PowerAuthCoreEciesEncryptor*) eciesEncryptorForActivationScope
{
    return [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session) {
        if (!session.hasValidActivation) {
            PowerAuthLog(@"eciesEncryptorForActivation: There's no activation.");
            return nil;
        }
        NSData * deviceKey = [self deviceRelatedKey];
        PA2PrivateEncryptorFactory * factory =  [[PA2PrivateEncryptorFactory alloc] initWithSessionProvider:_sessionInterface deviceRelatedKey:deviceKey];
        return [factory encryptorWithId:PA2EncryptorId_GenericActivationScope error:nil];
    }];
}

@end


#pragma mark - Request synchronization

@implementation PowerAuthSDK (RequestSync)

- (nullable id<PowerAuthOperationTask>) executeBlockOnSerialQueue:(void(^ _Nonnull)(id<PowerAuthOperationTask> _Nonnull task))execute
{
    PA2AsyncOperation * operation = [[PA2AsyncOperation alloc] initWithReportQueue:dispatch_get_main_queue()];
    operation.executionBlock = ^id(PA2AsyncOperation *op) {
        execute(op);
        return nil;
    };
    return [self executeOperationOnSerialQueue:operation] ? operation : nil;
}

- (BOOL) executeOperationOnSerialQueue:(nonnull NSOperation *)operation
{
    if (![self hasValidActivation]) {
        PowerAuthLog(@"executeOperationOnSerialQueue: There's no activation.");
        return NO;
    }
    // Add operation to serialized queue.
    [_sessionInterface addOperation:operation toSharedQueue:_client.serialQueue];
    return YES;
}

@end



#pragma mark - Recovery codes

@implementation PowerAuthSDK (RecoveryCode)

- (BOOL) hasActivationRecoveryData
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        return session.hasActivationRecoveryData;
    }];
}

- (nullable id<PowerAuthOperationTask>) activationRecoveryData:(nonnull PowerAuthAuthentication*)authentication
                                                      callback:(nonnull void(^)(PowerAuthActivationRecoveryData * _Nullable recoveryData, NSError * _Nullable error))callback
{
    if (![self hasActivationRecoveryData]) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"Session has no recovery data available."));
        return nil;
    }
    return [self fetchEncryptedVaultUnlockKey:authentication reason:PA2VaultUnlockReason_RECOVERY_CODE callback:^(NSString *encryptedEncryptionKey, NSError *error) {
        PowerAuthActivationRecoveryData * activationRecovery = nil;
        if (!error) {
            // Let's extract the data
            PowerAuthCoreSignatureUnlockKeys *keys = [[PowerAuthCoreSignatureUnlockKeys alloc] init];
            keys.possessionUnlockKey = [self deviceRelatedKey];
            PowerAuthCoreRecoveryData * recoveryData = [_sessionInterface readTaskWithSession:^id _Nullable(PowerAuthCoreSession * _Nonnull session) {
                return [session activationRecoveryData:encryptedEncryptionKey keys:keys];
            }];
            // Propagate error
            if (recoveryData) {
                activationRecovery = [[PowerAuthActivationRecoveryData alloc] initWithRecoveryData:recoveryData];
            } else {
                error = PA2MakeError(PowerAuthErrorCode_Encryption, nil);
            }
        }
        // Call back to application
        callback(activationRecovery, error);
    }];
}

- (nullable id<PowerAuthOperationTask>) confirmRecoveryCode:(nonnull NSString*)recoveryCode
                                             authentication:(nonnull PowerAuthAuthentication*)authentication
                                                   callback:(nonnull void(^)(BOOL alreadyConfirmed, NSError * _Nullable error))callback
{
    [self checkForValidSetup];
    
    // Check if there is an activation present
    if (![self hasValidActivation]) {
        callback(NO, PA2MakeError(PowerAuthErrorCode_MissingActivation, nil));
        return nil;
    }
    
    // Validate recovery code
    PowerAuthActivationCode * otp = [PowerAuthActivationCodeUtil parseFromRecoveryCode:recoveryCode];
    if (!otp) {
        callback(NO, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Invalid recovery code."));
        return nil;
    }
    
    // Construct and post request
    PA2ConfirmRecoveryCodeRequest * request = [[PA2ConfirmRecoveryCodeRequest alloc] init];
    request.recoveryCode = otp.activationCode;
    return [_client postObject:request
                            to:[PA2RestApiEndpoint confirmRecoveryCode]
                          auth:authentication
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        BOOL alreadyConfirmed;
                        if (status == PowerAuthRestApiResponseStatus_OK) {
                            alreadyConfirmed = ((PA2ConfirmRecoveryCodeResponse*)response).alreadyConfirmed;
                        } else {
                            alreadyConfirmed = NO;
                        }
                        callback(alreadyConfirmed, error);
                    }];
}

@end

#pragma mark - Activation data sharing

@implementation PowerAuthSDK (ActivationDataSharing)

- (PowerAuthExternalPendingOperation*) externalPendingOperation
{
    return _sessionInterface.externalPendingOperation;
}

@end

#pragma mark - External Encryption Key

@implementation PowerAuthSDK (EEK)

- (BOOL) hasExternalEncryptionKey
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session) {
        return [session hasExternalEncryptionKey];
    }];
}

- (BOOL) setExternalEncryptionKey:(NSData *)externalEncryptionKey error:(NSError **)error
{
    NSError * failure = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
        PowerAuthCoreErrorCode ec = [session setExternalEncryptionKey:externalEncryptionKey];
        switch (ec) {
            case PowerAuthCoreErrorCode_Ok:
                _configuration.externalEncryptionKey = externalEncryptionKey;
                return nil;
            case PowerAuthCoreErrorCode_WrongParam:
                return PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Invalid key size");
            case PowerAuthCoreErrorCode_WrongState:
                return PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"Activation is not using EEK");
            default:
                return PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to set EEK");
        }
    }];
    if (failure && error) {
        *error = failure;
    }
    return !failure;
}

- (BOOL) addExternalEncryptionKey:(NSData *)externalEncryptionKey error:(NSError **)error
{
    NSError * failure = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
        PowerAuthCoreErrorCode ec = [session addExternalEncryptionKey:externalEncryptionKey];
        switch (ec) {
            case PowerAuthCoreErrorCode_Ok:
                _configuration.externalEncryptionKey = externalEncryptionKey;
                return nil;
            case PowerAuthCoreErrorCode_WrongParam:
                return PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Invalid key size");
            case PowerAuthCoreErrorCode_WrongState:
                if (session.hasExternalEncryptionKey) {
                    return PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"EEK is already set");
                } else {
                    return PA2MakeError(session.hasValidActivation ? PowerAuthErrorCode_InvalidActivationState : PowerAuthErrorCode_MissingActivation, nil);
                }
            default:
                return PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to add EEK");
        }
    }];
    if (failure && error) {
        *error = failure;
    }
    return !failure;
}

- (BOOL) removeExternalEncryptionKey:(NSError **)error
{
    NSError * failure = [_sessionInterface writeTaskWithSession:^NSError* (PowerAuthCoreSession * session) {
        PowerAuthCoreErrorCode ec = [session removeExternalEncryptionKey];
        switch (ec) {
            case PowerAuthCoreErrorCode_Ok:
                _configuration.externalEncryptionKey = nil;
                return nil;
            case PowerAuthCoreErrorCode_WrongState:
                if (!session.hasExternalEncryptionKey) {
                    return PA2MakeError(PowerAuthErrorCode_InvalidActivationState, @"EEK is not set");
                } else {
                    return PA2MakeError(session.hasValidActivation ? PowerAuthErrorCode_InvalidActivationState : PowerAuthErrorCode_MissingActivation, nil);
                }
            default:
                // [session removeExternalEncryptionKey] never return WrongParam, so the default case is OK here.
                return PA2MakeError(PowerAuthErrorCode_Encryption, @"Failed to remove EEK");
        }
    }];
    if (failure && error) {
        *error = failure;
    }
    return !failure;
}

@end

#pragma mark - User Info

@implementation PowerAuthSDK (UserInfo)

- (PowerAuthUserInfo*) lastFetchedUserInfo
{
    [_lock lock];
    PowerAuthUserInfo * info = _lastFetchedUserInfo;
    [_lock unlock];
    return info;
}

- (void) setLastFetchedUserInfo:(PowerAuthUserInfo*)lastFetchedUserInfo
{
    [_lock lock];
    _lastFetchedUserInfo = lastFetchedUserInfo;
    [_lock unlock];
}

- (id<PowerAuthOperationTask>) fetchUserInfo:(void (^)(PowerAuthUserInfo *, NSError *))callback
{
    [self checkForValidSetup];

    // Post request
    return [_client postObject:nil
                            to:[PA2RestApiEndpoint getUserInfo]
                    completion:^(PowerAuthRestApiResponseStatus status, id<PA2Decodable> response, NSError *error) {
                        PowerAuthUserInfo * result;
                        if (status == PowerAuthRestApiResponseStatus_OK) {
                            result = (PowerAuthUserInfo*)response;
                            [self setLastFetchedUserInfo:result];
                        } else {
                            result = nil;
                        }
                        callback(result, error);
                    }];
}

@end

#pragma mark - Server Status

@implementation PowerAuthSDK (ServerStatus)

- (id<PowerAuthOperationTask>) fetchServerStatus:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
{
    return [self getSystemStatusWithCallback:callback callbackQueue:dispatch_get_main_queue()];
}

- (id<PowerAuthOperationTask>) getSystemStatusWithCallback:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
                                             callbackQueue:(dispatch_queue_t)callbackQueue
{
    [_lock lock];
    //
    id<PowerAuthOperationTask> task = [_getSystemStatusTask createChildTask:callback queue:callbackQueue];
    if (!task) {
        // If there's no grouping task, or task is already finished, then simply create new one with the child task.
        _getSystemStatusTask = [[PA2GetSystemStatusTask alloc] initWithHttpClient:_client sharedLock:_lock delegate:self];
        task = [_getSystemStatusTask createChildTask:callback];
    }
    //
    [_lock unlock];
    return task;
}

- (void) getSystemStatusTask:(PA2GetSystemStatusTask *)task didFinishedWithStatus:(PA2GetServerStatusResponse *)status error:(NSError *)error
{
    // [_lock lock] is guaranteed, because this method is called from task's completion while locked with shared lock.
    // So, we can freely mutate objects in this instance.
    if (_getSystemStatusTask == task) {
        _getSystemStatusTask = nil;
        // This is the reference to task which is going to finish its execution soon.
        // The ivar no longer holds the reference to the task, but we should keep that reference
        // for a little bit longer, to guarantee, that we don't destroy that object during its
        // finalization stage.
        [[NSOperationQueue mainQueue] addOperationWithBlock:^{
            // The following call does nothing, because the old task is no longer stored
            // in the `_getStatusTask` ivar. It just guarantees that the object will be alive
            // during waiting to execute the operation block.
            [self getSystemStatusTask:task didFinishedWithStatus:nil error:nil];
        }];
    }
}

@end
