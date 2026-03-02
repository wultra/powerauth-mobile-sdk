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

#import "PA2CoreHttpClient.h"
#import "PA2RestApiObjects.h"
#import "PA2AsyncOperation.h"

#import "PA2KeystoreService.h"
#import "PA2TimeSynchronizationService.h"
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateHttpTokenProvider.h"
#import "PA2PrivateMacros.h"
#import "PA2DefaultSessionInterface.h"
#import "PA2SharedSessionInterface.h"
#import "PA2SessionDataProvider.h"
#import "PA2AppGroupContainer.h"
#import "PA2CompositeTask.h"
#import "PA2Result.h"

#if defined(PA2_WATCH_SUPPORT)
#import "PowerAuthWCSessionManager+Private.h"
#endif

@import PowerAuthCore;

#import <UIKit/UIKit.h>

#pragma mark - Constants

/** In case a config is missing, exception with this identifier is thrown. */
NSString *const PowerAuthExceptionMissingConfig = @"PowerAuthExceptionMissingConfig";

#pragma mark - PowerAuth SDK implementation

@implementation PowerAuthSDK
{
    id<NSLocking> _lock;
    
    id<PA2SessionInterface> _sessionInterface;
    PowerAuthConfiguration * _configuration;
    PowerAuthBiometricConfiguration * _biometricConfiguration;
    PowerAuthKeychainConfiguration * _keychainConfiguration;
    PowerAuthClientConfiguration * _clientConfiguration;
    
    PA2KeystoreService * _keystoreService;
    PA2TimeSynchronizationService * _timeSynchronizationService;
    id<PowerAuthPrivateTokenStore> _tokenStore;
    PA2CoreHttpClient * _client;
    NSString * _biometryKeyIdentifier;
    PowerAuthKeychain * _statusKeychain;
    // TODO: shared keychain is no longer in use for the possession factor key. We're using internal calculation in C++ core from provided device specific data.
    //       Keep this for possible use in https://github.com/wultra/powerauth-mobile-sdk/issues/362
    PowerAuthKeychain * _sharedKeychain;
    PowerAuthKeychain * _biometryOnlyKeychain;
    PA2PrivateHttpTokenProvider * _remoteHttpTokenProvider;
    
    /// Current pending status task.
    PA2GetActivationStatusTask * _getActivationStatusTask;
}

#pragma mark - Private methods

/**
 The private function returns biometric configuration created from the provided configurations. If application still provide the deprecated keychain configuration,
 then the function constructs biometric configuration from the parameters provided in keychain configuration. If no configuration is provided, then returns the default
 biometric configuration.
 */
static PowerAuthBiometricConfiguration * _BuildBiometricConfiguration(PowerAuthBiometricConfiguration * biometricConfiguration, PowerAuthKeychainConfiguration * keychainConfiguration)
{
    if (biometricConfiguration) {
        return [biometricConfiguration copy];
    }
    if (keychainConfiguration) {
        return [[PowerAuthBiometricConfiguration alloc] initWithKeychainConfiguration:keychainConfiguration];
    }
    return [[PowerAuthBiometricConfiguration alloc] init];
}

/// Build device specific data for possession factor KEK.
static NSData * _BuildDeviceSpecificData(void)
{
    NSString *uuidString;
#if TARGET_IPHONE_SIMULATOR
    uuidString = @"ffa184f9-341a-444f-8495-de04d0d490be";
#else
    uuidString = [UIDevice currentDevice].identifierForVendor.UUIDString;
#endif
    return [uuidString dataUsingEncoding:NSUTF8StringEncoding];
}

/// Private SDK initialization.
/// - Parameters:
///   - configuration: Required configuration object.
///   - biometricConfiguration: Optional biometric configuration.
///   - clientConfiguration: Optional client configuration.
///   - keychainConfiguration: Optional keychain configuration.
///   - clearUnsupportedData: If true, then unsupported session data will be erased.
///   - error: Pointer to store error.
/// - Returns: YES in case of success, NO otherwise.
- (BOOL) initializeWithConfiguration:(PowerAuthConfiguration*)configuration
              biometricConfiguration:(PowerAuthBiometricConfiguration*)biometricConfiguration
                 clientConfiguration:(PowerAuthClientConfiguration*)clientConfiguration
               keychainConfiguration:(PowerAuthKeychainConfiguration*)keychainConfiguration
                clearUnsupportedData:(BOOL)clearUnsupportedData
                               error:(NSError**)error
{
    NSError * localError = nil;
    // Check if the configuration was nil
    if (configuration == nil) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Missing configuration");
        return NO;
    }
    
    // Validate that the configuration was set up correctly
    if (![configuration validateConfiguration]) {
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Invalid PowerAuthSDK configuration. You must set a valid PowerAuthConfiguration to PowerAuthSDK instance using initializer.");
        return NO;
    }
    
    // Exclusive lock
    _lock = [[NSRecursiveLock alloc] init];
    
    // Make copy of configuration objects
    _configuration = [configuration copy];
    _biometricConfiguration = _BuildBiometricConfiguration(biometricConfiguration, keychainConfiguration);
    _keychainConfiguration = keychainConfiguration ? [keychainConfiguration copy] : [[PowerAuthKeychainConfiguration alloc] init];
    _clientConfiguration = clientConfiguration ? [clientConfiguration copy] : [[PowerAuthClientConfiguration alloc] init];
    
    // Prepare identifier for biometry related keys - use instanceId by default, or a custom value if set
    _biometryKeyIdentifier = _configuration.keychainKey_Biometry ? _configuration.keychainKey_Biometry : _configuration.instanceId;
    
    // Alter keychain in case that PowerAuthSharingConfiguration is used
    PowerAuthSharingConfiguration * sharingConfiguration = _configuration.sharingConfiguration;
    NSString * keychainAccessGroup = nil;
    NSString * userDefaultsSuiteName = nil;
    if (sharingConfiguration != nil) {
        userDefaultsSuiteName = sharingConfiguration.appGroup;
        keychainAccessGroup = sharingConfiguration.keychainAccessGroup;
    } else if (_keychainConfiguration) {
        // Using deprecated interfaces internally.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        userDefaultsSuiteName = _keychainConfiguration.keychainAttribute_UserDefaultsSuiteName;
        keychainAccessGroup = _keychainConfiguration.keychainAttribute_AccessGroup;
#pragma clang diagnostic pop
    }
    
    // Create a new keychain instances
    _statusKeychain         = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Status
                                                                accessGroup:keychainAccessGroup];
    _sharedKeychain         = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Possession
                                                                accessGroup:keychainAccessGroup];
    _biometryOnlyKeychain   = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_Biometry
                                                                accessGroup:keychainAccessGroup];
    
    // Initialize token store with its own keychain as a backing storage and remote token provider.
    PowerAuthKeychain * tokenStoreKeychain = [[PowerAuthKeychain alloc] initWithIdentifier:_keychainConfiguration.keychainInstanceName_TokenStore
                                                                               accessGroup:keychainAccessGroup];
    // Create session setup parameters
    PowerAuthCoreConfig *coreConfig = [PowerAuthCoreConfig buildWithConfiguration:_configuration.configuration
                                                               deviceSpecificData:_BuildDeviceSpecificData()
                                                                       instanceId:_configuration.instanceId
                                                                        algorithm:(PowerAuthCoreAlgorithm)_configuration.algorithm
                                                                            error:&localError];
    // TODO: EEK
    //setup.externalEncryptionKey = _configuration.externalEncryptionKey;
    // Create a new session
    if (!coreConfig || localError) {
        PA2WrapError(localError, error);
        return NO;
    }
    // Build core session
    PowerAuthCoreSession * coreSession = [PowerAuthCoreSession createWithConfiguration:coreConfig error:&localError];
    if (!coreSession || localError) {
        PA2WrapError(localError, error);
        return NO;
    }
    
    // Make sure to reset keychain data after app re-install.
    // Important: This deletes all Keychain data in all PowerAuthSDK instances!
    // By default, the code uses standard user defaults, use `PowerAuthKeychainConfiguration.keychainAttribute_UserDefaultsSuiteName` to use `NSUserDefaults` with a custom suite name.
    NSUserDefaults *userDefaults = nil;
    if (userDefaultsSuiteName) {
        userDefaults = [[NSUserDefaults alloc] initWithSuiteName:userDefaultsSuiteName];
        if (!userDefaults) {
            PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Invalid user defaults suite name provided");
            return NO;
        }
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
        _sessionInterface = [[PA2DefaultSessionInterface alloc] initWithSession:coreSession dataProvider:sessionDataProvider error:&localError];
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
            PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Invalid sharing configuration provided");
            return NO;
        }
        // Finally, construct the shared session provider.
        _sessionInterface = [[PA2SharedSessionInterface alloc] initWithSession:coreSession
                                                                  dataProvider:sessionDataProvider
                                                                    instanceId:instanceId
                                                                 applicationId:_configuration.sharingConfiguration.appIdentifier
                                                                sharedMemoryId:sharedMemoryId
                                                                statusLockPath:statusLockPath
                                                             operationLockPath:operationLockPath
                                                                 queueLockPath:queueLockPath
                                                                         error:&localError];
    }
    // Throw a failure if session provider is not available.
    if (!_sessionInterface) {
        PowerAuthCoreLog(@"ERROR: Failed to create session interface");
        PA2WrapError(localError, error);
        return NO;
    }
    // Link core session and session interface together
    coreSession.delegate = _sessionInterface;
    
    // Load initial session's state
    if (![_sessionInterface loadInitialState:clearUnsupportedData error:&localError]) {
        PowerAuthCoreLog(@"ERROR: Failed to load initial session state");
        PA2WrapError(localError, error);
        return NO;
    }
    
    // Create and setup a new HTTP client
    _client = [[PA2CoreHttpClient alloc] initWithConfiguration:_clientConfiguration
                                              sessionInterface:_sessionInterface
                                               completionQueue:dispatch_get_main_queue()
                                                       baseUrl:_configuration.baseEndpointUrl];
    // Prepare time synchronization service.
    _timeSynchronizationService = [[PA2TimeSynchronizationService alloc] initWithCoreService:coreSession.timeSynchronizationService httpClient:_client sharedLock:_lock];
    [_timeSynchronizationService subscribeForSystemNotifications];
    
    // Prepare keystore service
    _keystoreService = [[PA2KeystoreService alloc] initWithHttpClient:_client sessionInterface:_sessionInterface sharedLock:_lock];
    
    // Create token store
    _remoteHttpTokenProvider = [[PA2PrivateHttpTokenProvider alloc] initWithHttpClient:_client credentialsResolver:self];
    _tokenStore = [[PA2PrivateTokenKeychainStore alloc] initWithConfiguration:self.configuration
                                                                     keychain:tokenStoreKeychain
                                                             sessionInterface:_sessionInterface
                                                               statusProvider:self
                                                               remoteProvider:_remoteHttpTokenProvider
                                                                  timeService:_timeSynchronizationService
                                                                     dataLock:_sessionInterface
                                                                    localLock:_lock];
    
    // Connect session interface with essential services. This step solves chicken-egg problem, when services depends on client and vice versa.
    [_sessionInterface connectWithKeystoreService:_keystoreService timeService:_timeSynchronizationService];
    
#if defined(PA2_WATCH_SUPPORT)
    // Register this instance to handle messages
    [[PowerAuthWCSessionManager sharedInstance] registerDataHandler:self];
#endif
    return YES;
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

- (PowerAuthBiometricConfiguration*) biometricConfiguration
{
    return [_biometricConfiguration copy];
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

- (id<PowerAuthCoreSessionProvider>) sessionProvider
{
    return _sessionInterface;
}

- (id<PA2SessionInterface>) sessionInterface
{
    return _sessionInterface;   // same as "sessionProvider" but exposes private interfaces
}

- (PowerAuthAlgorithm) currentAlgorithm
{
    NSNumber * enumValue = [_sessionInterface readTaskWithSession:^NSNumber*(PowerAuthCoreSession *session, NSError **error) {
        return @([session currentAlgorithm]);
    } error:nil];
    if (!enumValue) {
        return _configuration.algorithm;
    }
    return [enumValue intValue];
}

#pragma mark - Key management

- (PA2KeystoreService*) keystoreService
{
    return _keystoreService;
}

/// Acquire biometry related key from the keychain.
/// - Parameters:
///   - authentication: Keychain authentication object.
///   - error: Pointer to error object to fill when operation fails.
/// - Returns: Biometry related key or nil.
- (PowerAuthCoreData*) biometryRelatedKeyWithAuthentication:(nonnull PowerAuthKeychainAuthentication*)authentication error:(NSError **)error
{
#if PA2_HAS_LACONTEXT
    //
    // LAContext is available on this platform
    //
    __block PowerAuthCoreData *key = nil;
    __block OSStatus status;
    BOOL executed = [PowerAuthKeychain tryLockBiometryAndExecuteBlock:^{
        key = [_biometryOnlyKeychain coreDataForKey:_biometryKeyIdentifier status:&status authentication:authentication];
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
            PA2SetExistingError(error, localError);
            return nil;
        }
        // No error generated, so create a fake biometry key to fail on the server.
        key = [self generateInvalidBiometricKey];
    } else if (error) {
        // Success, so we should reset object at error pointer.
        *error = nil;
    }
    
    if (key && _biometricConfiguration.invalidateLocalAuthenticationContextAfterUse) {
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


/// Convert PowerAuthAuthentication object into PowerAuthCoreCredentials object.
/// - Parameters:
///   - authentication: Authentication object to translate
///   - error: Pointer to store error in case of failure.
/// - Returns: `PowerAuthCoreCredentials` created from factors provided in authentication object.
- (PowerAuthCoreCredentials*) resolveCredentialsWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                             error:(NSError **)error
{
    // Validate authentication object usage
    NSError * localError = [authentication validateUsage:NO];
    if (localError) {
        PA2SetExistingError(error, localError);
        return nil;
    }
    
    if (authentication.password) {
        // possession + knowledge
        return [PowerAuthCoreCredentials knowledge:authentication.password];
    } else if (authentication.useBiometry) {
        // possession + biometry
        PowerAuthCoreData *biometryKey = nil;
        if (authentication.customBiometryKey) {
            // application specified a custom biometry key
            biometryKey = authentication.customBiometryKey;
        } else {
            // default biometry key should be fetched
            PowerAuthLog(@"WARNING: Biometric factor key is not fetched in advance and therefore the calling thread may be blocked.");
            biometryKey = [self biometryRelatedKeyWithAuthentication:authentication.keychainAuthentication error:error];
            if (!biometryKey) {
                return nil;
            }
        }
        return [PowerAuthCoreCredentials biometry:biometryKey];
    } else {
        // Possession only
        return [PowerAuthCoreCredentials possession];
    }
}

#pragma mark - Public methods

#pragma mark Initializers and SDK instance getters

- (instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                biometricConfiguration:(nullable PowerAuthBiometricConfiguration *)biometricConfiguration
                   clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
                 keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                                 error:(NSError **)error
{
    self = [super init];
    if (self) {
        if (![self initializeWithConfiguration:configuration
                        biometricConfiguration:biometricConfiguration
                           clientConfiguration:clientConfiguration
                         keychainConfiguration:keychainConfiguration
                          clearUnsupportedData:NO
                                         error:error]) {
            return nil;
        }
    }
    return self;
}

- (instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                biometricConfiguration:(nullable PowerAuthBiometricConfiguration *)biometricConfiguration
                   clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
                                 error:(NSError **)error
{
    return [self initWithConfiguration:configuration
                biometricConfiguration:biometricConfiguration
                   clientConfiguration:clientConfiguration
                 keychainConfiguration:nil
                                 error:error];
}

- (instancetype) initWithConfiguration:(PowerAuthConfiguration *)configuration
                                 error:(NSError **)error
{
    return [self initWithConfiguration:configuration
                biometricConfiguration:nil
                   clientConfiguration:nil
                 keychainConfiguration:nil
                                 error:error];
}

// Private init function

- (instancetype) initForCleanupWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                           keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                                           error:(NSError **)error
{
    self = [super init];
    if (self) {
        if (![self initializeWithConfiguration:configuration
                        biometricConfiguration:nil
                           clientConfiguration:nil
                         keychainConfiguration:keychainConfiguration
                          clearUnsupportedData:YES
                                         error:error]) {
            return nil;
        }
    }
    return self;
}


+ (BOOL) cleanupInstanceDataForConfiguration:(nonnull PowerAuthConfiguration*)configuration
                       keychainConfiguration:(nullable PowerAuthKeychainConfiguration*)keychainConfiguration
                                       error:(NSError*_Nullable*_Nullable)error
{
    PowerAuthSDK * temporary = [[PowerAuthSDK alloc] initForCleanupWithConfiguration:configuration
                                                               keychainConfiguration:keychainConfiguration error:error];
    if (temporary) {
        [temporary removeActivationLocal];
    }
    return temporary != nil;
}

+ (BOOL) cleanupInstanceDataForConfiguration:(nonnull PowerAuthConfiguration*)configuration
                                       error:(NSError*_Nullable*_Nullable)error
{
    return [self cleanupInstanceDataForConfiguration:configuration keychainConfiguration:nil error:error];
}

static void _ThrowDeprecatedInitException(NSError * error)
{
    PowerAuthLog(@"Initialization failed: Error %@", error);
    [NSException raise:PowerAuthExceptionMissingConfig format:@"Invalid PowerAuthSDK configuration. Error: %@", error];
}

// PA2_DEPRECATED(2.0.0)
- (instancetype) initWithConfiguration:(nonnull PowerAuthConfiguration *)configuration
                 keychainConfiguration:(nullable PowerAuthKeychainConfiguration *)keychainConfiguration
                   clientConfiguration:(nullable PowerAuthClientConfiguration *)clientConfiguration
{
    NSError * error = nil;
    id instance = [self initWithConfiguration:configuration
                       biometricConfiguration:nil
                          clientConfiguration:clientConfiguration
                        keychainConfiguration:keychainConfiguration
                                        error:&error];
    if (error) {
        _ThrowDeprecatedInitException(error);
    }
    return instance;
}

// PA2_DEPRECATED(2.0.0)
+ (void) initSharedInstance:(PowerAuthConfiguration*)configuration
{
    [self initSharedInstance:configuration keychainConfiguration:nil clientConfiguration:nil];
}

// PA2_DEPRECATED(2.0.0)
static PowerAuthSDK * s_inst;

// PA2_DEPRECATED(2.0.0)
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

// PA2_DEPRECATED(2.0.0)
+ (PowerAuthSDK*) sharedInstance
{
    if (!s_inst) {
        _ThrowDeprecatedInitException(PA2MakeError(PowerAuthErrorCode_Other, @"Deprecated shared instance is not configured"));
    }
    return s_inst;
}

#pragma mark Session state management

- (BOOL) canStartActivation
{
    return _sessionInterface.canStartActivation;
}

- (BOOL) hasPendingActivation
{
    return _sessionInterface.hasPendingActivation;
}

- (BOOL) hasValidActivation
{
    return _sessionInterface.hasValidActivation;
}

- (BOOL) hasProtocolUpgradeAvailable
{
    return _sessionInterface.hasProtocolUpgradeAvailable;
}

- (BOOL) hasPendingProtocolUpgrade
{
    return _sessionInterface.hasPendingProtocolUpgrade;
}

- (void) cancelAllPendingTasks
{
    [_lock lock];
    
    [_getActivationStatusTask cancel];
    [_timeSynchronizationService cancelAllPendingRequests];
    [_tokenStore cancelAllTasks];
    
    [_lock unlock];
}

#pragma mark - Activation
#pragma mark Creating a new activation

- (id<PowerAuthOperationTask>) createActivation:(PowerAuthActivation*)activation
                                       callback:(void(^)(PowerAuthActivationResult * _Nullable result, NSError * _Nullable error))callback
{
    // Input parameters check
    
    if (!callback) {
        PowerAuthLog(@"ERROR: Missing callback in createActivation() method.");
        return nil;
    }
    if (!activation) {
        callback(nil, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Missing activation parameter"));
        return nil;
    }
    NSError * error = nil;
    if (![activation validate:&error]) {
        callback(nil, error);
        return nil;
    }
    
    // Prepare both layers of activation data
    NSMutableDictionary* L1data = [NSMutableDictionary dictionaryWithCapacity:8];
    PA2DictionarySafeSet(L1data, @"type", activation.activationType);
    PA2DictionarySafeSet(L1data, @"identityAttributes", activation.identityAttributes);
    PA2DictionarySafeSet(L1data, @"customAttributes", activation.customAttributes);
    
    NSMutableDictionary* L2data = [NSMutableDictionary dictionaryWithCapacity:8];
    PA2DictionarySafeSet(L2data, @"activationName", activation.name);
    PA2DictionarySafeSet(L2data, @"extras", activation.extras);
    PA2DictionarySafeSet(L2data, @"activationOtp", activation.additionalActivationOtp);
    PA2DictionarySafeSet(L2data, @"platform", [PowerAuthSystem platform]);
    PA2DictionarySafeSet(L2data, @"deviceInfo", [PowerAuthSystem deviceInfo]);
    
    // Notify other applications about pending activation
    if (![_sessionInterface startExternalPendingOperation:PowerAuthExternalPendingOperationType_Activation error:&error]) {
        callback(nil, error);
        return nil;
    }
    
    // Start an activation
    PowerAuthCoreRequest * request = [_sessionInterface writeTaskWithSession:^PowerAuthCoreRequest*(PowerAuthCoreSession * session, NSError ** error) {
        return [session createActivation:L1data withL2Data:L2data error:error];
    } error:&error];
    
    if (error) {
        callback(nil, error);
        return nil;
    }
    
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, PowerAuthCoreActivationResult * response, NSError * error) {
        PowerAuthActivationResult * result = nil;
        if (response) {
            result = [[PowerAuthActivationResult alloc] initWithCoreActivationResult:response];
        }
        callback(result, error);
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

#pragma mark Persist

- (id<PowerAuthOperationTask>) persistActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                                          callback:(void(^)(NSError * error))callback
{
    NSError * localError = nil;
    PowerAuthCoreTask * task = [self persistActivationInSession:authentication error:&localError];
    if (!task) {
        // If activation is V3, then it's OK to exit immediately, because there's no additional asynchronous
        // operation required. So, we can end here for both, successful and failure scenarios.
        callback(localError);
        return nil;
    }
    // Otherwise execute the core request
    return [_client postCoreTask:task completion:^(PowerAuthCoreTask* request, id response, NSError* error) {
        // TODO: recovery from failure
        callback(error);
    }];
}

- (id<PowerAuthOperationTask>) persistActivationWithPassword:(NSString*)password
                                                    callback:(void(^)(NSError * error))callback
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithPassword:password]
                                            callback:callback];
}

- (id<PowerAuthOperationTask>) persistActivationWithCorePassword:(PowerAuthCorePassword*)password
                                                        callback:(void(^)(NSError * error))callback
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithCorePassword:password]
                                            callback:callback];
}

#pragma mark Persist - deprecated

// PA2_DEPRECATED(2.0.0)
- (BOOL) persistActivationWithPassword:(NSString*)password
                                 error:(NSError**)error
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithPassword:password]
                                               error:error];
}

// PA2_DEPRECATED(2.0.0)
- (BOOL) persistActivationWithCorePassword:(PowerAuthCorePassword *)password
                                     error:(NSError **)error
{
    return [self persistActivationWithAuthentication:[PowerAuthAuthentication persistWithCorePassword:password]
                                               error:error];
}

// PA2_DEPRECATED(2.0.0)
- (BOOL) persistActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                       error:(NSError**)error
{
    NSError * localError = nil;
    PowerAuthCoreTask * task = [self persistActivationInSession:authentication error:&localError];
    if (localError) {
        PA2SetExistingError(error, localError);
        return NO;
    }
    if (task) {
        // Persist is asynchronous and this deprecated function is synchronous. Cancel the request and report error.
        [task cancel];
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Synchronous persist is not supported at this protocol version");
        return NO;
    }
    return YES;
}

- (NSString*) activationIdentifier
{
    return _sessionInterface.activationIdentifier;
}

- (NSString*) activationFingerprint
{
    return [_sessionInterface readTaskWithSession:^id (PowerAuthCoreSession * session, NSError** error) {
        return session.activationFingerprint;
    } error:nil];
}


- (PowerAuthCoreTask*) persistActivationInSession:(PowerAuthAuthentication*)authentication error:(NSError**)error
{
    // Validate authentication object usage
    NSError * localError = [authentication validateUsage:YES];
    if (localError) {
        PA2SetExistingError(error, localError);
        return nil;
    }
    
    return [_sessionInterface writeTaskWithSession:^PowerAuthCoreTask* (PowerAuthCoreSession * session, NSError** error) {
        
        NSError * localError = nil;
        
        // Prepare key encryption keys
        PowerAuthCorePassword * password = authentication.password;
        PowerAuthCoreData *biometryKek = authentication.customBiometryKey;
        if (authentication.useBiometry && !biometryKek) {
            if (!(biometryKek = [session generateFactorKek:&localError])) {
                PA2SetExistingError(error, localError);
                return nil;
            }
        }
        PowerAuthCoreTask * task = [session confirmActivationWithPassword:password withBiometryKek:biometryKek error:&localError];
        if (localError) {
            PA2SetExistingError(error, localError);
            return nil;
        }
        
        // success remove biometry key and store new one (if available)
        [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        if (biometryKek) {
            [_biometryOnlyKeychain setCoreData:biometryKek forKey:_biometryKeyIdentifier access:_biometricConfiguration.biometricItemAccess];
        }
        // Clear TokenStore
        [_tokenStore removeAllLocalTokens];
        return task;
        
    } error:error];
}

#pragma mark Getting activations state

- (id<PowerAuthOperationTask>) getActivationStatusWithCallback:(void(^)(PowerAuthActivationStatus * status, NSError * error))callback
{
    NSError * localError = nil;
    // Check for activation
    [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        if (!session.hasValidActivationData) {
            NSInteger errorCode = session.hasPendingCreateActivation ? PowerAuthErrorCode_ActivationPending : PowerAuthErrorCode_MissingActivation;
            PA2SetError(error, errorCode, nil);
            return NO;
        }
        return YES;
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    
    [_lock lock];
    //
    id<PowerAuthOperationTask> task = [_getActivationStatusTask createChildTask:callback];
    if (!task) {
        // If there's no grouping task, or task is already finished, then simply create new one with the child task.
        _getActivationStatusTask = [[PA2GetActivationStatusTask alloc] initWithHttpClient:_client
                                                                          sessionProvider:_sessionInterface
                                                                                 delegate:self
                                                                               sharedLock:_lock];
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

- (void) getActivationStatusTaskNeedRemoveBiometricFactorKek:(PA2GetActivationStatusTask *)task
{
    [_lock lock];
    if (_getActivationStatusTask == task) {
        [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
    }
    [_lock unlock];
}

- (PowerAuthActivationStatus*) lastFetchedActivationStatus
{
    PowerAuthCoreActivationStatus * coreStatus = [_sessionInterface readTaskWithSession:^PowerAuthCoreActivationStatus*(PowerAuthCoreSession *session, NSError **error) {
        return [session lastActivationStatus];
    } error:nil];
    
    if (!coreStatus) {
        return nil;
    }
    
    return [[PowerAuthActivationStatus alloc] initWithCoreStatus:coreStatus];
}

#pragma mark - Protocol upgrade

- (id<PowerAuthOperationTask>) startProtocolUpgradeWithCorePassword:(PowerAuthCorePassword*)password
                                                  customBiometryKek:(PowerAuthCoreData*)customBiometryKek
                                                           callback:(void(^)(PowerAuthProtocolUpgradeResult * result, NSError * error))callback
{
    NSError* localError = nil;
    PowerAuthCoreData * biometryKek = nil;
    
    if (self.hasBiometryFactor) {
        if (customBiometryKek) {
            biometryKek = customBiometryKek;
        } else {
            biometryKek = [_sessionInterface readTaskWithSession:^PowerAuthCoreData* _Nullable(PowerAuthCoreSession* session, NSError** error) {
                return [PowerAuthCoreSession generateFactorKekForProtocolVersion:PowerAuthCoreProtocolVersion_V4 error:error];
            } error:&localError];
        }
    }
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    
    id<PowerAuthOperationTask> task = [_sessionInterface writeTaskWithSession:^PowerAuthCoreTask*(PowerAuthCoreSession * session, NSError ** error) {
            return [session startProtocolUpgradeWithPassword:password
                                             withBiometryKek:biometryKek
                                                       error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    
    return [_client postCoreTask:task completion:^(PowerAuthCoreTask * _Nonnull task, PowerAuthProtocolUpgradeResult *  _Nullable result, NSError * _Nullable error) {
        if (!error && biometryKek) {
            [_biometryOnlyKeychain updateValue:biometryKek.sensitiveData
                                        forKey:_biometryKeyIdentifier];
        }
        callback(result, error);
    }];
}

- (id<PowerAuthOperationTask>) startProtocolUpgradeWithPassword:(NSString*)password
                                              customBiometryKek:(PowerAuthCoreData*)customBiometryKek
                                                       callback:(void(^)(PowerAuthProtocolUpgradeResult * result, NSError * error))callback
{
    return [self startProtocolUpgradeWithCorePassword:[PowerAuthCorePassword passwordWithString:password]
                                    customBiometryKek:customBiometryKek
                                             callback:callback];
}

- (id<PowerAuthOperationTask>) startProtocolUpgradeWithCorePassword:(PowerAuthCorePassword*)password
                                                           callback:(void(^)(PowerAuthProtocolUpgradeResult * result, NSError * error))callback
{
    return [self startProtocolUpgradeWithCorePassword:password
                                    customBiometryKek:nil
                                             callback:callback];
}

- (id<PowerAuthOperationTask>) startProtocolUpgradeWithPassword:(NSString*)password
                                                       callback:(void(^)(PowerAuthProtocolUpgradeResult * result, NSError * error))callback
{
    return [self startProtocolUpgradeWithCorePassword:[PowerAuthCorePassword passwordWithString:password]
                                    customBiometryKek:nil
                                             callback:callback];
}

#pragma mark Removing an activation

- (id<PowerAuthOperationTask>) removeActivationWithAuthentication:(PowerAuthAuthentication*)authentication
                                                         callback:(void(^)(NSError *error))callback
{
    NSError * localError = nil;
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        callback(localError);
        return nil;
    }
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError ** error) {
        return [session removeActivationWithCredentials:credentials error:error];
    } error:&localError];
    if (localError) {
        callback(localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, id response, NSError * error) {
        callback(error);
    }];
}

- (void) removeActivationLocal
{
    // TODO: prepare func returning error
    [self cancelAllPendingTasks];
    [self clearCachedData];
    [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        BOOL err = NO;
        if ([_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier]) {
            err = ![_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        }
        if (err) {
            PowerAuthLog(@"Removing activation data from keychain failed. We can't recover from this error.");
        }
        [_tokenStore removeAllLocalTokens];
        [session resetSession];
        return YES;
    } error:nil];
}

/**
 Clear in-memory cached data.
 */
- (void) clearCachedData
{
}

#pragma mark - Authentication codes

- (PowerAuthHttpHeader*) calculateAuthHeaderWithSession:(PowerAuthCoreSession*)session
                                         authentication:(PowerAuthAuthentication*)authentication
                                                 method:(NSString*)method
                                                  uriId:(NSString*)uriId
                                                   body:(NSData*)body
                                                  error:(NSError **)error
{
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:error];
    if (!credentials) {
        return nil;
    }
    PowerAuthCoreHttpHeader * header = [session calculateOnlineAuthenticationHeader:credentials
                                                                      uriIdentifier:uriId
                                                                         httpMethod:method
                                                                        requestBody:body
                                                                              error:error];
    if (!header) {
        return nil;
    }
    return [PowerAuthHttpHeader createWithCoreHeader:header];
}

- (NSString*) offlineAuthenticationCodeImpl:(PowerAuthAuthentication*)authentication
                                      uriId:(NSString*)uriId
                                       body:(NSData*)body
                                      nonce:(NSString*)nonce
                                      error:(NSError**)error
{
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:error];
    if (!credentials) {
        return nil;
    }
    return [_sessionInterface writeTaskWithSession:^NSString*(PowerAuthCoreSession * session, NSError **error) {
        return [session calculateOfflineAuthenticationCode:credentials
                                             uriIdentifier:uriId
                                              offlineNonce:nonce
                                                codeLength:_configuration.offlineAuthenticationCodeComponentLength
                                                      data:body
                                                     error:error];
    } error:error];
}


- (PowerAuthHttpHeader*) authenticationHeaderForRequestWithBodyWithAuthentication:(PowerAuthAuthentication*)authentication
                                                                           method:(NSString*)method
                                                                            uriId:(NSString*)uriId
                                                                             body:(NSData*)body
                                                                            error:(NSError **)error
{
    return [_sessionInterface writeTaskWithSession:^PowerAuthHttpHeader*(PowerAuthCoreSession * session, NSError **error) {
        return [self calculateAuthHeaderWithSession:session
                                     authentication:authentication
                                             method:method
                                              uriId:uriId
                                               body:body
                                              error:error];
    } error:error];
}

- (PowerAuthHttpHeader*) authenticationHeaderForRequestWithParamsWithAuthentication:(PowerAuthAuthentication*)authentication
                                                                             method:(NSString*)method
                                                                              uriId:(NSString*)uriId
                                                                             params:(NSDictionary<NSString*, NSString*>*)params
                                                                              error:(NSError **)error
{
    return [_sessionInterface writeTaskWithSession:^PowerAuthHttpHeader*(PowerAuthCoreSession * session, NSError **error) {
        NSData * normalizedParams = [session normalizeGetRequestParameters:params error:error];
        if (!normalizedParams) {
            return nil;
        }
        return [self calculateAuthHeaderWithSession:session
                                     authentication:authentication
                                             method:method
                                              uriId:uriId
                                               body:normalizedParams
                                              error:error];
    } error:error];
}

- (id<PowerAuthOperationTask>) offlineAuthenticationCodeWithAuthentication:(PowerAuthAuthentication*)authentication
                                                                     uriId:(NSString*)uriId
                                                                      body:(NSData*)body
                                                                     nonce:(NSString*)nonce
                                                                  callback:(void(^)(NSString * authenticationCode, NSError * error))callback
{
    // Prepare composite task that will cover the whole operation
    PA2CompositeTask * task = [[PA2CompositeTask alloc] initWithCancelBlock:nil];
    
    // Prepare completion function that dispatch result to the main thread.
    void (^completionFunc)(NSString*, NSError*) = ^(NSString * authenticationCode, NSError * error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            // If task is not canceled yet, then report finally the result.
            if ([task setCompleted]) {
                callback(authenticationCode, error);
            }
        });
    };
    // Prepare execution function that compute authentication code in the serial queue
    void (^executionFunc)(PowerAuthAuthentication*) = ^(PowerAuthAuthentication * resolvedAuthentication) {
        // We should compute the signature on the serial queue we have dedicated for the networking operations.
        id<PowerAuthOperationTask> computationTask = [self executeBlockOnSerialQueue:^(id<PowerAuthOperationTask> task) {
            // Finally compute the offline authentication code.
            NSError * localError = nil;
            NSString * authenticationCode = [self offlineAuthenticationCodeImpl:resolvedAuthentication
                                                                          uriId:uriId
                                                                           body:body
                                                                          nonce:nonce
                                                                          error:&localError];
            // Report result back to the application
            completionFunc(authenticationCode, localError);
            // Mark this synchronized task as completed
            [task cancel];
        }];
        // Keep the computation task as a sub-task of composite task.
        [task replaceOperationTask:computationTask];
    };
#if PA2_HAS_LACONTEXT
    if (authentication.useBiometry && authentication.customBiometryKey == nil) {
        // If biometric authentication is requested and the key is not resolved yet, then authenticate with biometry first.
        id<PowerAuthOperationTask> biometricAuthTask = [self authenticateUsingBiometryImpl:authentication.keychainAuthentication
                                                                                  callback:^(PowerAuthAuthentication *resolvedAuthentication, NSError *error) {
            if (resolvedAuthentication) {
                // Biometric authentication succeeded, now continue with authentication code calculation
                executionFunc(resolvedAuthentication);
            } else {
                // Biometric authentication failed
                completionFunc(nil, error);
            }
        }];
        // Keep the biometric authentication task as a sub-task of composite task.
        [task replaceOperationTask:biometricAuthTask];
    } else {
        // Seems that authentication object is already resolved, no additional tasks are required. So execute the
        // authentication code computation.
        executionFunc(authentication);
    }
#else
    // There's no biometric authentication on this platform. So execute the authentication code computation.
    executionFunc(authentication);
#endif
    return task;
}



#pragma mark - Computing signatures (deprecated naming)

// PA2_DEPRECATED(2.0.0)
- (PowerAuthHttpHeader*) requestGetSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                                         uriId:(NSString*)uriId
                                                        params:(NSDictionary<NSString*, NSString*>*)params
                                                         error:(NSError**)error
{
    return [self authenticationHeaderForRequestWithParamsWithAuthentication:authentication
                                                                     method:@"GET"
                                                                      uriId:uriId
                                                                     params:params
                                                                      error:error];
}

// PA2_DEPRECATED(2.0.0)
- (PowerAuthHttpHeader*) requestSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                                     method:(NSString*)method
                                                      uriId:(NSString*)uriId
                                                       body:(NSData*)body
                                                      error:(NSError**)error
{
    return [self authenticationHeaderForRequestWithBodyWithAuthentication:authentication
                                                                   method:method
                                                                    uriId:uriId
                                                                     body:body
                                                                    error:error];
}

// PA2_DEPRECATED(2.0.0)
- (NSString*) offlineSignatureWithAuthentication:(PowerAuthAuthentication*)authentication
                                           uriId:(NSString*)uriId
                                            body:(NSData*)body
                                           nonce:(NSString*)nonce
                                           error:(NSError**)error
{
    return [self offlineAuthenticationCodeImpl:authentication
                                         uriId:uriId
                                          body:body
                                         nonce:nonce
                                         error:error];
}

#pragma mark - Password

- (nullable id<PowerAuthOperationTask>) beginPasswordChangeWithCorePassword:(nonnull PowerAuthCorePassword*)oldPassword
                                                                   callback:(nonnull void(^)(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error))callback
{
    NSError * localError = nil;
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError ** error) {
        return [session verifyPassword:oldPassword error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, id response, NSError * error) {
        PowerAuthPasswordChangeData * changeData = error ? nil : [[PowerAuthPasswordChangeData alloc] initWithCorePassword:oldPassword];
        callback(changeData, error);
    }];

}

- (nullable id<PowerAuthOperationTask>) finishPasswordChangeWithNewCorePassword:(nonnull PowerAuthCorePassword*)newPassword
                                                                     changeData:(nonnull PowerAuthPasswordChangeData*)changeData
                                                                       callback:(nonnull void(^)(NSError * _Nullable error))callback
{
    PowerAuthCorePassword * oldPassword = [changeData.oldPassword copyToImmutable];
    if (!oldPassword) {
        callback(PA2MakeError(PowerAuthErrorCode_WrongParameter, @"PowerAuthPasswordChangeData is invalidated"));
        return nil;
    }
    NSError * localError = nil;
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError ** error) {
        return [session changePassword:oldPassword toPassword:newPassword error:error];
    } error:&localError];
    if (!request) {
        // V3 change password is executed immediately. It's OK to exit immediately, because there's no additional asynchronous
        // operation required. So, we can end here for both, successful and failure scenarios.
        callback(localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, id response, NSError * error) {
        callback(error);
    }];

}

- (nullable id<PowerAuthOperationTask>) beginPasswordChangeWithPassword:(nonnull NSString*)oldPassword
                                                               callback:(nonnull void(^)(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error))callback
{
    return [self beginPasswordChangeWithCorePassword:[PowerAuthCorePassword passwordWithString:oldPassword]
                                            callback:callback];
}

- (nullable id<PowerAuthOperationTask>) finishPasswordChangeWithNewPassword:(nonnull NSString*)newPassword
                                                                 changeData:(nonnull PowerAuthPasswordChangeData*)changeData
                                                                   callback:(nonnull void(^)(NSError * _Nullable error))callback
{
    return [self finishPasswordChangeWithNewCorePassword:[PowerAuthCorePassword passwordWithString:newPassword]
                                              changeData:changeData
                                                callback:callback];
}

#pragma mark - Password (deprecated)

// PowerAuthCorePassword versions

- (BOOL) unsafeChangeCorePasswordFrom:(PowerAuthCorePassword*)oldPassword
                                   to:(PowerAuthCorePassword*)newPassword
{
    NSError * localError = nil;
    [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError ** error) {
        PowerAuthCoreRequest * request = [session changePassword:oldPassword toPassword:newPassword error:error];
        if (request) {
            [request cancel];
            PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Synchronous password change is not supported at this protocol version");
        }
        return nil;
    } error:&localError];
    return localError ? NO : YES;
}

- (id<PowerAuthOperationTask>) changeCorePasswordFrom:(PowerAuthCorePassword*)oldPassword
                                                   to:(PowerAuthCorePassword*)newPassword
                                             callback:(void(^)(NSError *error))callback
{
    return [self finishPasswordChangeWithNewCorePassword:newPassword
                                              changeData:[[PowerAuthPasswordChangeData alloc] initWithCorePassword:oldPassword]
                                                callback:callback];
}

- (id<PowerAuthOperationTask>) validateCorePassword:(PowerAuthCorePassword*)password callback:(void(^)(NSError * error))callback
{
    return [self beginPasswordChangeWithCorePassword:password callback:^(PowerAuthPasswordChangeData * _Nullable changeData, NSError * _Nullable error) {
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
    return [self addBiometryFactorWithCorePassword:password customBiometryKek:nil callback:callback];
}

- (id<PowerAuthOperationTask>) addBiometryFactorWithCorePassword:(PowerAuthCorePassword*)password
                                               customBiometryKek:(PowerAuthCoreData *)customBiometryKek
                                                        callback:(void(^)(NSError *error))callback
{
    // Check if biometry can be used
    if (![PowerAuthKeychain canUseBiometricAuthentication]) {
        callback(PA2MakeError(PowerAuthErrorCode_BiometryNotAvailable, nil));
        return nil;
    }
    NSError * localError = nil;
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError ** error) {
        PowerAuthCoreData * biometryKek = customBiometryKek ? customBiometryKek : [session generateFactorKek:error];
        if (!biometryKek) {
            return nil;
        }
        PowerAuthCoreRequest * request = [session addBiometryFactorWithPassword:password withBiometryKek:biometryKek error:error];
        if (!*error) {
            [_biometryOnlyKeychain setCoreData:biometryKek forKey:_biometryKeyIdentifier access:_biometricConfiguration.biometricItemAccess];
        }
        return request;
    } error:&localError];
    if (localError) {
        callback(localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, id response, NSError * error) {
        callback(error);
    }];
}

- (id<PowerAuthOperationTask>) addBiometryFactorWithPassword:(NSString *)password callback:(void (^)(NSError *))callback
{
    return [self addBiometryFactorWithCorePassword:[PowerAuthCorePassword passwordWithString:password] customBiometryKek:nil callback:callback];
}

- (id<PowerAuthOperationTask>) addBiometryFactorWithPassword:(NSString *)password customBiometryKek:(PowerAuthCoreData *)customBiometryKek callback:(void (^)(NSError *))callback
{
    return [self addBiometryFactorWithCorePassword:[PowerAuthCorePassword passwordWithString:password] customBiometryKek:customBiometryKek callback:callback];
}

- (BOOL) hasBiometryFactor
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        return [_biometryOnlyKeychain containsDataForKey:_biometryKeyIdentifier] &&
        [session hasBiometryFactor];
    } error:nil];
}

// PA2_DEPRECATED(2.0.0)
- (BOOL) removeBiometryFactor
{
    return [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError** error) {
        [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        PowerAuthCoreRequest * request = [session removeBiometryFactor:error];
        if (request) {
            [request cancel];
            PowerAuthLog(@"Synchronous biometry factor remove is not supported at this protocol level");
            return NO;
        }
        return YES;
    } error:nil];
}

- (id<PowerAuthOperationTask>) removeBiometryFactorWithCallback:(void (^)(NSError * _Nullable))callback
{
    NSError* localError = nil;
    PowerAuthCoreRequest * request = [_sessionInterface writeTaskWithSession:^PowerAuthCoreRequest*(PowerAuthCoreSession * session, NSError ** error) {
        return [session removeBiometryFactor:error];
    } error:&localError];
    if (localError) {
        callback(localError);
        return nil;
    }
    if (!request) {
        // V3 activation, remove doesn't use request
        // Delete biometric KEK from the keychain
        [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        callback(nil);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * _Nonnull request, id  _Nullable response, NSError * _Nullable error) {
        if (!error) {
            // V4 activation, delete biometric KEK from the keychain after successful request
            [_biometryOnlyKeychain deleteDataForKey:_biometryKeyIdentifier];
        }
        callback(error);
    }];
}

#if PA2_HAS_LACONTEXT

// If LAContext is available then we assume that biometry is also available on the platform.

- (id<PowerAuthOperationTask>) authenticateUsingBiometryWithPrompt:(NSString *)prompt
                                                          callback:(void(^)(PowerAuthAuthentication * authentication, NSError * error))callback
{
    return [self authenticateUsingBiometryImpl:[[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt] callback:callback];
}

- (void) unlockBiometryKeysWithPrompt:(NSString*)prompt
                            withBlock:(void(^)(NSDictionary<NSString*, NSData*> *keys, BOOL userCanceled))block
{
    [self unlockBiometryKeysImpl:[[PowerAuthKeychainAuthentication alloc] initWithPrompt:prompt] withBlock:block];
}

- (id<PowerAuthOperationTask>) authenticateUsingBiometryWithContext:(LAContext *)context
                                                           callback:(void (^)(PowerAuthAuthentication *, NSError *))callback
{
    return [self authenticateUsingBiometryImpl:[[PowerAuthKeychainAuthentication alloc] initWithContext:context] callback:callback];
}

- (void) unlockBiometryKeysWithContext:(LAContext *)context
                             withBlock:(void (^)(NSDictionary<NSString *,NSData *> *, BOOL))block
{
    [self unlockBiometryKeysImpl:[[PowerAuthKeychainAuthentication alloc] initWithContext:context] withBlock:block];
}

- (id<PowerAuthOperationTask>) authenticateUsingBiometryImpl:(PowerAuthKeychainAuthentication *)keychainAuthentication
                                                    callback:(void(^)(PowerAuthAuthentication * authentication, NSError * error))callback
{
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
    
    // Prepare composite task and completion function
    PA2CompositeTask * task = [[PA2CompositeTask alloc] initWithCancelBlock:^{
        [context invalidate];
    }];
    void (^completionFunction)(PowerAuthAuthentication *, NSError*) = ^(PowerAuthAuthentication * biometricAuthentication, NSError * error) {
        // Report result back to the main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([task setCompleted]) {
                callback(biometricAuthentication, error);
            }
        });
    };
    
    // Check if activation is present
    if (!_sessionInterface.hasValidActivation) {
        completionFunction(nil, PA2MakeError(PowerAuthErrorCode_MissingActivation, nil));
        return task;
    }
    
    // Check biometric status in advance, to do not increase failed attempts counter
    // in case that biometry is already locked out.
    if (![PowerAuthKeychain canUseBiometricAuthentication]) {
        completionFunction(nil, PA2MakeError(PowerAuthErrorCode_BiometryNotAvailable, nil));
        return task;
    }
    
    
    // Prepare policy based on keychain configuration.
    LAPolicy policy;
    if (_biometricConfiguration.biometricItemAccess == PowerAuthKeychainItemAccess_AnyBiometricSetOrDevicePasscode) {
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
            PowerAuthCoreData * biometryKey = [self biometryRelatedKeyWithAuthentication:keychainAuthentication error:&error];
            if (biometryKey) {
                // The biometry key is available, so create a new PowerAuthAuthentication object preconfigured
                // with possession+biometry factors.
                authentication = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:biometryKey];
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
                        authentication = [PowerAuthAuthentication possessionWithBiometryWithCustomBiometryKey:[self generateInvalidBiometricKey]];
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
                        
                    case LAErrorSystemCancel:           // System cancel (e.g. user pressed power or home button)
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
        completionFunction(authentication, error);
    }];
    return task;
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
- (PowerAuthCoreData*) generateInvalidBiometricKey
{
    PowerAuthLog(@"WARNING: Generating fake biometry key to increase failed attempts counter on the server.");
    return [_sessionInterface readTaskWithSession:^PowerAuthCoreData* _Nullable(PowerAuthCoreSession* session, NSError** error) {
        return [session generateFactorKek:error];
    } error:nil];
}

#endif // PA2_HAS_LACONTEXT

@end


@implementation PowerAuthSDK (VaultEncryption)

#pragma mark - Secure vault support

- (id<PowerAuthOperationTask>) fetchVaultEncryptionKey:(PowerAuthAuthentication*)authentication
                                         keyIdentifier:(PowerAuthCoreSecureVaultKeyId)keyIdentifier
                                                 index:(UInt64)index
                                              callback:(void(^)(PowerAuthCoreData *encryptionKey, NSError *error))callback
{
    NSError* localError = nil;
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError** error) {
        return [session fetchVaultEncryptionKey:credentials
                                          keyId:keyIdentifier
                                          index:index
                                          error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, PowerAuthCoreData* response, NSError * error) {
        callback(response, error);
    }];
}

- (id<PowerAuthOperationTask>) fetchEncryptionKey:(PowerAuthAuthentication*)authentication
                                            index:(UInt64)index
                                         callback:(void(^)(PowerAuthCoreData *encryptionKey, NSError *error))callback
{
    return [self fetchVaultEncryptionKey:authentication
                           keyIdentifier:PowerAuthCoreSecureVaultKeyId_Legacy
                                   index:index
                                callback:^(PowerAuthCoreData *encryptionKey, NSError *error) {
        callback(encryptionKey, error);
    }];
}

- (id<PowerAuthOperationTask>) fetchSecureVaultKey:(PowerAuthAuthentication*)authentication
                                         keyIdentifier:(PowerAuthSecureVaultKeyId)keyIdentifier
                                              callback:(void(^)(PowerAuthSecureVaultKey *encryptionKey, NSError *error))callback
{
    return [self fetchVaultEncryptionKey:authentication
                           keyIdentifier:(PowerAuthCoreSecureVaultKeyId)keyIdentifier
                                   index:0
                                callback:^(PowerAuthCoreData *encryptionKey, NSError *error) {
        callback([[PowerAuthSecureVaultKey alloc] initWithCoreData:encryptionKey keyId:keyIdentifier], error);
    }];
}
@end


#pragma mark - Digital signatures

@implementation PowerAuthSDK (DigitalSignatures)

- (nullable NSArray<PowerAuthDevicePublicKeyData*>*) exportDevicePublicKeysToFormat:(PowerAuthDevicePublicKeyFormat)format
                                                                              error:(NSError*_Nullable*_Nullable)error
{
    NSArray<PowerAuthCoreDevicePublicKeyData*>* coreKeys = [_sessionInterface readTaskWithSession:^NSArray* (PowerAuthCoreSession * session, NSError ** error) {
        return [session exportDevicePublicKeysToFormat:(PowerAuthCoreDevicePublicKeyFormat)format error:error];
    } error:error];
    if (!coreKeys) {
        return nil;
    }
    NSMutableArray<PowerAuthDevicePublicKeyData*>* outputKeys = [NSMutableArray arrayWithCapacity:coreKeys.count];
    [coreKeys enumerateObjectsUsingBlock:^(PowerAuthCoreDevicePublicKeyData * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [outputKeys addObject:[[PowerAuthDevicePublicKeyData alloc] initWithCoreDevicePublicKeyData:obj]];
    }];
    return outputKeys;
}

- (BOOL) verifyDigitalSignature:(nonnull NSData*)signature
                     signedData:(nullable NSData*)signedData
                  keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                          error:(NSError*_Nullable*_Nullable)error
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        return [session verifySignature:signature
                                   data:signedData
                                  keyId:(PowerAuthCoreSignatureKeyId)keyIdentifier
                                  error:error];
    } error:error];
}

- (BOOL) verifyJwsSignature:(nonnull NSString*)signature
                    compact:(BOOL)compact
                     strict:(BOOL)strict
              keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                      error:(NSError*_Nullable*_Nullable)error
{
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        return [session jwsVerifySignature:signature
                               compactForm:compact
                                    strict:strict
                                     keyId:(PowerAuthCoreSignatureKeyId)keyIdentifier
                                     error:error];
    } error:error];
}

- (nullable id<PowerAuthOperationTask>) calculateDigitalSignature:(nonnull PowerAuthAuthentication*)authentication
                                                       dataToSign:(nullable NSData*)dataToSign
                                                    keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                         callback:(nonnull void(^)(NSData * _Nullable signature, NSError * _Nullable error))callback
{
    NSError* localError = nil;
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError** error) {
        return [session signData:dataToSign
                     credentials:credentials
                           keyId:(PowerAuthCoreSignatureKeyId)keyIdentifier
                           error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, NSData * response, NSError * error) {
        callback(response, error);
    }];
}

- (nullable id<PowerAuthOperationTask>) calculateJwsSignature:(nonnull PowerAuthAuthentication*)authentication
                                                   dataToSign:(nullable NSData*)dataToSign
                                                     dataType:(nullable NSString*)dataType
                                                      compact:(BOOL)compact
                                                keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                     callback:(nonnull void(^)(NSString * jws, NSError * error))callback
{
    NSError* localError = nil;
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError** error) {
        return [session jwsSignData:dataToSign
                           dataType:dataType
                        compactForm:compact
                        credentials:credentials
                              keyId:(PowerAuthCoreSignatureKeyId)keyIdentifier
                              error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, NSString* response, NSError * error) {
        callback(response, error);
    }];
}

- (nullable id<PowerAuthOperationTask>) createCertificateSigningRequestWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                                       distinguishedNames:(nonnull NSDictionary<NSString*, NSString*>*)distinguishedNames
                                                                          subjectAltNames:(nullable NSArray<NSString*>*)subjectAltNames
                                                                            keyIdentifier:(PowerAuthSignatureKeyId)keyIdentifier
                                                                                 callback:(nonnull void(^)(NSString * _Nullable csr, NSError * _Nullable error))callback
{
    NSError* localError = nil;
    PowerAuthCoreCredentials * credentials = [self resolveCredentialsWithAuthentication:authentication error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    PowerAuthCoreRequest * request = [_sessionInterface readTaskWithSession:^PowerAuthCoreRequest* (PowerAuthCoreSession * session, NSError** error) {
        return [session createCertificateSigningRequest:credentials
                                                dnItems:distinguishedNames
                                               sanItems:subjectAltNames
                                                  keyId:(PowerAuthCoreSignatureKeyId)keyIdentifier
                                                  error:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * request, NSString* response, NSError * error) {
        callback(response, error);
    }];
}

#pragma clang diagnostic push   // PA2_DEPRECATED(2.0.0)
#pragma clang diagnostic ignored "-Wdeprecated-implementations"

- (id<PowerAuthOperationTask>) signDataWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
                                                       data:(NSData*)data
                                                   callback:(void(^)(NSData *signature, NSError *error))callback
{
    return [self calculateDigitalSignature:authentication
                                dataToSign:data
                             keyIdentifier:PowerAuthSignatureKeyId_Device_EC
                                  callback:callback];
}

- (id<PowerAuthOperationTask>) signJwtWithDevicePrivateKey:(PowerAuthAuthentication*)authentication
                                                    claims:(NSDictionary<NSString*, NSObject*>*)claims
                                                  callback:(void(^)(NSString *jwt, NSError *error))callback
{
    return [self calculateJwsSignature:authentication
                            dataToSign:[NSJSONSerialization dataWithJSONObject:claims options:0 error:nil]
                              dataType:@"JWT"
                               compact:YES
                         keyIdentifier:PowerAuthSignatureKeyId_Device_EC
                              callback:callback];
}

- (BOOL) verifyServerSignedData:(nonnull NSData*)data
                      signature:(nonnull NSString*)signature
                      masterKey:(BOOL)masterKey
{
    return [self verifyDigitalSignature:[[NSData alloc] initWithBase64EncodedString:signature options:0]
                             signedData:data
                          keyIdentifier:masterKey ? PowerAuthSignatureKeyId_Master_EC : PowerAuthSignatureKeyId_Server_EC
                                  error:nil];
}

- (nullable id<PowerAuthOperationTask>) createSignedCSRWithAuthentication:(nonnull PowerAuthAuthentication*)authentication
                                                       distinguishedNames:(nonnull NSDictionary<NSString*, NSString*>*)distinguishedNames
                                                          subjectAltNames:(nullable NSArray<NSString*>*)subjectAltNames
                                                                 callback:(nonnull void(^)(NSString * _Nullable csr, NSError * _Nullable error))callback
{
    return [self createCertificateSigningRequestWithAuthentication:authentication
                                                distinguishedNames:distinguishedNames
                                                   subjectAltNames:subjectAltNames
                                                     keyIdentifier:PowerAuthSignatureKeyId_Device_EC
                                                          callback:callback];
}
#pragma clang diagnostic pop // PA2_DEPRECATED(2.0.0)
@end

#pragma mark - End-2-End Encryption

@implementation PowerAuthSDK (E2EE)

- (id<PowerAuthOperationTask>) encryptorForApplicationScopeWithCallback:(void(^)(PowerAuthCoreEncryptor * encryptor, NSError * error))callback
{
    return [self createEncryptorWithScope:PowerAuthCoreEncryptorScope_Application callback:callback];
}

- (id<PowerAuthOperationTask>) encryptorForActivationScopeWithCallback:(void(^)(PowerAuthCoreEncryptor * encryptor, NSError * error))callback
{
    return [self createEncryptorWithScope:PowerAuthCoreEncryptorScope_Activation callback:callback];
}

// Private

- (id<PowerAuthOperationTask>) createEncryptorWithScope:(PowerAuthCoreEncryptorScope)scope
                                               callback:(void (^)(PowerAuthCoreEncryptor *, NSError *))callback
{
    return [_keystoreService createKeyForEncryptorScope:scope callback:^(NSError * error) {
        PowerAuthCoreEncryptor* encryptor = nil;
        if (!error) {
            encryptor = [_sessionInterface readTaskWithSession:^PowerAuthCoreEncryptor*(PowerAuthCoreSession * session, NSError** error) {
                return [[session encryptorFactory] createEncryptorWithScope:scope error:error];
            } error:&error];
        }
        callback(encryptor, error);
    } callbackQueue:dispatch_get_main_queue()];
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
    return [_sessionInterface readBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        return [session hasExternalEncryptionKey];
    } error:nil];
}

- (BOOL) removeExternalEncryptionKey:(PowerAuthCoreData *)externalEncryptionKey
                               error:(NSError * _Nullable __autoreleasing *)error
{
    return [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        return [session removeExternalEncryptionKey:externalEncryptionKey error:error];
    } error:error];
}

- (BOOL) addExternalEncryptionKeyForTest:(PowerAuthCoreData *)externalEncryptionKey
                                   error:(NSError * _Nullable __autoreleasing *)error
{
#if DEBUG
    return [_sessionInterface writeBoolTaskWithSession:^BOOL(PowerAuthCoreSession * session, NSError ** error) {
        return [session addExternalEncryptionKeyForTest:externalEncryptionKey error:error];
    } error:error];
#else
    PA2SetError(error, PowerAuthErrorCode_Other, @"Function is not available in release SDK build");
    return NO;
#endif
}
@end

#pragma mark - User Info

@implementation PowerAuthSDK (UserInfo)

- (PowerAuthUserInfo*) lastFetchedUserInfo
{
    NSDictionary * claims = [_sessionInterface readTaskWithSession:^NSDictionary*(PowerAuthCoreSession *session, NSError **error) {
        return [session lastUserInfo];
    } error:nil];
    return [[PowerAuthUserInfo alloc] initWithDictionary:claims];
}

- (id<PowerAuthOperationTask>) fetchUserInfo:(void (^)(PowerAuthUserInfo *, NSError *))callback
{
    NSError* localError = nil;
    PowerAuthCoreRequest * request = [_sessionInterface writeTaskWithSession:^PowerAuthCoreRequest*(PowerAuthCoreSession * session, NSError ** error) {
        return [session fetchUserInfo:error];
    } error:&localError];
    if (localError) {
        callback(nil, localError);
        return nil;
    }
    
    return [_client postCoreRequest:request completion:^(PowerAuthCoreRequest * _Nonnull request, PowerAuthUserInfo * _Nullable response, NSError * _Nullable error) {
        PowerAuthUserInfo * info = [[PowerAuthUserInfo alloc] initWithDictionary:request.responseJson];
        callback(info, error);
    }];
}

@end

#pragma mark - Server Status

@implementation PowerAuthSDK (ServerStatus)

- (id<PowerAuthOperationTask>) fetchServerStatus:(void(^)(PowerAuthServerStatus * status, NSError * error))callback
{
    return [_timeSynchronizationService fetchServerStatus:callback callbackQueue:dispatch_get_main_queue()];
}

@end
