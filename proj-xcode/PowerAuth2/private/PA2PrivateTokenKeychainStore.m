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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateMacros.h"
#import "PA2CreateTokenTask.h"
#import "PA2CompositeTask.h"
#import "PA2SessionInterface.h"
#import "PowerAuthAuthentication+Private.h"

#import <PowerAuth2/PowerAuthErrorConstants.h>
#import <PowerAuth2/PowerAuthKeychain.h>
#import <PowerAuth2/PowerAuthConfiguration.h>
#import <PowerAuth2/PowerAuthLog.h>

@implementation PA2PrivateTokenKeychainStore
{
    /// A copy of SDK configuration
    PowerAuthConfiguration *    _sdkConfiguration;
    /// Token data locking implementation
    id<PA2TokenDataLock>        _tokenDataLock;
    /// Local lock, protecting data in this process.
    id<NSLocking>               _localLock;
    /// Session interface
    id<PA2SessionInterface>     _sessionInterface;
    // Lazy initialized data

    /// A prefix for all tokens stored in the keychain
    NSString * _keychainKeyPrefix;
    /// A local database for tokens.
    NSMutableDictionary<NSString*, PA2PrivateTokenData*> * _database;
    
    NSMutableDictionary<NSString*, PA2CreateTokenTask*> *_createTokenTasks;
}

@synthesize timeSynchronizationService = _timeSynchronizationService;

- (id) initWithConfiguration:(PowerAuthConfiguration*)configuration
                    keychain:(PowerAuthKeychain*)keychain
            sessionInterface:(id<PA2SessionInterface>)sessionInterface
              statusProvider:(id<PowerAuthSessionStatusProvider>)statusProvider
              remoteProvider:(id<PA2PrivateRemoteTokenProvider>)remoteProvider
                 timeService:(id<PowerAuthTimeSynchronizationService>)timeService
                    dataLock:(id<PA2TokenDataLock>)dataLock
                   localLock:(id<NSLocking>)localLock
{
    self = [super init];
    if (self) {
        _sdkConfiguration = configuration;
        _statusProvider = statusProvider;
        _remoteTokenProvider = remoteProvider;
        _timeSynchronizationService = timeService;
        _keychain = keychain;
        _tokenDataLock = dataLock;
        _localLock = localLock ? localLock : [[NSRecursiveLock alloc] init];
        _sessionInterface = sessionInterface;
        _allowInMemoryCache = YES;
    }
    return self;
}

- (void) dealloc
{
    [self cancelAllTasksImpl];
}

- (PowerAuthConfiguration*) configuration
{
    return _sdkConfiguration;
}

/**
 Prepares runtime data required by this class. We're initializing that objects only
 on demand, when the first token is being accessed.
 */
- (void) prepareInstance
{
    // Initialize remote provider (instance may be nil)
    [_remoteTokenProvider prepareInstanceForConfiguration:_sdkConfiguration];

    // Build base key for all stored tokens
    _keychainKeyPrefix = [PA2PrivateTokenKeychainStore keychainPrefixForInstanceId:_sdkConfiguration.instanceId];
    _database = [NSMutableDictionary dictionaryWithCapacity:2];
    _createTokenTasks = [NSMutableDictionary dictionaryWithCapacity:2];
}

/**
 A simple replacement for @synchronized() construct.
 This version of function returns object returned from the block.
 */
- (id) synchronized:(id(NS_NOESCAPE ^)(BOOL * setModified, NSError** error))block error:(NSError**)error
{
    NSError * localError = nil;
    BOOL isDirty = NO;
    id result = nil;
    if ([_tokenDataLock lockTokenStore:&isDirty error:&localError]) {
        if (_keychainKeyPrefix == nil) {
            [self prepareInstance];
        }
        if (_allowInMemoryCache && isDirty) {
            [_database removeAllObjects];
        }
        BOOL modified = NO;
        result = block(&modified, &localError);
        [_tokenDataLock unlockTokenStore:modified error:&localError];
    }
    if (localError) {
        if (error) *error = localError;
        result = nil;
    }
    return result;
}

/**
 A simple replacement for @synchronized() construct.
 This version of function has no return value.
 */
- (BOOL) synchronizedVoid:(BOOL(NS_NOESCAPE ^)(BOOL * setModified, NSError** error))block error:(NSError**)error
{
    NSError * localError = nil;
    BOOL isDirty = NO;
    BOOL result = NO;
    if ([_tokenDataLock lockTokenStore:&isDirty error:&localError]) {
        if (_keychainKeyPrefix == nil) {
            [self prepareInstance];
        }
        if (_allowInMemoryCache && isDirty) {
            [_database removeAllObjects];
        }
        BOOL modified = NO;
        result = block(&modified, &localError);
        [_tokenDataLock unlockTokenStore:modified error:&localError];
    }
    if (localError) {
        if (error) *error = localError;
        result = NO;
    }
    return result;
}

#pragma mark - PowerAuthPrivateTokenStore protocol

- (BOOL) canGenerateHeaderForToken:(PowerAuthToken *)token
{
    return [_statusProvider hasValidActivation] && [_statusProvider.activationIdentifier isEqualToString:token.privateTokenData.activationIdentifier];
}

- (BOOL) storeTokenData:(PA2PrivateTokenData*)tokenData error:(NSError**)error
{
    return [self synchronizedVoid:^(BOOL *setModified, NSError**error) {
        if (!self.canRequestForAccessToken) {
            PA2SetError(error, PowerAuthErrorCode_InvalidActivationState, @"Activation is no longer valid");
            return NO;
        }
        [self storeTokenDataWhenLocked:tokenData isUpgrade:NO];
        *setModified = YES;
        return YES;
    } error:error];
}

- (void) removeCreateTokenTask:(NSString *)tokenName
{
    [_localLock lock];
    // Remove group task from the dictionary.
    [_createTokenTasks removeObjectForKey:tokenName];
    [_localLock unlock];
}

- (void) cancelAllTasks
{
    [_localLock lock];
    [self cancelAllTasksImpl];
    [_localLock unlock];
}

- (void) cancelAllTasksImpl
{
    [[_createTokenTasks copy] enumerateKeysAndObjectsUsingBlock:^(NSString * key, PA2CreateTokenTask * obj, BOOL * stop) {
        [obj cancel];
    }];
    [_createTokenTasks removeAllObjects];
}

- (PowerAuthHttpHeader*) calculateTokenHeader:(PA2PrivateTokenData*)tokenData
                                                     error:(NSError**)error
{
    return [_sessionInterface readTaskWithSession:^PowerAuthHttpHeader* (PowerAuthCoreSession * session, NSError ** error) {
        PowerAuthCoreHttpHeader * coreHeader = [session calculateTokenHeader:tokenData.identifier tokenSecret:tokenData.secret error:error];
        return coreHeader ? [PowerAuthHttpHeader createWithCoreHeader:coreHeader] : nil;
    } error:error];
}

#pragma mark - PowerAuthTokenStore protocol

- (BOOL) canRequestForAccessToken
{
    return [_statusProvider hasValidActivation];
}

- (id<PowerAuthOperationTask>) requestAccessTokenWithName:(NSString*)name
                                           authentication:(PowerAuthAuthentication*)authentication
                                               completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
    return [self requestAccessTokenImpl:name authentication:authentication completion:completion];
}

- (id<PowerAuthOperationTask>) requestAccessTokenWithName:(NSString*)name
                                               completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
    return [self requestAccessTokenImpl:name authentication:nil completion:completion];
}

/*
 This is an actual implementation of `requestAccessTokenWithName...` method, but allowing authentication to be nil.
 */
- (id<PowerAuthOperationTask>) requestAccessTokenImpl:(NSString*)name
                                       authentication:(PowerAuthAuthentication*)authentication
                                           completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
    if (!name || !completion) {
        if (completion) {
            completion(nil, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Missing required parameter."));
        }
        return nil;
    }
    BOOL authenticationIsRequired = [_remoteTokenProvider authenticationIsRequired];
    if (!authentication && authenticationIsRequired) {
        completion(nil, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Authentication object is missing."));
        return nil;
    }
    if (!_statusProvider.hasValidActivation) {
        completion(nil, PA2MakeError(PowerAuthErrorCode_MissingActivation, @"Activation is no longer valid."));
        return nil;
    }
    
    NSError * error = nil;
    PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name authentication:authentication error:&error];
    if (tokenData || error) {
        // The data is available, so the token can be returned synchronously
        PowerAuthToken * token = tokenData ? [[PowerAuthToken alloc] initWithStore:self data:tokenData] : nil;
        completion(token, error);
        return nil;
    }
    
    // Local token is not found, so we have to fire a remote request.
    
    id<PA2PrivateRemoteTokenProvider> strongTokenProvider = _remoteTokenProvider;
    if (!strongTokenProvider) {
        // Looks like parent SDK object is already destroyed.
        completion(nil, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Object is no longer operational."));
        return nil;
    }
    
    [_localLock lock];
    //
    PA2CreateTokenTask * groupTask = _createTokenTasks[name];
    id<PowerAuthOperationTask> result = nil;
    if (groupTask && authenticationIsRequired) {
        if (groupTask.authentication.signatureFactorMask != authentication.signatureFactorMask) {
            error = PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Different PowerAuthAuthentication used for the same token creation.");
        }
    }
    if (!error) {
        // No error yet, so try to create child task. Note that groupTask may be nil.
        result = [groupTask createChildTask:completion];
        if (!result) {
            // No group task created yet, or existing task is already completed, so we have to create a new one.
            groupTask = [[PA2CreateTokenTask alloc] initWithProvider:strongTokenProvider
                                                          tokenStore:self
                                                      authentication:authentication
                                                        activationId:_statusProvider.activationIdentifier
                                                           tokenName:name
                                                          sharedLock:_localLock];
            // Keep group task in the dictionary.
            _createTokenTasks[name] = groupTask;
            // Create child task that capture the completion for the application.
            result = [groupTask createChildTask:completion];
        }
    }
    //
    [_localLock unlock];
    
    if (error) {
        completion(nil, error);
    }
    return result;
}


- (id<PowerAuthOperationTask>) removeAccessTokenWithName:(NSString *)name
                                              completion:(void (^)(BOOL, NSError * ))completion
{
    if (!name || !completion) {
        if (completion) {
            completion(NO, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Missing required parameter."));
        }
        return nil;
    }
    if (!_statusProvider.hasValidActivation) {
        completion(NO, PA2MakeError(PowerAuthErrorCode_MissingActivation, @"Activation is no longer valid."));
        return nil;
    }
    NSError * error = nil;
    PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name authentication:nil error:&error];
    if (!tokenData) {
        completion(NO, error ? error : PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Token not found."));
        return nil;
    }

    id<PA2PrivateRemoteTokenProvider> strongTokenProvider = _remoteTokenProvider;
    if (!strongTokenProvider) {
        // Looks like parent SDK object is already destroyed.
        completion(NO, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Object is no longer operational."));
        return nil;
    }
    
    return [strongTokenProvider removeTokenData:tokenData completion:^(BOOL removed, NSError * _Nullable error) {
        if (removed) {
            [self removeLocalTokenWithName:name];
        }
        completion(removed, error);
    }];
}

- (void) removeLocalTokenWithName:(NSString *)name
{
    NSError * localError = nil;
    [self synchronizedVoid:^BOOL(BOOL * setModified, NSError**error){
        if (name) {
            [self removeTokenWithIdentifier:[self identifierForTokenName:name]];
            *setModified = YES;
            return YES;
        }
        PA2SetError(error, PowerAuthErrorCode_WrongParameter, @"Invalid token name");
        return NO;
    } error:&localError];
    if (localError) {
        PowerAuthLog(@"ERROR: removeLocalTokenWithName() failed: %@", localError);
    }
}


- (void) removeAllLocalTokens
{
    NSError * localError = nil;
    [self synchronizedVoid:^BOOL(BOOL * setModified, NSError**error) {
        [[self allTokenIdentifiers] enumerateObjectsUsingBlock:^(NSString * identifier, NSUInteger idx, BOOL * stop) {
            [self removeTokenWithIdentifier:identifier];
        }];
        *setModified = YES;
        return YES;
    } error:&localError];
    if (localError) {
        PowerAuthLog(@"ERROR: removeAllLocalTokens() failed: %@", localError);
    }
}

- (BOOL) hasLocalTokenWithName:(nonnull NSString*)name
{
    return nil != [self tokenDataForTokenName:name authentication:nil error:nil];
}


- (PowerAuthToken*) localTokenWithName:(NSString*)name
{
    PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name authentication:nil error:nil];
    if (tokenData) {
        return [[PowerAuthToken alloc] initWithStore:self data:tokenData];
    }
    return nil;
}


#pragma mark - Keychain

+ (NSString*) keychainPrefixForInstanceId:(NSString*)instanceId
{
    if (instanceId.length > 0) {
        return [[@"powerAuthToken__" stringByAppendingString:instanceId] stringByAppendingString:@"__"];
    }
    return nil;
}

+ (NSString*) identifierForTokenName:(NSString*)name forInstanceId:(NSString*)instanceId
{
    if (name.length > 0 && instanceId.length > 0) {
        return [[self keychainPrefixForInstanceId:instanceId] stringByAppendingString:name];
    }
    return nil;
}

/**
 Returns identifier for keychain created from token's name
 */
- (NSString*) identifierForTokenName:(NSString*)name
{
    return [_keychainKeyPrefix stringByAppendingString:name];
}

/**
 Returns YES if given identifier is a valid token's identifier
 */
- (BOOL) isValidIdentifierForToken:(NSString*)identifier
{
    return [identifier hasPrefix:_keychainKeyPrefix];
}

/**
 Returns token identifiers for all items stored in the keychain.
 */
- (NSArray*) allTokenIdentifiers
{
    NSDictionary * items = [_keychain allItems];
    NSMutableArray * result = [NSMutableArray arrayWithCapacity:items.count];
    [items enumerateKeysAndObjectsUsingBlock:^(NSString * key, id obj, BOOL * stop) {
        if ([self isValidIdentifierForToken:key]) {
            [result addObject:key];
        }
    }];
    return result;
}

/**
 Returns PA2PrivateTokenData object created for token with name or nil if no such data is stored.
 */
- (PA2PrivateTokenData*) tokenDataForTokenName:(NSString*)name
                                authentication:(PowerAuthAuthentication*)authentication
                                         error:(NSError**)error
{
    NSError * localError = nil;
    PA2PrivateTokenData * result = [self synchronized:^id(BOOL *setModified, NSError**error) {
        NSString * identifier = [self identifierForTokenName:name];
        PA2PrivateTokenData * tokenData = _allowInMemoryCache ? _database[identifier] : nil;
        if (!tokenData) {
            tokenData = [PA2PrivateTokenData deserializeWithData: [_keychain dataForKey:identifier status:NULL]];
            if (tokenData) {
                NSString * tokenDataAID = tokenData.activationIdentifier;
                BOOL isInvalid          = tokenDataAID != nil && ![tokenDataAID isEqualToString:_statusProvider.activationIdentifier];
                BOOL doUpgradeAID       = tokenDataAID == nil;
                BOOL doUpgradeFactors   = authentication != nil && tokenData.authenticationFactors == 0;
                if (isInvalid) {
                    // Looks like serialized activation identifier is different to the current AID.
                    // This token is no longer valid and must be removed from the keychain.
                    PowerAuthLog(@"KeychainTokenStore: WARNING: Token '%@' is no longer valid.", name);
                    [_keychain deleteDataForKey:identifier];
                    tokenData = nil;
                    *setModified = YES;
                } else if (doUpgradeAID || doUpgradeFactors) {
                    // Old data format, with no activation identifier or factors serialized. Re-save the data
                    if (doUpgradeFactors) {
                        tokenData.authenticationFactors = authentication.signatureFactorMask;
                    }
                    [self storeTokenDataWhenLocked:tokenData isUpgrade:YES];
                    *setModified = YES;
                }
            }
            // Finally, keep tokenData in cache, if allowed
            if (tokenData && _allowInMemoryCache) {
                _database[identifier] = tokenData;
            }
        }
        // Finally, validate whether the requested factors
        if (authentication != nil && tokenData.authenticationFactors != 0) {
            if (tokenData.authenticationFactors != authentication.signatureFactorMask) {
                if (error) {
                    *error = PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Different PowerAuthAuthentication used for the same token creation.");
                }
                tokenData = nil;
            }
        }
        return tokenData;
    } error:&localError];
    if (error && localError) {
        *error = localError;
    }
    return result;
}

- (void) storeTokenDataWhenLocked:(PA2PrivateTokenData*)tokenData isUpgrade:(BOOL)isUpgrade
{
    NSString * identifier = [self identifierForTokenName:tokenData.name];
    if (tokenData.activationIdentifier == nil) {
        tokenData.activationIdentifier = _statusProvider.activationIdentifier;
    }
    NSData * data = [tokenData serializedData];
    if ([_keychain containsDataForKey:identifier]) {
        if (!isUpgrade) {
            // This is just warning, but creating two tokens with the same name at the same time, is not recommended.
            PowerAuthLog(@"KeychainTokenStore: WARNING: Looks like that token '%@' already has some data stored. Overwriting the content.", tokenData.name);
        } else {
            PowerAuthLog(@"KeychainTokenStore: Upgrading data for token '%@'.", tokenData.name);
        }
        [_keychain updateValue:data forKey:identifier];
    } else {
        [_keychain addValue:data forKey:identifier];
    }
    if (_allowInMemoryCache) {
        _database[identifier] = tokenData;
    }
}

/**
 Removes token with identifier from keychain.
 */
- (void) removeTokenWithIdentifier:(NSString*)identifier
{
    [_keychain deleteDataForKey:identifier];
    [_database removeObjectForKey:identifier];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
// PA2_DEPRECATED(2.0.0)
- (id<PowerAuthOperationTask>) generateAuthorizationHeaderWithName:(NSString *)name
                                                        completion:(void(^)(PowerAuthAuthorizationHttpHeader * header, NSError * error))completion
{
    return [self generateAuthenticationHeaderWithName:name completion:completion];
}
#pragma clang diagnostic pop

- (id<PowerAuthOperationTask>) generateAuthenticationHeaderWithName:(NSString *)name
                                                         completion:(void(^)(PowerAuthHttpHeader * header, NSError * error))completion
{
    // Prepare composite task and completion closure.
    PA2CompositeTask * compositeTask = [[PA2CompositeTask alloc] initWithCancelBlock:nil];
    void (^completionCallback)(PowerAuthToken *, NSError *) = ^(PowerAuthToken * token, NSError * error) {
        PowerAuthHttpHeader * header;
        if (token) {
            // So far, so good, generate header now.
            header = [self calculateTokenHeader:token.privateTokenData error:&error];
        } else {
            header = nil;
        }
        // Always report result back to the main thread.
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([compositeTask setCompleted]) {
                completion(header, error);
            }
        });
    };
    if (name.length > 0) {
        PowerAuthToken * token = [self localTokenWithName:name];
        if (token) {
            if (_timeSynchronizationService.isTimeSynchronized) {
                // Time is already synchronized, we can safely generate authorization header
                completionCallback(token, nil);
            } else {
                // Time is not synchronized yet.
                id<PowerAuthOperationTask> synchronizeTime = [_timeSynchronizationService synchronizeTimeWithCallback:^(NSError * _Nullable error) {
                    if (!error) {
                        // Time is properly synchronized, continue with header generator.
                        completionCallback(token, nil);
                    } else {
                        // Time synchronization failed.
                        completionCallback(nil, error);
                    }
                } callbackQueue:nil];
                if (synchronizeTime) {
                    [compositeTask replaceOperationTask:synchronizeTime];
                }
            }
        } else {
            completionCallback(nil, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Token not found"));
        }
    } else {
        // Name not provided
        completionCallback(nil, PA2MakeError(PowerAuthErrorCode_WrongParameter, @"Missing required parameter"));
    }
    return compositeTask;
}

@end
