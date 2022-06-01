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
#import "PowerAuthErrorConstants.h"
#import "PowerAuthKeychain.h"
#import "PowerAuthConfiguration.h"
#import "PowerAuthLog.h"

@implementation PA2PrivateTokenKeychainStore
{
	/// A copy of SDK configuration
	PowerAuthConfiguration *	_sdkConfiguration;
	/// Token data locking implementation
	id<PA2TokenDataLock>		_tokenDataLock;
	/// Local lock, protecting data in this process.
	id<NSLocking>				_localLock;
	
	// Lazy initialized data

	/// A prefix for all tokens stored in the keychain
	NSString * _keychainKeyPrefix;
	/// A local database for tokens.
	NSMutableDictionary<NSString*, PA2PrivateTokenData*> * _database;
	
	NSMutableDictionary<NSString*, PA2CreateTokenTask*> *_createTokenTasks;
}

- (id) initWithConfiguration:(PowerAuthConfiguration*)configuration
					keychain:(PowerAuthKeychain*)keychain
			  statusProvider:(id<PowerAuthSessionStatusProvider>)statusProvider
			  remoteProvider:(id<PA2PrivateRemoteTokenProvider>)remoteProvider
					dataLock:(id<PA2TokenDataLock>)dataLock
				   localLock:(id<NSLocking>)localLock
{
	self = [super init];
	if (self) {
		_sdkConfiguration = configuration;
		_statusProvider = statusProvider;
		_remoteTokenProvider = remoteProvider;
		_keychain = keychain;
		_tokenDataLock = dataLock;
		_localLock = localLock ? localLock : [[NSRecursiveLock alloc] init];
		_allowInMemoryCache = YES;
	}
	return self;
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
- (id) synchronized:(id(NS_NOESCAPE ^)(BOOL * setModified))block
{
	BOOL isDirty = [_tokenDataLock lockTokenStore];
	if (_keychainKeyPrefix == nil) {
		[self prepareInstance];
	}
	if (_allowInMemoryCache && isDirty) {
		[_database removeAllObjects];
	}
	BOOL modified = NO;
	id result = block(&modified);
	[_tokenDataLock unlockTokenStore:modified];
	return result;
}

/**
 A simple replacement for @synchronized() construct.
 This version of function has no return value.
 */
- (void) synchronizedVoid:(void(NS_NOESCAPE ^)(BOOL * setModified))block
{
	BOOL isDirty = [_tokenDataLock lockTokenStore];
	if (_keychainKeyPrefix == nil) {
		[self prepareInstance];
	}
	if (_allowInMemoryCache && isDirty) {
		[_database removeAllObjects];
	}
	BOOL modified = NO;
	block(&modified);
	[_tokenDataLock unlockTokenStore:modified];
}

#pragma mark - PowerAuthPrivateTokenStore protocol

- (BOOL) canGenerateHeaderForToken:(PowerAuthToken *)token
{
	return [_statusProvider hasValidActivation] && [_statusProvider.activationIdentifier isEqualToString:token.privateTokenData.activationIdentifier];
}

- (void) storeTokenData:(PA2PrivateTokenData*)tokenData
{
	[self synchronizedVoid:^(BOOL *setModified) {
		if (!self.canRequestForAccessToken) {
			return;
		}
		[self storeTokenDataWhenLocked:tokenData isUpgrade:NO];
		*setModified = YES;
	}];
}

- (void) removeCreateTokenTask:(NSString *)tokenName
{
	[_localLock lock];
	// Remove group task from the dictionary.
	[_createTokenTasks removeObjectForKey:tokenName];
	[_localLock unlock];
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
	PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name];
	if (tokenData) {
		// The data is available, so the token can be returned synchronously
		PowerAuthToken * token = [[PowerAuthToken alloc] initWithStore:self data:tokenData];
		completion(token, nil);
		return nil;
	}
	
	id<PA2PrivateRemoteTokenProvider> strongTokenProvider = _remoteTokenProvider;
	if (!strongTokenProvider) {
		// Looks like parent SDK object is already destroyed.
		completion(nil, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Object is no longer operational."));
		return nil;
	}
	
	// Local token is not found, so we have to fire a remote request.
	
	[_localLock lock];
	//
	PA2CreateTokenTask * groupTask = _createTokenTasks[name];
	id<PowerAuthOperationTask> result = nil;
	NSError * error = nil;
	if (groupTask && authenticationIsRequired) {
		if (![groupTask.authentication hasEqualFactorsToAuthentication:authentication]) {
			error = PA2MakeError(PowerAuthErrorCode_WrongParameter, @"There's already pending request for this token, but with a different authentication.");
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
	PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name];
	if (!tokenData) {
		completion(NO, PA2MakeError(PowerAuthErrorCode_InvalidToken, @"Token not found."));
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


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
- (void) cancelTask:(id)task
{
	[PA2ConformsTo(task, PowerAuthOperationTask) cancel];
}
#pragma clang diagnostic pop

- (void) removeLocalTokenWithName:(NSString *)name
{
	[self synchronizedVoid:^(BOOL * setModified){
		if (name) {
			[self removeTokenWithIdentifier:[self identifierForTokenName:name]];
			*setModified = YES;
		}
	}];
}


- (void) removeAllLocalTokens
{
	[self synchronizedVoid:^(BOOL *setModified) {
		[[self allTokenIdentifiers] enumerateObjectsUsingBlock:^(NSString * identifier, NSUInteger idx, BOOL * stop) {
			[self removeTokenWithIdentifier:identifier];
		}];
		*setModified = YES;
	}];
}


- (BOOL) hasLocalTokenWithName:(nonnull NSString*)name
{
	return nil != [self tokenDataForTokenName:name];
}


- (PowerAuthToken*) localTokenWithName:(NSString*)name
{
	PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name];
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
{
	return [self synchronized:^id(BOOL *setModified) {
		NSString * identifier = [self identifierForTokenName:name];
		PA2PrivateTokenData * tokenData = _allowInMemoryCache ? _database[identifier] : nil;
		if (!tokenData) {
			tokenData = [PA2PrivateTokenData deserializeWithData: [_keychain dataForKey:identifier status:NULL]];
			if (tokenData) {
				NSString * aid = tokenData.activationIdentifier;
				if (aid == nil) {
					// Old data format, with no activation identifier serialized. Re-save the data
					[self storeTokenDataWhenLocked:tokenData isUpgrade:YES];
					*setModified = YES;
				} else if (![aid isEqualToString:_statusProvider.activationIdentifier]) {
					// Looks like serialized activation identifier is different to the current AID.
					// This token is no longer valid and must be removed from the keychain.
					PowerAuthLog(@"KeychainTokenStore: WARNING: Token '%@' is no longer valid.", name);
					[_keychain deleteDataForKey:identifier];
					tokenData = nil;
					*setModified = YES;
				}
			}
			// Finally, keep tokenData in cache, if allowed
			if (tokenData && _allowInMemoryCache) {
				_database[identifier] = tokenData;
			}
		}
		return tokenData;
	}];
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

@end
