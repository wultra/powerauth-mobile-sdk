/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateMacros.h"
#import "PA2ErrorConstants.h"
#import "PA2Keychain.h"
#import "PowerAuthConfiguration.h"

@implementation PA2PrivateTokenKeychainStore
{
	/// A copy of SDK configuration
	PowerAuthConfiguration *	_sdkConfiguration;
	/// Semaphore for locking
	dispatch_semaphore_t		_lock;
	
	// Lazy initialized data

	/// A prefix for all tokens stored in the keychain
	NSString * _keychainKeyPrefix;
	/// A local database for tokens.
	NSMutableDictionary<NSString*, PA2PrivateTokenData*> * _database;
	/// A debug set with pending operations (valid only for DEBUG build of library)
	NSMutableSet<NSString*> * 	_pendingNamedOperations;
}

/**
 Following debug macros allows tracking of dangerous simultaneous requests for the same tokens.
 The feature is turned off in release build of the library.
 */
#if defined(DEBUG)
	#define _START_OPERATION(name)	[self startOperationForName:name]
	#define _STOP_OPERATION(name)	[self stopOperationForName:name]
	#define _OPERATIONS_SET() 		[NSMutableSet set]
#else
	#define _START_OPERATION(name)
	#define _STOP_OPERATION(name)
	#define _OPERATIONS_SET() 		nil
#endif


- (id) initWithConfiguration:(PowerAuthConfiguration*)configuration
					keychain:(PA2Keychain*)keychain
			  statusProvider:(id<PA2SessionStatusProvider>)statusProvider
			  remoteProvider:(id<PA2PrivateRemoteTokenProvider>)remoteProvider
{
	self = [super init];
	if (self) {
		_sdkConfiguration = configuration;
		_statusProvider = statusProvider;
		_remoteTokenProvider = remoteProvider;
		_keychain = keychain;
		_lock = dispatch_semaphore_create(1);
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
static void _prepareInstance(PA2PrivateTokenKeychainStore * obj)
{
	// Initialize remote provider (instance may be nil)
	[obj->_remoteTokenProvider prepareInstanceForConfiguration:obj->_sdkConfiguration];

	// Build base key for all stored tokens
	obj->_keychainKeyPrefix = [PA2PrivateTokenKeychainStore keychainPrefixForInstanceId:obj->_sdkConfiguration.instanceId];
	obj->_database = [NSMutableDictionary dictionaryWithCapacity:2];
	// ...and debug set for overlapping operations
	obj->_pendingNamedOperations = _OPERATIONS_SET();
}


/**
 A simple replacement for @synchronized() construct.
 This version of function returns object returned from the block.
 */
static id _synchronized(PA2PrivateTokenKeychainStore * obj, id(^block)(void))
{
	dispatch_semaphore_wait(obj->_lock, DISPATCH_TIME_FOREVER);
	if (nil == obj->_keychainKeyPrefix) {
		_prepareInstance(obj);
	}
	id result = block();
	dispatch_semaphore_signal(obj->_lock);
	return result;
}

/**
 A simple replacement for @synchronized() construct.
 This version of function has no return value.
 */
static void _synchronizedVoid(PA2PrivateTokenKeychainStore  * obj, void(^block)(void))
{
	dispatch_semaphore_wait(obj->_lock, DISPATCH_TIME_FOREVER);
	if (nil == obj->_keychainKeyPrefix) {
		_prepareInstance(obj);
	}
	block();
	dispatch_semaphore_signal(obj->_lock);
}

#pragma mark - PowerAuthTokenStore protocol

- (BOOL) canRequestForAccessToken
{
	return [_statusProvider hasValidActivation];
}

- (PowerAuthTokenStoreTask) requestAccessTokenWithName:(NSString*)name
										authentication:(PowerAuthAuthentication*)authentication
											completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
	return [self requestAccessTokenImpl:name authentication:authentication completion:completion];
}

- (PowerAuthTokenStoreTask) requestAccessTokenWithName:(NSString*)name
											completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
	return [self requestAccessTokenImpl:name authentication:nil completion:completion];
}

/*
 This is an actual implementation of `requestAccessTokenWithName...` method, but allowing authentication to be nil.
 */
- (PowerAuthTokenStoreTask) requestAccessTokenImpl:(NSString*)name
									authentication:(PowerAuthAuthentication*)authentication
										completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
	if (!name || !completion) {
		if (completion) {
			completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeWrongParameter userInfo:nil]);
		}
		return nil;
	}
	if (!authentication && [_remoteTokenProvider authenticationIsRequired]) {
		if (completion) {
			completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeWrongParameter userInfo:nil]);
		}
		return nil;
	}
	if (!_statusProvider.hasValidActivation) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
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
		PALog(@"KeychainTokenStore: ERROR: The store has no remote token provider. Returning invalid token error.");
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidToken userInfo:nil]);
		return nil;
	}
	
	_START_OPERATION(name);
	return [strongTokenProvider requestTokenWithName:name authentication:authentication completion:^(PA2PrivateTokenData * _Nullable tokenData, NSError * _Nullable error) {
		PowerAuthToken * token;
		if (tokenData && !error) {
			[self storeTokenData:tokenData];
			token = [[PowerAuthToken alloc] initWithStore:self data:tokenData];
		} else {
			token = nil;
		}
		_STOP_OPERATION(name);
		completion(token, error);
	}];
}


- (PowerAuthTokenStoreTask) removeAccessTokenWithName:(NSString *)name
										   completion:(void (^)(BOOL, NSError * ))completion
{
	if (!name || !completion) {
		if (completion) {
			completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeWrongParameter userInfo:nil]);
		}
		return nil;
	}
	if (!_statusProvider.hasValidActivation) {
		completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
		return nil;
	}
	PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name];
	if (!tokenData) {
		completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidToken userInfo:nil]);
		return nil;
	}
	
	id<PA2PrivateRemoteTokenProvider> strongTokenProvider = _remoteTokenProvider;
	if (!strongTokenProvider) {
		PALog(@"KeychainTokenStore: ERROR: The store has no remote token provider. Returning invalid token error.");
		completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidToken userInfo:nil]);
		return nil;
	}
	
	_START_OPERATION(name);
	return [strongTokenProvider removeTokenData:tokenData completion:^(BOOL removed, NSError * _Nullable error) {
		_STOP_OPERATION(name);
		if (removed) {
			[self removeLocalTokenWithName:name];
		}
		completion(removed, error);
	}];
}


- (void) cancelTask:(PowerAuthTokenStoreTask)task
{
	[_remoteTokenProvider cancelTask:task];
}


- (void) removeLocalTokenWithName:(NSString *)name
{
	_synchronizedVoid(self, ^{
		if (name) {
			[self removeTokenWithIdentifier:[self identifierForTokenName:name]];
		}
	});
}


- (void) removeAllLocalTokens
{
	_synchronizedVoid(self, ^{
		[[self allTokenIdentifiers] enumerateObjectsUsingBlock:^(NSString * identifier, NSUInteger idx, BOOL * stop) {
			[self removeTokenWithIdentifier:identifier];
		}];
	});
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
	return _synchronized(self, ^id{
		NSString * identifier = [self identifierForTokenName:name];
		PA2PrivateTokenData * tokenData = _database[identifier];
		if (!tokenData) {
			tokenData = [PA2PrivateTokenData deserializeWithData: [_keychain dataForKey:identifier status:NULL]];
			if (tokenData && _allowInMemoryCache) {
				_database[identifier] = tokenData;
			}
		}
		return tokenData;
	});
}

/**
 Stores a private data object to keychain.
 */
- (void) storeTokenData:(PA2PrivateTokenData*)tokenData
{
	if (!self.canRequestForAccessToken) {
		return;
	}
	_synchronizedVoid(self, ^{
		NSString * identifier = [self identifierForTokenName:tokenData.name];
		NSData * data = [tokenData serializedData];
		if ([_keychain containsDataForKey:identifier]) {
			// This is just warning, but creating two tokens with the same name at the same time, is not recommended.
			PALog(@"KeychainTokenStore: WARNING: Looks like that token '%@' already has some data stored. Overwriting the content.", tokenData.name);
			[_keychain updateValue:data forKey:identifier];
		} else {
			[_keychain addValue:data forKey:identifier];
		}
		_database[identifier] = tokenData;
	});
}

/**
 Removes token with identifier from keychain.
 */
- (void) removeTokenWithIdentifier:(NSString*)identifier
{
	[_keychain deleteDataForKey:identifier];
	[_database removeObjectForKey:identifier];
}

#pragma mark - Debug methods

#if defined(DEBUG)
- (void) startOperationForName:(NSString*)name
{
	_synchronizedVoid(self, ^{
		if ([_pendingNamedOperations containsObject:name]) {
			// Well, this store implementation is thread safe, so the application won't crash on race condition, but it's not aware against requesting
			// the same token for multiple times. This may lead to situations, when you will not be able to remove all previously created tokens
			// on the server.
			// This warning is also displayed for removal and creation operations created at the same time.
			PALog(@"TokenKeychainStore: WARNING: Looks like you're running simultaneous operations for token '%@'. This is highly not recommended.", name);
		} else {
			[_pendingNamedOperations addObject:name];
		}
	});
}

- (void) stopOperationForName:(NSString*)name
{
	_synchronizedVoid(self, ^{
		[_pendingNamedOperations removeObject:name];
	});
}
#endif // defined(DEBUG)


@end
