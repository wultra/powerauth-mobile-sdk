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

#import "PowerAuthSDK.h"	// THIS... is really, really heavy inlcude :(
#import "PA2PrivateTokenKeychainStore.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateTokenInterfaces.h"
#import "PA2ECIESEncryptor.h"
#import "PA2Client.h"
#import "PA2EncryptedRequest.h"
#import "PA2EncryptedResponse.h"
#import "PA2GetTokenResponse.h"
#import "PA2PrivateMacros.h"

@implementation PA2PrivateTokenKeychainStore
{
	/// Weak reference to PowerAuthSDK
	__weak PowerAuthSDK *		 _sdk;
	/// A copy of SDK configuration
	PowerAuthConfiguration *	_sdkConfiguration;
	/// Semaphore for locking
	dispatch_semaphore_t		_lock;
	
	// Lazy initialized data

	/// A prefix for all tokens stored in the keychain
	NSString * _keychainKeyPrefix;
	/// An ECIES encryptor, created from master server public key.
	PA2ECIESEncryptor * 		_encryptor;
	/// A HTTP client for communication with the server
	PA2Client * 				_client;
	/// A debug set with pending operations (valid only for DEBUG build of library)
	NSMutableSet<NSString*> * 	_pendingNamedOperations;
	/// A local database for tokens.
	NSMutableDictionary<NSString*, PA2PrivateTokenData*> * _database;
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

- (id) initWithSdk:(PowerAuthSDK*)sdk keychain:(PA2Keychain*)keychain
{
	self = [super init];
	if (self) {
		_sdk = sdk;
		_keychain = keychain;
		_sdkConfiguration = sdk.configuration;		// keep copy of config object
		_lock = dispatch_semaphore_create(1);
	}
	return self;
}

/**
 Prepares runtime data required by this class. We're initializing that objects only
 on demand, when the first token is being accessed.
 */
static void _prepareInstance(PA2PrivateTokenKeychainStore * obj)
{
	// Prepare encryptor
	NSData * pubKeyData = [[NSData alloc] initWithBase64EncodedString:obj->_sdkConfiguration.masterServerPublicKey options:0];
	obj->_encryptor = [[PA2ECIESEncryptor alloc] initWithPublicKey:pubKeyData sharedInfo2:nil];
	// Prepare client
	obj->_client = [[PA2Client alloc] init];
	obj->_client.baseEndpointUrl = obj->_sdkConfiguration.baseEndpointUrl;
	obj->_client.defaultRequestTimeout = [PA2ClientConfiguration sharedInstance].defaultRequestTimeout;
	obj->_client.sslValidationStrategy = [PA2ClientConfiguration sharedInstance].sslValidationStrategy;
	obj->_database = [NSMutableDictionary dictionaryWithCapacity:2];
	// ...and debug set for overlapping operations
	obj->_pendingNamedOperations = _OPERATIONS_SET();
	// Build base key for all stored tokens
	obj->_keychainKeyPrefix = [[@"powerAuthToken__" stringByAppendingString:obj->_sdkConfiguration.instanceId] stringByAppendingString:@"__"];
}


/**
 A simple replacement for @synchronized() construct.
 This version of function returns object returned from the block.
 */
static id _synchronized(PA2PrivateTokenKeychainStore * obj, id(^block)(void))
{
	dispatch_semaphore_wait(obj->_lock, DISPATCH_TIME_FOREVER);
	if (nil == obj->_encryptor) {
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
	if (nil == obj->_encryptor) {
		_prepareInstance(obj);
	}
	block();
	dispatch_semaphore_signal(obj->_lock);
}

#pragma mark - PowerAuthTokenStore protocol

- (BOOL) canRequestForAccessToken
{
	return [_sdk hasValidActivation];
}


- (PowerAuthTokenStoreTask) requestAccessTokenWithName:(NSString*)name
										authentication:(PowerAuthAuthentication*)authentication
											completion:(void(^)(PowerAuthToken * token, NSError * error))completion
{
	if (!name || !authentication || !completion) {
		if (completion) {
			completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeWrongParameter userInfo:nil]);
		}
		return nil;
	}
	if (!_sdk.hasValidActivation) {
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

	// Prepare request. We're encrypting empty data, so the ephemeral key is only payload in the JSON.
	PA2EncryptedRequest * requestObject = [[PA2EncryptedRequest alloc] init];
	__block PA2ECIESEncryptor * responseDecryptor = nil;
	BOOL success = [_encryptor encryptRequest:nil completion:^(PA2ECIESCryptogram * cryptogram, PA2ECIESEncryptor * decryptor) {
		requestObject.ephemeralPublicKey = cryptogram.keyBase64;
		responseDecryptor = decryptor;
	}];
	if (!success) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil]);
		return nil;
	}
	// Prepare operation task...
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	_START_OPERATION(name);
	
	// Prepare callback to main thread
	void (^safeCompletion)(PowerAuthToken*, NSError*) = ^(PowerAuthToken * token, NSError * error) {
		dispatch_async(dispatch_get_main_queue(), ^{
			_STOP_OPERATION(name);
			completion(token, error);
		});
	};

	// ...and do the rest on background thread, due to expected biometric signature.
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

		NSError * error = nil;
		// This is tricky. We need to embed that request object before the signature is calculated.
		// We need to use the same function as is used in the PA2Client for data preparation. 
		NSData * jsonData = [_client embedNetworkObjectIntoRequest:requestObject];
		if (!jsonData || error) {
			safeCompletion(nil, error);
		}
		// Now sign encrypted data
		PA2AuthorizationHttpHeader * header = [_sdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/pa/token/create" body:jsonData error:&error];
		if (!header || error) {
			safeCompletion(nil, error);
		}
		task.dataTask = [_client createToken:header encryptedData:requestObject callback:^(PA2RestResponseStatus status, PA2EncryptedResponse * encryptedResponse, NSError * error) {
			PowerAuthToken * token = nil;
			if (status == PA2RestResponseStatus_OK) {
				// Decrypt response
				PA2ECIESCryptogram * responseCryptogram = [[PA2ECIESCryptogram alloc] init];
				responseCryptogram.bodyBase64 = encryptedResponse.encryptedData;
				responseCryptogram.macBase64 = encryptedResponse.mac;
				NSData * responseData = [responseDecryptor decryptResponse:responseCryptogram];
				if (responseData) {
					// Parse JSON
					NSDictionary * responseDictionary = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:responseData options:0 error:&error], NSDictionary);
					if (responseDictionary && !error) {
						// ...and finally, create a private token data object
						PA2GetTokenResponse * responseObject = [[PA2GetTokenResponse alloc] initWithDictionary:responseDictionary];
						PA2PrivateTokenData * tokenData = [[PA2PrivateTokenData alloc] init];
						tokenData.identifier = responseObject.tokenId;
						tokenData.name = name;
						tokenData.secret = responseObject.tokenSecret ? [[NSData alloc] initWithBase64EncodedString:responseObject.tokenSecret options:0] : nil;
						if (tokenData.hasValidData) {
							// Everything looks good, store token to keychain and create and finally create a new PowerAuthToken object
							[self storeTokenData:tokenData];
							token = [[PowerAuthToken alloc] initWithStore:self data:tokenData];
						}
					}
				}
			}
			// call back to the application...
			if (!token && !error) {
				// Create fallback error in case that token has not been created.
				error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil];
			}
			safeCompletion(token, error);
		}];
	});
	return task;
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
	if (!_sdk.hasValidActivation) {
		completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
		return nil;
	}
	PA2PrivateTokenData * tokenData = [self tokenDataForTokenName:name];
	if (!tokenData) {
		completion(NO, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeInvalidToken userInfo:nil]);
		return nil;
	}

	// Prepare data for HTTP request
	PA2RemoveTokenRequest * removeRequest = [[PA2RemoveTokenRequest alloc] init];
	removeRequest.tokenId = tokenData.identifier;
	NSData * jsonData = [_client embedNetworkObjectIntoRequest:removeRequest];
	// Sign http request
	NSError * error = nil;
	PowerAuthAuthentication * authentication = [[PowerAuthAuthentication alloc] init];
	authentication.usePossession = YES;
	PA2AuthorizationHttpHeader * signatureHeader = [_sdk requestSignatureWithAuthentication:authentication method:@"POST" uriId:@"/pa/token/remove" body:jsonData error:&error];
	if (!signatureHeader || error) {
		completion(NO, error);
		return nil;
	}
	
	// Start http request...
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	_START_OPERATION(name);
	task.dataTask = [_client removeToken:removeRequest
						 signatureHeader:signatureHeader
								callback:^(PA2RestResponseStatus status, NSError * _Nullable error) {
		if (status == PA2RestResponseStatus_OK) {
			[self removeLocalTokenWithName:name];
		}
		dispatch_async(dispatch_get_main_queue(), ^{
			_STOP_OPERATION(name);
			completion(error == nil, error);
		});
	}];
	return task;
}


- (void) cancelTask:(PowerAuthTokenStoreTask)task
{
	if ([task isKindOfClass:[PA2OperationTask class]]) {
		[(PA2OperationTask*)task cancel];
	}
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

/**
 Returns identifier for keychain created from token's name
 */
- (NSString*) identifierForTokenName:(NSString*)name
{
	return[_keychainKeyPrefix stringByAppendingString:name];
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
			if (tokenData) {
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
			PALog(@"WARNING: TokenKeychainStore: Looks like you're running simultaneous operations for token '%@'. This is highly not recommended.", name);
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
#endif

@end
