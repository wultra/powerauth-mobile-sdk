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
	__weak PowerAuthSDK *		 _sdk;
	PowerAuthConfiguration *	_sdkConfiguration;
	
	// Lazy initialized data
	dispatch_once_t 			_dispatchOnceToken;
	PA2ECIESEncryptor * 		_encryptor;
	PA2Client * 				_client;
	NSMutableSet<NSString*> * 	_pendingNamedOperations;
}

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
		_dispatchOnceToken = 0;
	}
	return self;
}

/**
 Prepares runtime data required by this class. We're initializing that objects only
 on demand, when the first token is being accessed.
 */
- (void) prepareRuntimeData
{
	dispatch_once(&_dispatchOnceToken, ^{
		// Prepare encryptor
		NSData * pubKeyData = [[NSData alloc] initWithBase64EncodedString:_sdkConfiguration.masterServerPublicKey options:0];
		_encryptor = [[PA2ECIESEncryptor alloc] initWithPublicKey:pubKeyData sharedInfo2:nil];
		// Prepare client
		_client = [[PA2Client alloc] init];
		_client.baseEndpointUrl = _sdkConfiguration.baseEndpointUrl;
		_client.defaultRequestTimeout = [PA2ClientConfiguration sharedInstance].defaultRequestTimeout;
		_client.sslValidationStrategy = [PA2ClientConfiguration sharedInstance].sslValidationStrategy;
		// ...and debug set for overlapping operations
		_pendingNamedOperations = _OPERATIONS_SET();
	});
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
	[self prepareRuntimeData];

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
				} else {
				}
			}
			// call back to application...
			if (!token && !error) {
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
	[self prepareRuntimeData];

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
	
	PA2RemoveTokenRequest * removeRequest = [[PA2RemoveTokenRequest alloc] init];
	removeRequest.tokenId = tokenData.identifier;
	
	// Start http request...
	PA2OperationTask *task = [[PA2OperationTask alloc] init];
	_START_OPERATION(name);

	task.dataTask = [_client removeToken:removeRequest callback:^(PA2RestResponseStatus status, NSError * _Nullable error) {
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
	if (name) {
		[self removeTokenWithIdentifier:[self identifierForTokenName:name]];
	}
}


- (void) removeAllLocalTokens
{
	[[self allTokenIdentifiers] enumerateObjectsUsingBlock:^(NSString * identifier, NSUInteger idx, BOOL * stop) {
		[_keychain deleteDataForKey:identifier];
	}];
}



#pragma mark - Keychain

- (NSString*) identifierForTokenName:(NSString*)name
{
	return[@"token__" stringByAppendingString:name];
}


- (BOOL) isValidIdentifierForToken:(NSString*)identifier
{
	return [identifier hasPrefix:@"token__"];
}


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


- (void) removeTokenWithIdentifier:(NSString*)identifier
{
	[_keychain deleteDataForKey:identifier];
}


- (PA2PrivateTokenData*) tokenDataForTokenName:(NSString*)name
{
	NSString * identifier = [self identifierForTokenName:name];
	return [PA2PrivateTokenData deserializeWithData: [_keychain dataForKey:identifier status:NULL]];
}


- (void) storeTokenData:(PA2PrivateTokenData*)tokenData
{
	NSString * identifier = [self identifierForTokenName:tokenData.name];
	NSData * data = [tokenData serializedData];
	if ([_keychain containsDataForKey:identifier]) {
		// This is just warning, but creating two tokens with the same name at the same time, is not recommended.
		PALog(@"KeychainTokenStore: WARNING: Looks like that token '%@' already has some data stored. Overwriting the content.", tokenData.name);
		[_keychain updateValue:data forKey:identifier];
	} else {
		[_keychain addValue:data forKey:identifier];
	}
}


#pragma mark - Debug methods

#if defined(DEBUG)
- (void) startOperationForName:(NSString*)name
{
	@synchronized (self) {
		if ([_pendingNamedOperations containsObject:name]) {
			// Well, this store implementation is thread safe, so the application won't crash on race condition, but it's not aware against requesting
			// the same token for multiple times. This may lead to situations, when you will not be able to remove all previously created tokens
			// on the server.
			// This warning is also displayed for removal and creation operations created simultaneously.
			PALog(@"WARNING: TokenKeychainStore: Looks like you're running simultaneous operations for the same token name. This is not recommended.");
		} else {
			[_pendingNamedOperations addObject:name];
		}
	}
}

- (void) stopOperationForName:(NSString*)name
{
	@synchronized (self) {
		[_pendingNamedOperations removeObject:name];
	}
}
#endif

@end
