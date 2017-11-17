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
#import "PA2Macros.h"
#import "PA2ECIESEncryptor.h"

@implementation PA2PrivateTokenKeychainStore
{
	__weak PowerAuthSDK * _sdk;
	PA2Keychain * _keychain;
	PowerAuthConfiguration * _sdkConfiguration;
	PA2ECIESEncryptor * _encryptor;
}

- (id) initWithSdk:(PowerAuthSDK*)sdk keychain:(PA2Keychain*)keychain
{
	self = [super init];
	if (self) {
		_sdk = sdk;
		_keychain = keychain;
		// keep copy of config object
		_sdkConfiguration = sdk.configuration;
	}
	return self;
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
		// Wrong input params, but we don't have an error code for that...
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeOperationCancelled userInfo:nil]);
		return nil;
	}
	
	if (!_sdk.hasValidActivation) {
		completion(nil, [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeMissingActivation userInfo:nil]);
		return nil;
	}
	NSString * identifier = [self identifierForTokenName:name];
	PA2PrivateTokenData * tokenData = [PA2PrivateTokenData deserializeWithData: [_keychain dataForKey:identifier status:NULL]];
	if (tokenData) {
		PowerAuthToken * token = [[PowerAuthToken alloc] initWithStore:self data:tokenData];
		completion(token, nil);
		return nil;
	}
	// Token needs to be acquired on the server.
	return [self httpRequestForToken:name authentication:authentication callback:^(PowerAuthToken * token, NSError * error) {
		if (completion) {
			completion(token, error);
		}
	}];
}

- (void) cancelTask:(PowerAuthTokenStoreTask)task
{
	if ([task isKindOfClass:[PA2OperationTask class]]) {
		[(PA2OperationTask*)task cancel];
	}
}

- (void) removeTokenWithName:(NSString *)name
{
	if (name) {
		[self removeTokenWithIdentifier:[self identifierForTokenName:name]];
	}
}

- (void) removeAllTokens
{
	[[self allTokenIdentifiers] enumerateObjectsUsingBlock:^(NSString * identifier, NSUInteger idx, BOOL * stop) {
		[self removeTokenWithIdentifier:identifier];
	}];
}


#pragma mark - Keychain

- (NSString*) identifierForTokenName:(NSString*)name
{
	return[@"token$" stringByAppendingString:name];
}

- (BOOL) isValidIdentifierForToken:(NSString*)identifier
{
	return [identifier hasPrefix:@"token$"];
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



#pragma mark - Networking

- (PA2ECIESEncryptor*) eciesEncryptor
{
	if (!_encryptor) {
		NSData * pubKeyData = [[NSData alloc] initWithBase64EncodedString:_sdkConfiguration.masterServerPublicKey options:0];
		_encryptor = [[PA2ECIESEncryptor alloc] initWithPublicKey:pubKeyData sharedInfo2:nil];
	}
	return _encryptor;
}

- (PowerAuthTokenStoreTask) httpRequestForToken:(NSString*)token
			authentication:(PowerAuthAuthentication*)authentication
				  callback:(void(^)(PowerAuthToken *, NSError *))callback
{
	// TODO: implementation...
	return nil;
}

@end
