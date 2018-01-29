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

#import "FakePowerAuthTokenStore.h"
#import "PowerAuthTestServerAPI.h"

@implementation FakePowerAuthTokenStore
{
	PowerAuthTestServerAPI * _testServer;
	NSString * _activationId;
	NSMutableDictionary<NSString*, PA2PrivateTokenData*> * _tokens;
}

- (id) initWithTestServer:(PowerAuthTestServerAPI*)testServer activationId:(NSString*)activationId
{
	self = [super init];
	if (self) {
		_testServer = testServer;
		_activationId = activationId;
		_tokens = @{}.mutableCopy;
	}
	return self;
}

#pragma mark - Fake PowerAuthTokenStore

- (BOOL) canRequestForAccessToken
{
	return _testServer.appDetail != nil;
}

- (nullable PowerAuthTokenStoreTask) requestAccessTokenWithName:(nonnull NSString*)name
												 authentication:(nonnull PowerAuthAuthentication*)authentication
													 completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion
{
	PA2PrivateTokenData * tokenData = _tokens[name];
	if (!tokenData) {
		PATSToken * serverToken = [_testServer createTokenForApplication:_testServer.appDetail activationId:_activationId signatureType:@"POSSESSION"];
		if (!serverToken) {
			completion(nil, [NSError errorWithDomain:@"FakeTokenStoreError" code:-99 userInfo:nil]);
			return nil;
		}
		tokenData = [[PA2PrivateTokenData alloc] init];
		tokenData.identifier = serverToken.tokenIdentifier;
		tokenData.name = name;
		tokenData.secret = [[NSData alloc] initWithBase64EncodedString:serverToken.tokenSecret options:0];
		if (!tokenData.hasValidData) {
			completion(nil, [NSError errorWithDomain:@"FakeTokenStoreError" code:-999 userInfo:nil]);
			return nil;
		}
		// Cache this object
		_tokens[name] = tokenData;
	}
	// Return a new token instance
	PowerAuthToken * token = [[PowerAuthToken alloc] initWithStore:self data:tokenData];
	completion(token, nil);
	return nil;
}

- (nullable PowerAuthTokenStoreTask) requestAccessTokenWithName:(nonnull NSString*)name
													 completion:(nonnull void(^)(PowerAuthToken * _Nullable token, NSError * _Nullable error))completion
{
	if (completion) {
		completion(nil, [NSError errorWithDomain:@"FakeTokenStoreError" code:-999 userInfo:nil]);
	}
	return nil;
}

- (nullable PowerAuthTokenStoreTask) removeAccessTokenWithName:(nonnull NSString*)name
													completion:(nonnull void(^)(BOOL removed, NSError * _Nullable error))completion
{
	PA2PrivateTokenData * tokenData = _tokens[name];
	BOOL removed = NO;
	NSError * error = nil;
	if (tokenData) {
		PATSToken * token = [[PATSToken alloc] init];
		token.tokenIdentifier = tokenData.identifier;
		token.tokenSecret = [tokenData.secret base64EncodedStringWithOptions:0];
		token.activationId = _activationId;
		removed = [_testServer removeToken:token];
		if (removed) {
			[_tokens removeObjectForKey:name];
		} else {
			error = [NSError errorWithDomain:@"FakeTokenStoreError" code:-97 userInfo:nil];
		}
	} else {
		error = [NSError errorWithDomain:@"FakeTokenStoreError" code:-96 userInfo:nil];
	}
	if (completion) {
		completion(removed, error);
	}
	return nil;
}

- (void) cancelTask:(PowerAuthTokenStoreTask)task
{
	// empty, this store has no asynchronous tasks
}

- (void) removeLocalTokenWithName:(NSString *)name
{
	[_tokens removeObjectForKey:name];
}

- (void) removeAllLocalTokens
{
	[_tokens removeAllObjects];
}

- (BOOL) hasLocalTokenWithName:(NSString *)name
{
	return [_tokens objectForKey:name] != nil;
}

- (PowerAuthToken*) localTokenWithName:(NSString*)name
{
	PA2PrivateTokenData * tokenData = _tokens[name];
	if (tokenData) {
		return [[PowerAuthToken alloc] initWithStore:self data:tokenData];
	}
	return nil;
}

@end
