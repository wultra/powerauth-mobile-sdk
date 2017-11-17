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

#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateTokenData.h"
#import "PA2PrivateCrypto.h"
#import "PA2AuthorizationHttpHeader.h"
#import "PA2Macros.h"

@implementation PowerAuthToken
{
	PA2PrivateTokenData * _tokenData;
}


#pragma mark - Public methods

- (NSString*) tokenName
{
	@synchronized (self) {
		return _tokenData.name;
	}
}

- (PA2AuthorizationHttpHeader*) generateHeader
{
	NSData * tokenSecret = nil;
	NSString * tokenIdentifier = nil;
	// Capture constants in thread-safe block
	@synchronized (self) {
		if (!_tokenData.hasValidData) {
			// Data object is not valid.
			PALog(@"PowerAuthToken: Token contains invalid data, or has been already removed.");
			return nil;
		}
		if (![_tokenStore canRequestForAccessToken]) {
			PALog(@"PowerAuthToken: The associated token store has no longer valid activation.");
			return nil;
		}
		tokenSecret = _tokenData.secret;
		tokenIdentifier = _tokenData.identifier;
	}
	// Prepare data for HMAC
	NSNumber * currentTimeMs = @((int64_t)([[NSDate date] timeIntervalSince1970] * 1000));
	NSString * currentTimeString = [currentTimeMs stringValue];
	NSData * currentTimeData = [currentTimeString dataUsingEncoding:NSASCIIStringEncoding];
	NSData * nonce = PA2PrivateCrypto_GetRandomBytes(16);
	NSMutableData * data = [nonce mutableCopy];
	[data appendBytes:"&" length:1];
	[data appendData: currentTimeData];
	// Calculate digest...
	NSData * digest = PA2PrivateCrypto_HMAC_SHA256(data, tokenSecret);
	NSString * digestBase64 = [digest base64EncodedStringWithOptions:0];
	NSString * nonceBase64 = [nonce base64EncodedStringWithOptions:0];
	// Final check...
	if (digest.length == 0 || !digestBase64 || !nonceBase64 || !currentTimeString) {
		PALog(@"PowerAuthToken: Digest calculation did fail.");
		return nil;
	}
	NSString * value = [NSString stringWithFormat:
						@"PowerAuth version=\"2.1\""
						@" token_id=\"%@\""
						@" token_digest=\"%@\""
						@" nonce=\"%@\""
						@" timestamp=\"%@\"",
						tokenIdentifier, digestBase64, nonceBase64, currentTimeString];
	return [PA2AuthorizationHttpHeader tokenHeaderWithValue:value];
}

- (void) remove
{
	NSString * nameToRemove;
	id<PowerAuthTokenStore> store;
	@synchronized (self) {
		nameToRemove = _tokenData.name;
		store = _tokenStore;
		_tokenStore = nil;
		_tokenData = nil;
	}
	if (nameToRemove) {
		[store removeTokenWithName:nameToRemove];
	}
}

- (BOOL) isValid
{
	@synchronized (self) {
		return _tokenData != nil;
	}
}


#pragma mark - Private methods

- (id) init
{
	return nil;
}

- (id) initWithStore:(id<PowerAuthTokenStore>)store
				data:(PA2PrivateTokenData*)data
{
	self = [super init];
	if (self) {
		_tokenStore = store;
		_tokenData = data;
	}
	return self;
}

- (void) accessPrivateData:(void (^_Nonnull)(PA2PrivateTokenData * _Nullable tokenData))block
{
	@synchronized (self) {
		if (block) {
			block(_tokenData);
		}
	}
}

@end
