/**
 * Copyright 2017 Wultra s.r.o.
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
#import "PA2PlatformCrypto.h"
#import "PA2AuthorizationHttpHeader.h"
#import "PA2Log.h"

@implementation PowerAuthToken
{
	PA2PrivateTokenData * _tokenData;
}

#pragma mark - Public getters

- (PA2PrivateTokenData*) privateTokenData
{
	return _tokenData;
}

- (NSString*) tokenName
{
	return _tokenData.name;
}

- (NSString*) tokenIdentifier
{
	return _tokenData.identifier;
}

- (BOOL) isValid
{
	return _tokenData != nil;
}

- (BOOL) canGenerateHeader
{
	return _tokenData != nil && _tokenStore.canRequestForAccessToken;
}

#pragma mark - Public methods

- (PA2AuthorizationHttpHeader*) generateHeader
{
	NSData * tokenSecret = nil;
	NSString * tokenIdentifier = nil;
	
	if (!self.canGenerateHeader) {
#if defined(DEBUG)
		if (!self.isValid) {
			PA2Log(@"PowerAuthToken: Token contains invalid data.");
		} else {
			PA2Log(@"PowerAuthToken: The associated token store has no longer valid activation.");
		}
#endif
		return nil;
	}
	
	tokenSecret = _tokenData.secret;
	tokenIdentifier = _tokenData.identifier;

	// Prepare data for HMAC
	NSNumber * currentTimeMs = @((int64_t)([[NSDate date] timeIntervalSince1970] * 1000));
	NSString * currentTimeString = [currentTimeMs stringValue];
	NSData * currentTimeData = [currentTimeString dataUsingEncoding:NSASCIIStringEncoding];
	NSData * nonce = PA2PrivateCrypto_GetRandomBytes(16);
	if (nonce.length != 16) {
		PA2Log(@"PowerAuthToken: Random generator did not generate enough bytes.");
		return nil;
	}
	NSMutableData * data = [nonce mutableCopy];
	[data appendBytes:"&" length:1];
	[data appendData: currentTimeData];
	// Calculate digest...
	NSData * digest = PA2PrivateCrypto_HMAC_SHA256(data, tokenSecret);
	NSString * digestBase64 = [digest base64EncodedStringWithOptions:0];
	NSString * nonceBase64 = [nonce base64EncodedStringWithOptions:0];
	// Final check...
	if (digest.length == 0 || !digestBase64 || !nonceBase64 || !currentTimeString) {
		PA2Log(@"PowerAuthToken: Digest calculation did fail.");
		return nil;
	}
	NSString * value = [NSString stringWithFormat:
						@"PowerAuth version=\"3.1\""
						@", token_id=\"%@\""
						@", token_digest=\"%@\""
						@", nonce=\"%@\""
						@", timestamp=\"%@\"",
						tokenIdentifier, digestBase64, nonceBase64, currentTimeString];
	return [PA2AuthorizationHttpHeader tokenHeaderWithValue:value];
}

- (BOOL) isEqualToToken:(nonnull PowerAuthToken*)token
{
	if (token == self) {
		return YES;
	}
	if (_tokenStore != token.tokenStore || !_tokenData) {
		return NO;
	}
	return [_tokenData isEqualToTokenData:token.privateTokenData];
}

#pragma mark - Copying

- (id) copyWithZone:(NSZone *)zone
{
	return [[PowerAuthToken alloc] initWithStore:_tokenStore data:[_tokenData copy]];
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

#pragma mark - Debug

#if defined(DEBUG)
- (NSString*) description
{
	return [NSString stringWithFormat:@"<PowerAuthToken name='%@' identifier='%@' canGenerateHeader=%@>",
			self.tokenName,
			self.tokenIdentifier,
			@(self.canGenerateHeader)];
}
#endif // DEBUG

@end
