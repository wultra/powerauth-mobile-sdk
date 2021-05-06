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

#import "PA2PrivateTokenData.h"
#import "PA2PrivateMacros.h"

#define TOKEN_SECRET_LENGTH		16

@implementation PA2PrivateTokenData

- (BOOL) hasValidData
{
	return !(!_name || !_identifier || _secret.length != TOKEN_SECRET_LENGTH);
}

- (nonnull NSData*)serializedData
{
	NSDictionary * dict = [self toDictionary];
	return [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
}

+ (PA2PrivateTokenData*) deserializeWithData:(nonnull NSData*)data
{
	if (!data) {
		return nil;
	}
	NSDictionary * dict = PA2ObjectAs([NSJSONSerialization JSONObjectWithData:data options:0 error:NULL], NSDictionary);
	if (!dict) {
		return nil;
	}
	PA2PrivateTokenData * result = [[PA2PrivateTokenData alloc] init];
	result.name		 			= PA2ObjectAs(dict[@"name"], NSString);
	result.identifier			= PA2ObjectAs(dict[@"id"], NSString);
	NSString * loadedB64Secret 	= PA2ObjectAs(dict[@"sec"], NSString);
	NSData * loadedSecret 		= loadedB64Secret ? [[NSData alloc] initWithBase64EncodedString:loadedB64Secret options:0] : nil;
	if (loadedSecret) {
		result.secret = loadedSecret;
	}
	return result.hasValidData ? result : nil;
}

#pragma mark - Private and debug

- (NSDictionary*) toDictionary
{
	if (!self.hasValidData) {
		return nil;
	}
	NSString * b64secret = [_secret base64EncodedStringWithOptions:0];
	return @{ @"name" : _name, @"id" : _identifier, @"sec": b64secret };
}

#if defined(DEBUG)
- (NSString*) description
{
	NSDictionary * dict = [self toDictionary];
	NSString * info = dict ? [dict description] : @"INVALID DATA";
	return [NSString stringWithFormat:@"<%@ 0x%p: %@>", NSStringFromClass(self.class), (__bridge void*)self, info];
}
#endif

#pragma mark - Compare

- (BOOL) isEqualToTokenData:(nullable PA2PrivateTokenData*)otherData
{
	if (self == otherData) {
		return YES;
	}
	BOOL equal = [otherData.name isEqualToString:_name];
	equal = equal && [otherData.identifier isEqualToString:_identifier];
	equal = equal && [otherData.secret isEqualToData:_secret];
	return equal;
}

#pragma mark - Copying

- (id) copyWithZone:(NSZone *)zone
{
	PA2PrivateTokenData * c = [[self.class allocWithZone:zone] init];
	if (c) {
		c->_name = _name;
		c->_identifier = _identifier;
		c->_secret = _secret;
	}
	return c;
}

@end
