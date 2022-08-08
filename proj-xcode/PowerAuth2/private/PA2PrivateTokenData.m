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

#define TOKEN_SECRET_LENGTH     16

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

#define KEY_NAME        @"name"
#define KEY_ID          @"id"
#define KEY_ACT_ID      @"aid"
#define KEY_FACTORS     @"af"
#define KEY_SECRET      @"sec"

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
    result.name                  = PA2ObjectAs(dict[KEY_NAME], NSString);
    result.identifier            = PA2ObjectAs(dict[KEY_ID], NSString);
    result.activationIdentifier  = PA2ObjectAs(dict[KEY_ACT_ID], NSString);
    result.authenticationFactors = [PA2ObjectAs(dict[KEY_FACTORS], NSNumber) integerValue];
    NSString * loadedB64Secret   = PA2ObjectAs(dict[KEY_SECRET], NSString);
    NSData * loadedSecret        = loadedB64Secret ? [[NSData alloc] initWithBase64EncodedString:loadedB64Secret options:0] : nil;
    if (loadedSecret) {
        result.secret = loadedSecret;
    }
    
    return result.hasValidData ? result : nil;
}

- (NSDictionary*) toDictionary
{
    if (!self.hasValidData) {
        return nil;
    }
    NSString * b64secret = [_secret base64EncodedStringWithOptions:0];
    if (_activationIdentifier != nil) {
        return @{
            KEY_NAME    : _name,
            KEY_ID      : _identifier,
            KEY_ACT_ID  : _activationIdentifier,
            KEY_FACTORS : @(_authenticationFactors),
            KEY_SECRET  : b64secret
        };
    } else {
        return @{
            KEY_NAME    : _name,
            KEY_ACT_ID  : _identifier,
            KEY_FACTORS : @(_authenticationFactors),
            KEY_SECRET  : b64secret
        };
    }
}

#pragma mark - Debug

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
    equal = equal && [otherData.activationIdentifier isEqualToString:_activationIdentifier];
    equal = equal && (otherData.authenticationFactors == _authenticationFactors);
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
