/*
 * Copyright 2024 Wultra s.r.o.
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

#import "PA2GetTemporaryKeyResponse.h"
#import "PA2PrivateMacros.h"

@implementation PA2GetTemporaryKeyResponse

- (instancetype) initWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
    self = [super init];
    if (self) {
        _applicationKey         = PA2ObjectAs(dictionary[@"applicationKey"], NSString);
        _activationId   = PA2ObjectAs(dictionary[@"activationId"], NSString);
        _challenge      = PA2ObjectAs(dictionary[@"challenge"], NSString);
        _publicKey      = PA2ObjectAs(dictionary[@"publicKey"], NSString);
        _keyId          = PA2ObjectAs(dictionary[@"sub"], NSString);
        _expiration     = [PA2ObjectAs(dictionary[@"exp_ms"], NSNumber) unsignedLongLongValue];
        _serverTime     = [PA2ObjectAs(dictionary[@"iat_ms"], NSNumber) unsignedLongLongValue];
    }
    return self;
}

@end
