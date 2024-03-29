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

#import "PA2CreateActivationResponse.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateActivationResponse

- (instancetype) initWithDictionary:(NSDictionary *)dictionary
{
    self = [super init];
    if (self) {
        NSDictionary * activationDataDict   = PA2ObjectAs(dictionary[@"activationData"], NSDictionary);
        _activationData = [[PA2EncryptedResponse alloc] initWithDictionary:activationDataDict];
        _customAttributes                   = PA2ObjectAs(dictionary[@"customAttributes"], NSDictionary);
        _userInfo                           = PA2ObjectAs(dictionary[@"userInfo"], NSDictionary);
    }
    return self;
}

@end
