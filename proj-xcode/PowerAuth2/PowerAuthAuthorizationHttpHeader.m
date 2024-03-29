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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2/PowerAuthAuthorizationHttpHeader.h>

@implementation PowerAuthAuthorizationHttpHeader

- (instancetype)initWithKey:(NSString*)key value:(NSString*)value
{
    self = [super init];
    if (self) {
        _key = key;
        _value = value;
    }
    return self;
}

+ (PowerAuthAuthorizationHttpHeader*) authorizationHeaderWithValue:(NSString *)value
{
    return !value ? nil : [[self alloc] initWithKey:@"X-PowerAuth-Authorization" value:value];
}

+ (PowerAuthAuthorizationHttpHeader*) tokenHeaderWithValue:(NSString *)value
{
    return !value ? nil : [[self alloc] initWithKey:@"X-PowerAuth-Token" value:value];
}

@end
