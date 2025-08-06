/*
 * Copyright 2023 Wultra s.r.o.
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

#import "PowerAuthServerStatus+Private.h"
#import "PA2PrivateMacros.h"

@implementation PowerAuthServerStatus

- (instancetype) initWithJsonResponse:(id)response
{
    self = [super init];
    if (self) {
        NSDictionary * dict   = PA2ObjectAs(response, NSDictionary);
        NSNumber * serverTime = PA2ObjectAs(dict[@"serverTime"], NSNumber);
        if (serverTime) {
            _serverTime = [NSDate dateWithTimeIntervalSince1970:0.001 * [serverTime longLongValue]];
        } else {
            return nil;
        }
    }
    return self;
}

@end
