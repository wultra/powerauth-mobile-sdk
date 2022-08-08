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

#import "PA2Request.h"

@implementation PA2Request

- (instancetype) initWithObject:(id<PA2Encodable>)object
{
    self = [super init];
    if (self) {
        _requestObject = object;
    }
    return self;
}

- (NSDictionary*) toDictionary
{
    NSDictionary * dict = [_requestObject toDictionary];
    return dict ? @{ @"requestObject" : dict } : @{};
}

@end
