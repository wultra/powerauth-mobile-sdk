/*
 * Copyright 2022 Wultra s.r.o.
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

#import "PA2Result.h"

@implementation PA2Result

- (id) initWithResult:(id)result error:(NSError*)error data:(id)data
{
    self = [super init];
    if (self) {
        _result = result;
        _error = error;
        _associatedData = data;
    }
    return self;
}

+ (id) success:(id)result
{
    return [[PA2Result alloc] initWithResult:result error:nil data:nil];
}

+ (id) success:(id)result withData:(id)data
{
    return [[PA2Result alloc] initWithResult:result error:nil data:data];
}

+ (id) failure:(NSError*)failure
{
    return [[PA2Result alloc] initWithResult:nil error:failure data:nil];
}

+ (id) failure:(NSError*)failure withData:(id)data
{
    return [[PA2Result alloc] initWithResult:nil error:failure data:data];
}

+ (id)success:(id)result orFailure:(NSError*)failure
{
    return [[PA2Result alloc] initWithResult:result error:failure data:nil];
}

- (id) extractResult:(NSError**)error
{
    if (error) {
        *error = _error;
    }
    return _result;
}

@end
