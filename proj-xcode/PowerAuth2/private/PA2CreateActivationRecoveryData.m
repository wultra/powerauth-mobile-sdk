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

#import "PA2CreateActivationRecoveryData.h"
#import "PA2PrivateMacros.h"

@implementation PA2CreateActivationRecoveryData

- (instancetype) initWithDictionary:(NSDictionary<NSString *,NSObject *> *)dictionary
{
    self = [super init];
    if (self) {
        _recoveryCode   = PA2ObjectAs(dictionary[@"recoveryCode"], NSString);
        _puk            = PA2ObjectAs(dictionary[@"puk"], NSString);
    }
    return self;
}

@end
