/*
 * Copyright 2025 Wultra s.r.o.
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

#import "PowerAuthCoreTokenData.h"
#include <PowerAuth/TokenService.h>
#include <cc7/objc/ObjcHelper.h>

@implementation PowerAuthCoreTokenData

static NSInteger _FactorsToMask(powerAuth::AuthFactors factors)
{
    switch (factors) {
        case powerAuth::AuthFactors::POSSESSION:
            return 1;
        case powerAuth::AuthFactors::POSSESSION_KNOWLEDGE:
            return 1 | 2;
        case powerAuth::AuthFactors::POSSESSION_BIOMETRY:
            return 1 | 4;
    }
}

- (instancetype) initWithResponse:(const powerAuth::GetAccessTokenResponsePtr&)response
{
    self = [super init];
    if (self) {
        _authenticationFactorMask = _FactorsToMask(response->getFactors());
        _tokenIdentifier = cc7::objc::CopyToNSString(response->getIdentifier());
        _tokenSecret = cc7::objc::CopyToNSData(response->getSecret());
    }
    return self;
}

@end
