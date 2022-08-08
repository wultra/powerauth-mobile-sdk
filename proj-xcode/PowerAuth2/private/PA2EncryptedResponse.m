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

#import "PA2EncryptedResponse.h"
#import "PA2PrivateMacros.h"

@import PowerAuthCore;

@implementation PA2EncryptedResponse

- (instancetype) initWithDictionary:(NSDictionary *)dict
{
    self = [super init];
    if (self) {
        _encryptedData      = PA2ObjectAs(dict[@"encryptedData"], NSString);
        _mac                = PA2ObjectAs(dict[@"mac"], NSString);
    }
    return self;
}

- (PowerAuthCoreEciesCryptogram*) cryptogram
{
    PowerAuthCoreEciesCryptogram * cryptogram = [[PowerAuthCoreEciesCryptogram alloc] init];
    cryptogram.bodyBase64 = _encryptedData;
    cryptogram.macBase64 = _mac;
    return cryptogram;
}

@end
