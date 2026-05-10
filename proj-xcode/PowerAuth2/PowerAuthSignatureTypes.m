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

#import "PowerAuthSignatureTypes.h"

#import <PowerAuthCore/PowerAuthCore.h>

@implementation PowerAuthDevicePublicKeyData

- (instancetype) initWithCoreDevicePublicKeyData:(PowerAuthCoreDevicePublicKeyData*)keyData
{
    self = [super init];
    if (self) {
        _keyType = (PowerAuthSignatureKeyType) keyData.keyType;
        _keyAlgorithm = keyData.keyAlgorithm;
        _keyData = keyData.keyData;
    }
    return self;
}

- (NSString*) description
{
    NSString * keyType = _keyType == PowerAuthSignatureKeyType_EC ? @"EC" : @"ML-DSA";
    return [NSString stringWithFormat:@"<PowerAuthDevicePublicKeyData type=\"%@\", algorithm=\"%@\">", keyType, _keyAlgorithm];
}

@end
