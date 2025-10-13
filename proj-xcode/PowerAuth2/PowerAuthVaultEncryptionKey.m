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

#import <PowerAuth2/PowerAuthVaultEncryptionKey.h>
#import "PA2PrivateMacros.h"

@import PowerAuthCore;

@implementation PowerAuthVaultEncryptionKey

- (instancetype) initWithCoreData:(PowerAuthCoreData*)coreData
                            keyId:(PowerAuthVaultEncryptionKeyId)keyId
                            index:(UInt64)index
                             base:(BOOL)base
{
    self = [super init];
    if (self) {
        _key = coreData;
        _keyId = keyId;
        _derivationIndex = index;
        _baseKey = base;
    }
    return self;
}

- (nullable PowerAuthVaultEncryptionKey*) deriveKeyWithIndex:(UInt64)index error:(NSError * _Nullable __autoreleasing *)error
{
    NSError * localError = nil;
    PowerAuthCoreData * newKey = [PowerAuthCoreSession deriveVaultEncryptionKey:_key
                                                                          keyId:(PowerAuthCoreVaultEncryptionKeyId)_keyId
                                                                          index:index error:&localError];
    if (localError) {
        PA2WrapError(localError, error);
        return nil;
    }
    return [[PowerAuthVaultEncryptionKey alloc] initWithCoreData:newKey
                                                           keyId:_keyId
                                                           index:index
                                                            base:NO];
}

@end
