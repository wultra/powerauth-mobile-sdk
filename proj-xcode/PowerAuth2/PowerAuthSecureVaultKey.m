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

#import <PowerAuth2/PowerAuthSecureVaultKey.h>
#import "PA2PrivateMacros.h"
#import "PowerAuthSecureData+Private.h"

#import <PowerAuthCore/PowerAuthCore.h>

@implementation PowerAuthSecureVaultKey
{
    PowerAuthSecureData * _key;
}

- (instancetype) initWithSecureData:(PowerAuthSecureData*)secureData
                              keyId:(PowerAuthSecureVaultKeyId)keyId
{
    if (!secureData) {
        return nil;
    }
    self = [super init];
    if (self) {
        _key = secureData;
        _keyId = keyId;
    }
    return self;
}

- (nullable PowerAuthSecureData*) deriveKeyWithIndex:(UInt64)index
                                             keySize:(UInt64)keySize
                                               error:(NSError * _Nullable __autoreleasing *)error
{
    NSError * localError = nil;
    PowerAuthCoreData * derivedKey = [PowerAuthCoreSession deriveVaultEncryptionKey:_key.coreData
                                                                              keyId:(PowerAuthCoreSecureVaultKeyId)_keyId
                                                                              index:index
                                                                            keySize:keySize
                                                                              error:&localError];
    if (localError) {
        PA2WrapError(localError, error);
        return nil;
    }
    return [derivedKey toSecureData];
}

- (BOOL) isEqualToVaultEncryptionKey:(nullable PowerAuthSecureVaultKey*)other
{
    if (!other) {
        return NO;
    }
    if (self == other) {
        return YES;
    }
    return _keyId == other->_keyId &&
           [_key isEqualToSecureData:other->_key];
}

- (BOOL) isEqual:(id)object
{
    if (self == object) {
        return YES;
    }
    if ([object isKindOfClass:[PowerAuthSecureVaultKey class]]) {
        return [self isEqualToVaultEncryptionKey:object];
    }
    return NO;
}

@end
