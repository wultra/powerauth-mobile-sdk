/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PowerAuthSecureData+Private.h"
#import <PowerAuthCore/PowerAuthCoreData.h>

@implementation PowerAuthSecureData
{
    PowerAuthCoreData * _data;
}

- (PowerAuthCoreData*) coreData
{
    return _data;
}

- (nonnull instancetype) initWithCoreData:(nonnull PowerAuthCoreData*)coreData
{
    self = [super init];
    if (self) {
        _data = coreData;
    }
    return self;
}

- (nonnull instancetype) initWithData:(nullable NSData*)data
{
    return [self initWithCoreData:[[PowerAuthCoreData alloc] initWithData:data]];
}

- (nonnull instancetype) initWithDataAndClearSource:(nullable NSData*)data
{
    return [self initWithCoreData:[[PowerAuthCoreData alloc] initWithDataAndClearSource:data]];
}

- (NSData*) sensitiveData
{
    return _data.sensitiveData;
}

- (BOOL) isEqualToSecureData:(nullable PowerAuthSecureData*)coreData
{
    if (self == coreData) {
        return YES;
    }
    return [_data isEqualToCoreData:coreData.coreData];
}

- (BOOL) isEqual:(id)object
{
    if (object == self) {
        return YES;
    }
    if ([object isKindOfClass:[PowerAuthSecureData class]]) {
        return [self isEqualToSecureData:(PowerAuthSecureData*)object];
    }
    return NO;
}

- (nonnull id) copyWithZone:(nullable NSZone *)zone
{
    PowerAuthCoreData * dataCopy = [_data copyWithZone:zone];
    return [[self.class allocWithZone:zone] initWithCoreData:dataCopy];
}

@end


@implementation PowerAuthCoreData (SdkPrivate)

- (PowerAuthSecureData*) toSecureData
{
    return [[PowerAuthSecureData alloc] initWithCoreData:self];
}

@end
