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

#import "PowerAuthCoreData.h"
#import "PowerAuthCorePrivateImpl.h"

@implementation PowerAuthCoreData
{
    NSMutableData * _data;
    cc7::ByteRange _range;
}

- (instancetype) initWithData:(NSData*)data
{
    self = [super init];
    if (self) {
        [self assignByteRange:cc7::ByteRange(data.bytes, data.length)];
    }
    return self;
}


- (instancetype) initWithDataAndClearSource:(NSData*)data
{
    self = [super init];
    if (self) {
        const auto length = data.length;
        [self assignByteRange:cc7::ByteRange(data.bytes, length)];
        if ([data isKindOfClass:[NSMutableData class]]) {
            // If data is mutable, then wipe-out its content
            [(NSMutableData*)data resetBytesInRange:NSMakeRange(0, length)];
        }
    }
    return self;
}


- (instancetype) initWithByteRange:(const cc7::ByteRange &)byteRange
{
    self = [super init];
    if (self) {
        [self assignByteRange:byteRange];
    }
    return self;
}


- (void) assignByteRange:(const cc7::ByteRange &)range
{
    const auto newSize = range.size();
    if (!_data) {
        // No data object yet, just create a new object with expected size.
        _data = [NSMutableData dataWithCapacity:newSize];
    } else {
        // There's already mutable object. Clear the content first.
        memset_s(_data.mutableBytes, _data.length, 0, _data.length);
    }
    // Resize the mutable data object
    _data.length = newSize;
    // Copy new bytes
    auto ptr  = _data.mutableBytes;
    memcpy(ptr, range.data(), newSize);
    // Update range object
    _range = cc7::ByteRange(ptr, newSize);
}


- (void) dealloc
{
    // Assigning empty range causes content of array to be cleared.
    [self assignByteRange:cc7::ByteRange()];
}


- (NSData*) sensitiveData
{
    return _data;
}


- (const cc7::ByteRange &) byteArrayRef
{
    return _range;
}

- (id) copyWithZone:(NSZone *)zone
{
    return [[self.class allocWithZone:zone] initWithByteRange:_range];
}

- (BOOL) isEqualToCoreData:(PowerAuthCoreData *)coreData
{
    if (self == coreData) {
        return YES;
    } else if (!coreData) {
        return NO;
    }
    return cc7::ConstTimeEqual(_range, coreData->_range);
}

- (BOOL) isEqual:(id)object
{
    if (object == self) {
        return YES;
    }
    if ([object isKindOfClass:[PowerAuthCoreData class]]) {
        return cc7::ConstTimeEqual(_range, ((PowerAuthCoreData*)object)->_range);
    }
    return NO;
}

@end
