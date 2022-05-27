/**
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

#import "PA2SessionStatusDataReader.h"

// MARK: - Private implementation

/**
 The PDReader structure helps to deserialize informations from the persisted
 activation data.
 */
typedef struct PDReader {
    const uint8_t * bytes;
    NSUInteger      length;
    NSUInteger      offset;
    BOOL            failure;
} PDReader;

/**
 Initialize persistent data stream reader with provided bytes and the length of bytes.
 */
static BOOL PDR_init(PDReader * r, const uint8_t * bytes, NSUInteger length)
{
    if (!bytes || !length) {
        return NO;
    }
    r->bytes = bytes;
    r->length = length;
    r->offset = 0;
    r->failure = NO;
    return YES;
}

/**
 Get remaining bytes in the byte stream.
 */
static NSUInteger PDR_remaining(PDReader * r)
{
    return !r->failure ? r->length - r->offset : 0;
}

/**
 Determine whether we can read required amount of bytes from the byte stream.
 */
static BOOL PDR_canRead(PDReader * r, NSUInteger length)
{
    return PDR_remaining(r) >= length;
}

/**
 Get one byte from the byte stream.
 */
static uint8_t PDR_getByte(PDReader * r)
{
    if (PDR_canRead(r, 1)) {
        return r->bytes[r->offset++];
    }
    r->failure = YES;
    return 0;
}

/**
 Copy required amount of bytes to outBytes pointer.
 */
static BOOL PDR_getMemory(PDReader * r, void * outBytes, NSUInteger outBytesLength)
{
    if (PDR_canRead(r, outBytesLength)) {
        memcpy(outBytes, r->bytes + r->offset, outBytesLength);
        r->offset += outBytesLength;
        return YES;
    }
    r->failure = YES;
    return NO;
}

/**
 Skip desired amount of bytes.
 */
static BOOL PDR_skip(PDReader * r, NSUInteger size)
{
    if (PDR_canRead(r, size)) {
        r->offset += size;
        return YES;
    }
    r->failure = YES;
    return NO;
}

/**
 Read value representing a count from the byte stream. This function is
 equivalent to DataReader::readCount() available in C++ impl.
 */
static NSUInteger PDR_getCount(PDReader * r)
{
    uint8_t tmp[4];
    tmp[0] = PDR_getByte(r);
    uint8_t marker = tmp[0] & 0xC0;
    if (marker == 0x00 || marker == 0x40) {
        // just one byte
        return tmp[0];
    }
    // marker is 2 or 3, that means that we need 1 or 3 more bytes
    NSUInteger additional_bytes = marker == 0xC0 ? 3 : 1;
    if (!PDR_getMemory(r, &tmp[1], additional_bytes)) {
        return 0;
    }
    if (marker == 0xC0) {
        // 4 bytes
        return (((NSUInteger)(tmp[0] & 0x3F)) << 24) |
               (((NSUInteger)(tmp[1]       )) << 16) |
               (((NSUInteger)(tmp[2]       )) << 8 ) |
                 (NSUInteger)(tmp[3]);
        //
    } else {
        // 2 bytes
        return (((NSUInteger)(tmp[0] & 0x3F)) << 8 ) |
                 (NSUInteger)(tmp[1]);
        //
    }
}

const uint8_t PD_MAGIC1 = 'P';
const uint8_t PD_MAGIC2 = 'A';

const uint8_t PD_TAG     = 'P';
const uint8_t PD_VER2    = '3';
const uint8_t PD_VER3    = '4';
const uint8_t PD_VER_MAX = '6';

/**
 Function extracts activation identifier from the serialized activation data.
 */
static NSString * _ExtractActivationId(const uint8_t * bytes, NSUInteger length)
{
    PDReader r;
    if (!PDR_init(&r, bytes, length)) {
        return nil;
    }
    // Process data header. The format is simple:
    //  - 'P', 'A', state
    // Where state is byte that contains 0x02 in case that the data blob contains
    // the activation data.
    if (PDR_getByte(&r) != PD_MAGIC1 || PDR_getByte(&r) != PD_MAGIC2) {
        return nil;
    }
    uint8_t state = PDR_getByte(&r);
    if (state == 0x00) {
        return nil; // Failure, or no activation
    }
    if ((state & 0x02) == 0) {
        return nil; // Invalid activation flag
    }
    
    // Process activation data. The format differs whether it's Protocol_V2 or V3:
    // Protocol V2
    //  - 'P', '3', UInt64 counter, [activationId] ...
    // Protocol V3
    //  - 'P', Char version, [hashCounter], [activationId] ...
    //    where version is '4' up to '6'
    //          hashCounter is 16 bytes serialzied as ByteArray (e.g. contains counter + data)
    
    if (PDR_getByte(&r) != PD_TAG) {
        return nil; // Invalid tag
    }
    uint8_t ver = PDR_getByte(&r);
    if (ver < PD_VER2 || ver > PD_VER_MAX) {
        return nil; // Invalid PD version
    }
    
    // Skip 16 bytes of hash counter for Protocol_V3 or 64 bit counter for V2.
    NSUInteger skipCount = ver >= PD_VER3 ? 1 + 16 : 8;
    if (!PDR_skip(&r, skipCount)) {
        return nil;
    }
    
    // Finally, extract an activation identifier.
    NSUInteger stringLength = PDR_getCount(&r);
    NSMutableData * stringData = [NSMutableData dataWithLength:stringLength];
    if (!PDR_getMemory(&r, stringData.mutableBytes, stringData.length)) {
        return nil;
    }
    return [[NSString alloc] initWithData:stringData encoding:NSUTF8StringEncoding];
}


// MARK: - Public functions

NSString * PA2SessionStatusDataReader_GetActivationId(NSData * data)
{
    return _ExtractActivationId((const uint8_t *)data.bytes, data.length);
}
