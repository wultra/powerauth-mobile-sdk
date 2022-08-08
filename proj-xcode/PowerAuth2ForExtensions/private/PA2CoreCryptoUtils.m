/*
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2CoreCryptoUtils.h"
#import <PowerAuth2ForExtensions/PowerAuthLog.h>

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonRandom.h>

@implementation PA2CoreCryptoUtils

+ (nonnull NSData*) hashSha256:(nonnull NSData*)data
{
    unsigned char md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, md);
    return [NSData dataWithBytes:md length:sizeof(md)];
}

+ (nonnull NSData*) hmacSha256:(nonnull NSData*)data
                           key:(nonnull NSData*)key
{
    char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, mac);
    return [NSData dataWithBytes:mac length:sizeof(mac)];
}

+ (nullable NSData*) randomBytes:(NSUInteger)count
{
    if (count == 0) {
        return nil;
    }
    NSMutableData * zeros = [NSMutableData dataWithLength:count];
    NSMutableData * data  = [NSMutableData dataWithLength:count];
    void * dest_ptr = data.mutableBytes;
    size_t dest_len = data.length;
    NSUInteger attempts = 16;
    while (attempts-- != 0) {
        if (kCCSuccess != CCRandomGenerateBytes(dest_ptr, dest_len)) {
            arc4random_buf(dest_ptr, dest_len);
        }
        if (![data isEqualToData:zeros]) {
            return data;
        }
    }
    PowerAuthLog(@"PA2CoreCryptoUtils: Failed to generat %@ random bytes.", @(count));
    return nil;
}

@end
