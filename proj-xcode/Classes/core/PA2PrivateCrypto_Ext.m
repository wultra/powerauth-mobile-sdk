/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2PrivateCrypto.h"

#if !defined(PA2_EXTENSION_SDK)
#error "This file is for IOS extensions or WatchOS projects only"
#endif

// For WatchOS we need to link CommonCrypto and use its functions
#include <CommonCrypto/CommonCrypto.h>


NSData * PA2PrivateCrypto_HMAC_SHA256(NSData * data, NSData * key)
{
	char mac[CC_SHA256_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, mac);
	return [NSData dataWithBytes:mac length:sizeof(mac)];
}

NSData * PA2PrivateCrypto_GetRandomBytes(size_t count)
{
	NSMutableData * data = [NSMutableData dataWithLength:count];
	arc4random_buf(data.mutableBytes, count);
	return data;
}
