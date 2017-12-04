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
#include "TargetConditionals.h"

#if TARGET_OS_IPHONE == 1 && TARGET_OS_IOS == 1
	#define USE_CC7
#endif

#if defined(USE_CC7)
	// For IOS, we can use CC7 as a crypto provider
	#include <cc7/objc/ObjcHelper.h>
	#include "CryptoUtils.h"
	using namespace io::getlime::powerAuth;
#else
	// For WatchOS we need to link CommonCrypto and use its functions
	#include <CommonCrypto/CommonCrypto.h>
#endif

NSData * PA2PrivateCrypto_HMAC_SHA256(NSData * data, NSData * key)
{
#if defined(USE_CC7)
	auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), 0);
	return cc7::objc::CopyToNSData(result);
#else
	char mac[CC_SHA256_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, mac);
	return [NSData dataWithBytes:mac length:sizeof(mac)];
#endif
}

NSData * PA2PrivateCrypto_GetRandomBytes(size_t count)
{
#if defined(USE_CC7)
	return cc7::objc::CopyToNSData(crypto::GetRandomData(count));
#else
	NSMutableData * data = [NSMutableData dataWithLength:count];
	arc4random_buf(data.mutableBytes, count);
	return data;
#endif
}
