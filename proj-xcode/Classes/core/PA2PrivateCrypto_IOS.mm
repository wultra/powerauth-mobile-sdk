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

// For IOS, we can use CC7 as a crypto provider
#include <cc7/objc/ObjcHelper.h>
#include "CryptoUtils.h"

#import "PA2PrivateCrypto.h"

#if defined(PA2_EXTENSION_SDK)
#error "This should not be compiled in IOS extensions or WatchOS projects"
#endif

using namespace io::getlime::powerAuth;

NSData * PA2PrivateCrypto_HMAC_SHA256(NSData * data, NSData * key)
{
	auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), 0);
	return cc7::objc::CopyToNSData(result);
}

NSData * PA2PrivateCrypto_GetRandomBytes(size_t count)
{
	return cc7::objc::CopyToNullableNSData(crypto::GetRandomData(count, true));
}
