/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#pragma once

#include <cc7/ByteArray.h>

/*
 Note that all functionality provided by this header will
 be replaced with a similar cc7 implementation.
 */

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
	// PBKDF with HMAC & SHA1
	cc7::ByteArray PBKDF2_HMAC_SHA1(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t outputBytes);
	
	// PBKDF with HMAC & SHA256
	cc7::ByteArray PBKDF2_HMAC_SHA256(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t outputBytes);
	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
