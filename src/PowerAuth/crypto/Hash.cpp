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

#include "Hash.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>


namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

	// -------------------------------------------------------------------------------------------
	// MARK: - SHA256 -
	//
	
	cc7::ByteArray SHA256(const cc7::ByteRange & data)
	{
		cc7::ByteArray hash(SHA256_DIGEST_LENGTH, 0);
		
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, data.data(), data.size());
		SHA256_Final(hash.data(), &sha256);
		OPENSSL_cleanse(&sha256, sizeof(sha256));
		
		return hash;
	}
	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
