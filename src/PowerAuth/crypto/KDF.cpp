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

#include "KDF.h"
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
	// MARK: - PBKDF2 -
	//
	
	cc7::ByteArray PBKDF2_HMAC_SHA1(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t outputBytes)
	{
		cc7::ByteArray result(outputBytes, 0);
		if (1 != PKCS5_PBKDF2_HMAC((const char*)pass.data(), (int)pass.size(), salt.data(), (int)salt.size(), (int)iterations, EVP_sha1(), (int)outputBytes, result.data())) {
			CC7_LOG("PKCS5_PBKDF2_HMAC has failed!");
			result.clear();
		}
		return result;
	}

	cc7::ByteArray PBKDF2_HMAC_SHA256(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t outputBytes)
	{
		cc7::ByteArray result(outputBytes, 0);
		if (1 != PKCS5_PBKDF2_HMAC((const char*)pass.data(), (int)pass.size(), salt.data(), (int)salt.size(), (int)iterations, EVP_sha256(), (int)outputBytes, result.data())) {
			CC7_LOG("PKCS5_PBKDF2_HMAC has failed!");
			result.clear();
		}
		return result;
	}

	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io

