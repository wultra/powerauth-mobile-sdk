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

#include "Digest.h"
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
	// MARK: - HMAC & SHA & PBKDF2 -
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
	
	cc7::ByteArray HMAC_SHA256(const cc7::ByteRange & data, const cc7::ByteRange & key, size_t outputBytes)
	{
		const unsigned char * key_ptr = key.empty() ? NULL : key.data();
		
		cc7::ByteArray digest(SHA256_DIGEST_LENGTH, 0);
		unsigned int digest_length = SHA256_DIGEST_LENGTH;
		const unsigned char * result = HMAC(EVP_sha256(), key_ptr, (int)key.size(), data.data(), (int)data.size(), digest.data(), &digest_length);
		
		if ((result != NULL) && (digest_length == digest.size())) {
			if (outputBytes > 0 && outputBytes < SHA256_DIGEST_LENGTH) {
				digest.resize(outputBytes);
			}
			return digest;
		}
		CC7_LOG("HMAC_SHA256 has failed!");
		return cc7::ByteArray();
	}
	
	cc7::ByteArray PBKDF2_HMAC_SHA_1(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t outputBytes)
	{
		cc7::ByteArray result(outputBytes, 0);
		PKCS5_PBKDF2_HMAC_SHA1((const char*)pass.data(), (int)pass.size(), salt.data(), (int)salt.size(), (int)iterations, (int)outputBytes, result.data());
		return result;
	}
	
	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
