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

#include "AES.h"
#include "PKCS7Padding.h"
#include <openssl/aes.h>


namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
	
	cc7::ByteArray AES_CBC_Encrypt(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
	{
		cc7::ByteArray out(data.size(), 0);
		cc7::ByteArray ivec = iv;
		AES_KEY aes_key;
		
		int res = AES_set_encrypt_key(key.data(), (int)key.size() * 8, &aes_key);
		if (res == 0) {
			AES_cbc_encrypt(data.data(), out.data(), data.size(), &aes_key, ivec.data(), AES_ENCRYPT);
		} else {
			out.clear();
			CC7_LOG("AES_set_encrypt_key failed");
		}
		return out;
	}
	
	
	cc7::ByteArray AES_CBC_Decrypt(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
	{
		cc7::ByteArray out(data.size(), 0);
		cc7::ByteArray ivec(iv);
		AES_KEY aes_key;
		
		int res = AES_set_decrypt_key(key.data(), (int)key.size() * 8, &aes_key);
		if (res == 0) {
			AES_cbc_encrypt(data.data(), out.data(), data.size(), &aes_key, ivec.data(), AES_DECRYPT);
		} else {
			out.clear();
			CC7_LOG("AES_set_decrypt_key failed");
		}
		return out;
	}
	
	
	cc7::ByteArray AES_CBC_Decrypt_Padding(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data, bool * error)
	{
		cc7::ByteArray paddedData = AES_CBC_Decrypt(key, iv, data);
		bool failure = !PKCS7_ValidateAndUpdateData(paddedData, AES_BLOCK_SIZE);
		if (failure) {
			paddedData.clear();
		}
		if (error) {
			*error = failure;
		}
		return paddedData;
	}
	
	
	cc7::ByteArray AES_CBC_Encrypt_Padding(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
	{
		cc7::ByteArray paddedData = PKCS7_GetPaddedData(data, AES_BLOCK_SIZE);
		return AES_CBC_Encrypt(key, iv, paddedData);
	}
	

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
