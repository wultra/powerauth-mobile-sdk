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

#include <cc7tests/CC7Tests.h>
#include <cc7/HexString.h>
#include <cc7/Base64.h>
#include "crypto/CryptoUtils.h"
#include <openssl/err.h>

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	class pa2CryptoECDSATests : public UnitTest
	{
	public:
		
		pa2CryptoECDSATests()
		{
			CC7_REGISTER_TEST_METHOD(testEcdsaSignVerify)
			//CC7_REGISTER_TEST_METHOD(ecdsaTestDataGenerator)
		}
		
		void testEcdsaSignVerify()
		{
			// Generate key-pair
			auto key_pair = crypto::ECC_GenerateKeyPair();
			if (!key_pair) {
				ccstFailure();
				return;
			}
			auto public_key_export = crypto::ECC_ExportPublicKeyToB64(key_pair);
			ccstAssertFalse(public_key_export.empty());
			// Import public & private key back to OpenSSL structure.
			auto public_key = crypto::ECC_ImportPublicKeyFromB64(nullptr, public_key_export);
			if (!public_key) {
				ccstFailure();
				EC_KEY_free(key_pair);
				return;
			}
			
			// Compute signature
			auto message = getRandomData();
			cc7::ByteArray signature;
			auto success = crypto::ECDSA_ComputeSignature(message, key_pair, signature);
			ccstAssertTrue(success);
			ccstAssertFalse(signature.empty());
			
			// Validate signature
			auto result = crypto::ECDSA_ValidateSignature(message, signature, public_key);
			ccstAssertTrue(result);
			
			// Validate corrupted data
			auto bad_message = message;
			bad_message[12]++;
			result = crypto::ECDSA_ValidateSignature(bad_message, signature, public_key);
			ccstAssertFalse(result);
			auto bad_signature = signature;
			bad_signature[12]++;
			result = crypto::ECDSA_ValidateSignature(message, bad_signature, public_key);
			ccstAssertFalse(result);
			result = crypto::ECDSA_ValidateSignature(bad_message, bad_signature, public_key);
			ccstAssertFalse(result);
			
			EC_KEY_free(public_key);
			EC_KEY_free(key_pair);
		}
		
		void ecdsaTestDataGenerator()
		{
			// This function generates a test data for high level functions to test
			// JNI and ObjC wrappers.
			const bool hex_output = false;
			for (int i = 0; i < 10; i++) {
				auto key_pair = crypto::ECC_GenerateKeyPair();
				auto key = crypto::ECC_ExportPublicKeyToB64(key_pair);
				auto data = getRandomData();
				cc7::ByteArray signature;
				auto result = crypto::ECDSA_ComputeSignature(data, key_pair, signature);
				EC_KEY_free(key_pair);
				if (!result) {
					ccstFailure("Failed to compute signature");
					return;
				}
				printf("Iteration %d\n", i);
				if (hex_output) {
					auto key_hex = FromBase64String(key).hexString();
					printf("  - Message    : %s\n", data.hexString().c_str());
					printf("  - Signature  : %s\n", signature.hexString().c_str());
					printf("  - Public Key : %s\n", key_hex.c_str());
				} else {
					printf("  - Message    : %s\n", data.base64String().c_str());
					printf("  - Signature  : %s\n", signature.base64String().c_str());
					printf("  - Public Key : %s\n", key.c_str());
				}
			}
		}
		
	private:
		cc7::ByteArray getRandomData()
		{
			size_t count = (crypto::GetRandomData(1)[0] & 63) + 13;
			return crypto::GetRandomData(count);
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2CryptoECDSATests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
