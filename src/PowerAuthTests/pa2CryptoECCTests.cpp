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
	class pa2CryptoECCTests : public UnitTest
	{
	public:
		
		pa2CryptoECCTests()
		{
			CC7_REGISTER_TEST_METHOD(testKeyImportExport)
			CC7_REGISTER_TEST_METHOD(testPubKeyImport)
		}

		struct test_data {
			const char * point;
			bool import_result;
		};
		
		void testKeyImportExport()
		{
			// Generate key-pair
			auto key_pair = crypto::ECC_GenerateKeyPair();
			if (!key_pair) {
				ccstFailure();
				return;
			}
			// Export private and public key
			auto private_key_export = crypto::ECC_ExportPrivateKey(key_pair);
			ccstAssertFalse(private_key_export.empty());
			auto public_key_export = crypto::ECC_ExportPublicKeyToB64(key_pair);
			ccstAssertFalse(public_key_export.empty());
			EC_KEY_free(key_pair);
			// Import public & private key back to OpenSSL structure.
			auto public_key = crypto::ECC_ImportPublicKeyFromB64(nullptr, public_key_export);
			if (!public_key) {
				ccstFailure();
				return;
			}
			ccstAssertEqual(public_key_export, crypto::ECC_ExportPublicKeyToB64(public_key));
			
			auto private_key = crypto::ECC_ImportPrivateKey(nullptr, private_key_export);
			if (!private_key) {
				ccstFailure();
				EC_KEY_free(public_key);
				return;
			}
			ccstAssertEqual(private_key_export, crypto::ECC_ExportPrivateKey(private_key));
			ccstAssertEqual(1, EC_KEY_can_sign(private_key));
			
			EC_KEY_free(private_key);
			EC_KEY_free(public_key);
		}
				
		void testPubKeyImport()
		{
			const test_data test_vectors[] = {
				// Valid points
				{ "ApwBezqIdwCdmcjfysfrCaWZ5h9LttqP2RvCjapdKrLd", true },
				{ "A/CR2dXXwpj+Y2Kb3eytxmbBEv4/mqQxYW7N5oNg+iea", true },
				{ "Ag0TRAqRbD/KVDVeFDhhZX49Wk2X+NitEx7Au7KWMTWi", true },
				{ "A5kU3PmJii+kdPVoqtufs9apFbeum43Pz2WnqMyrb2Hp", true },
				{ "AxAR3xlwvz9BiFEtRkXx7unhQ5/BmEfrtkM+Z0zzpe8U", true },
				{ "AlasqZKRDyk+VUtdrQzSGbF1ATHZ3PYvyUdx3X+rdQsB", true },
				{ "A+zDDUcBMErVtKLGT3wrqssQPWgBIlfqZ8cOsU2LARRo", true },
				{ "AwOmvwWIIsvPTDcRzz9ZCEOd/CorfSE0AWIJlacCl/NO", true },
				{ "Ah6xT4mYIAa5eRRThVFwu5DH5PfWHApOUV/O46EfqKfU", true },
				{ "A83L0L6idMpdFbPsB6Btolaa33y1SztWLeE/LoYbI8Ih", true },
				// Invalid points
				{ "ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/=", false }, // invalid Base64
				{ "ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/", false }, // invalid compressed point
				{ "BMa1eFhnJNtFLU6yFeFgcHMt9iPg074ZUKM9D8tX3nuNk7cKwTbbQG8uHItW8NxvPaMYo0WM87eV5Ud9dB3/14Q=", false }, // point is not on curve
				{ "Pes+/6wnmrjwVa2L9v2wqUDBYMCtq0qvQ7JIZ6+nZe6fsT+vr85+rUPunAIaK3tRAuIkIROUwYEvj/TlcemQ5Q==", false }, // invalid encoding
				{ "BGjj8wAErlEt1FNJzH8uhpWN2GSd9apNK0tWaDAN+Bukt5EwKZ6l3YzX475apYQdVbzmg0X2mRysqrvTEPRj8b8=", false }, // point is not on curve
				{ "BLcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/Si4N7VelFWu4LrQxTDf9QVU5Wn5RmIryiczlMbnBcZI=", false }, // point is not on curve
				{ "AA==", false }, // infinity
				{ nullptr, false }
			};

			int i = 0;
			while (true) {
				const test_data & td = test_vectors[i++];
				const char * test_key = td.point;
				if (!test_key) {
					break;
				}
				EC_KEY * pub_key = crypto::ECC_ImportPublicKeyFromB64(nullptr, test_key, nullptr);
				bool imported = pub_key != nullptr;
				if (imported != td.import_result) {
					if (imported) {
						ccstFailure("Public key '%s' should not be imported.", test_key);
					} else {
						ccstFailure("Public key '%s' should be imported.", test_key);
						// Print error in case you're curious about an actual failure.
						char buffer[256];
						ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
						ccstMessage("OpenSSL failure: %s", buffer);
					}
				}
				EC_KEY_free(pub_key);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2CryptoECCTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
