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

#include <cc7tests/CC7Tests.h>
#include <cc7tests/detail/StringUtils.h>
#include "../PowerAuth/crypto/CryptoUtils.h"
#include "../PowerAuth/protocol/ProtocolUtils.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	extern TestDirectory g_pa2Files;
	
	class pa2PublicKeyFingerprintTests : public UnitTest
	{
	public:
		pa2PublicKeyFingerprintTests()
		{
			CC7_REGISTER_TEST_METHOD(testPublicKeyFingerprint)
		}
		
		void testPublicKeyFingerprint()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/public-key-fingerprint.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				// Load data
				cc7::ByteArray publicKeyData  = item.dataFromBase64StringAtPath("input.publicKey");
				cc7::ByteArray expectedCoordX = item.dataFromBase64StringAtPath("output.publicKeyCoordX");
				std::string expectedFingerprint = item.stringAtPath("output.fingerprint");
				// Do the test
				EC_KEY * publicKey = crypto::ECC_ImportPublicKey(nullptr, publicKeyData);
				if (nullptr == publicKey) {
					ccstFailure("Invalid public key in test dat file");
					break;
				}
				cc7::ByteArray coordX = crypto::ECC_ExportPublicKeyToNormalizedForm(publicKey);
				if (coordX != expectedCoordX) {
					ccstMessage("CoordX doesn't match");
					ccstMessage("  expected : %s", expectedCoordX.hexString().c_str());
					ccstMessage("  ours     : %s", coordX.hexString().c_str());
					ccstFailure();
					break;
				}
				EC_KEY_free(publicKey);
				std::string fingerprint = protocol::CalculateDecimalizedSignature(crypto::SHA256(coordX));
				if (fingerprint != expectedFingerprint) {
					ccstMessage("Doesn't match: Expected %s vs %s", expectedFingerprint.c_str(), fingerprint.c_str());
					ccstMessage("  Key   : %s", publicKeyData.base64String().c_str());
					ccstMessage("  exp X : %s", expectedCoordX.hexString().c_str());
					ccstMessage("  our X : %s", coordX.hexString().c_str());
					ccstFailure();
					break;
				}
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2PublicKeyFingerprintTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io

