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
	
	class pa2ServerPublicKeyDecryption : public UnitTest
	{
	public:
		pa2ServerPublicKeyDecryption()
		{
			CC7_REGISTER_TEST_METHOD(testKeyDecryption)
		}
		
		void testKeyDecryption()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/decrypt-server-public-key.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				std::string activationIdShort        = item.stringAtPath("input.activationIdShort");
				std::string activationOtp            = item.stringAtPath("input.activationOtp");
				ByteArray   activationNonce          = item.dataFromBase64StringAtPath("input.activationNonce");
				ByteArray   devicePrivateKey         = item.dataFromBase64StringAtPath("input.devicePrivateKey");
				ByteArray   devicePublicKey          = item.dataFromBase64StringAtPath("input.devicePublicKey");
				ByteArray   encryptedServerPublicKey = item.dataFromBase64StringAtPath("input.encryptedServerPublicKey");
				ByteArray   ephemeralPublicKey       = item.dataFromBase64StringAtPath("input.ephemeralPublicKey");
				ByteArray   expectedServerPublicKey  = item.dataFromBase64StringAtPath("output.serverPublicKey");
				
				protocol::ActivationData ad;
				ad.expandedOtp      = protocol::ExpandOTPKey(activationIdShort, activationOtp);
				ad.devicePrivateKey = crypto::ECC_ImportPrivateKey(nullptr, devicePrivateKey);
				ccstAssertNotNull(ad.devicePrivateKey);
				bool result = protocol::DecryptServerPublicKey(ad, ephemeralPublicKey, encryptedServerPublicKey, activationNonce);
				ccstAssertTrue(result);
				ccstAssertEqual(expectedServerPublicKey, ad.serverPublicKeyData);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ServerPublicKeyDecryption, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
