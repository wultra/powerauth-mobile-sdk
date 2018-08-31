/*
 * Copyright 2016-2017 Wultra s.r.o.
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
	
	class pa2ServerPublicKeyVerification : public UnitTest
	{
	public:
		pa2ServerPublicKeyVerification()
		{
			CC7_REGISTER_TEST_METHOD(testPublicKeyVerification)
		}
		
		void testPublicKeyVerification()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/verify-encrypted-server-public-key-signature.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				std::string activationId            = item.stringAtPath("input.activationId");
				ByteArray encryptedServerPublicKey  = item.dataFromBase64StringAtPath("input.encryptedServerPublicKey");
				ByteArray masterServerPrivateKey    = item.dataFromBase64StringAtPath("input.masterServerPrivateKey");
				ByteArray masterServerPublicKey     = item.dataFromBase64StringAtPath("input.masterServerPublicKey");
				ByteArray signature                 = item.dataFromBase64StringAtPath("output.encryptedServerPublicKeySignature");

				protocol::ActivationData ad;
				ad.masterServerPublicKey = crypto::ECC_ImportPublicKey(nullptr, masterServerPublicKey);
				ccstAssertNotNull(ad.masterServerPublicKey);
				bool validSignature = protocol::ValidateActivationDataSignature(activationId, encryptedServerPublicKey.base64String(), signature, ad.masterServerPublicKey);
				ccstAssertTrue(validSignature);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ServerPublicKeyVerification, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
