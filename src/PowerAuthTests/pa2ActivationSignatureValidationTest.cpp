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
	
	class pa2ActivationSignatureValidationTest : public UnitTest
	{
	public:
		pa2ActivationSignatureValidationTest()
		{
			CC7_REGISTER_TEST_METHOD(testSignaturesValidation)
		}
		
		void testSignaturesValidation()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/verify-activation-data-signature.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				std::string activationIdShort = item.stringAtPath("input.activationIdShort");
				std::string activationOtp     = item.stringAtPath("input.activationOtp");
				std::string masterPrivateKey  = item.stringAtPath("input.masterPrivateKey");
				std::string masterPublicKey   = item.stringAtPath("input.masterPublicKey");
				std::string signature         = item.stringAtPath("output.activationSignature");

				EC_KEY * masterPK = crypto::ECC_ImportPublicKeyFromB64(nullptr, masterPublicKey);
				ccstAssertNotNull(masterPK);
				bool valid = protocol::ValidateShortIdAndOtpSignature(activationIdShort, activationOtp, signature, masterPK);
				ccstAssertTrue(valid);
				EC_KEY_free(masterPK);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ActivationSignatureValidationTest, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
