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
	
	class pa2ActivationStatusBlobTests : public UnitTest
	{
	public:
		pa2ActivationStatusBlobTests()
		{
			CC7_REGISTER_TEST_METHOD(testPublicKeyFingerprint)
		}
		
		void testPublicKeyFingerprint()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/activation-status-blob-iv.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				// Load data
				cc7::ByteArray transportKey  = item.dataFromBase64StringAtPath("input.transportKey");
				cc7::ByteArray challenge     = item.dataFromBase64StringAtPath("input.challenge");
				cc7::ByteArray nonce         = item.dataFromBase64StringAtPath("input.nonce");
				cc7::ByteArray expectedIV    = item.dataFromBase64StringAtPath("output.iv");
				cc7::ByteArray calculatedIV = protocol::DeriveIVForStatusBlobDecryption(challenge, nonce, transportKey);
				
				if (calculatedIV != expectedIV) {
					ccstFailure("Doesn't match: Expected %s vs %s", expectedIV.hexString().c_str(), calculatedIV.hexString().c_str());
					break;
				}
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ActivationStatusBlobTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
