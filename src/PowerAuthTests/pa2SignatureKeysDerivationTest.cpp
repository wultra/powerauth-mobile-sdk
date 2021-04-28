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
	
	class pa2SignatureKeysDerivationTest : public UnitTest
	{
	public:
		pa2SignatureKeysDerivationTest()
		{
			CC7_REGISTER_TEST_METHOD(testKeyDerivation)
		}
		
		void testKeyDerivation()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/compute-derived-keys.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				ByteArray masterSecret   = item.dataFromBase64StringAtPath("input.masterSecretKey");
				ByteArray outPosssession = item.dataFromBase64StringAtPath("output.signaturePossessionKey");
				ByteArray outKnowledge   = item.dataFromBase64StringAtPath("output.signatureKnowledgeKey");
				ByteArray outBiometry    = item.dataFromBase64StringAtPath("output.signatureBiometryKey");
				ByteArray outTransport   = item.dataFromBase64StringAtPath("output.transportKey");
				ByteArray outVault       = item.dataFromBase64StringAtPath("output.vaultEncryptionKey");
				
				protocol::SignatureKeys keys;
				ByteArray vault_key;
				bool result = protocol::DeriveAllSecretKeys(keys, vault_key, masterSecret);
				ccstAssertTrue(result);
				
				ccstAssertEqual(keys.possessionKey, outPosssession);
				ccstAssertEqual(keys.knowledgeKey, outKnowledge);
				ccstAssertEqual(keys.biometryKey, outBiometry);
				ccstAssertEqual(keys.transportKey, outTransport);
				ccstAssertEqual(vault_key, outVault);

			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2SignatureKeysDerivationTest, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
