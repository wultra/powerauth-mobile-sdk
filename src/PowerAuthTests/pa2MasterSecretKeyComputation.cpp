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
	
	class pa2MasterSecretKeyComputation : public UnitTest
	{
	public:
		pa2MasterSecretKeyComputation()
		{
			CC7_REGISTER_TEST_METHOD(testMasterSecretKeyComputation)
		}
		
		void testMasterSecretKeyComputation()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/compute-master-secret-key.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				ByteArray   devicePrivateKey = item.dataFromBase64StringAtPath("input.devicePrivateKey");
				ByteArray   devicePublicKey  = item.dataFromBase64StringAtPath("input.devicePublicKey");
				ByteArray   serverPrivateKey = item.dataFromBase64StringAtPath("input.serverPrivateKey");
				ByteArray   serverPublicKey  = item.dataFromBase64StringAtPath("input.serverPublicKey");
				ByteArray   masterSecretKey  = item.dataFromBase64StringAtPath("output.masterSecretKey");
				
				protocol::ActivationData ad;
				ad.devicePrivateKey = crypto::ECC_ImportPrivateKey(nullptr, devicePrivateKey);
				ad.devicePrivateKey = crypto::ECC_ImportPublicKey(ad.devicePrivateKey, devicePublicKey);
				ccstAssertNotNull(ad.devicePrivateKey);
				ad.serverPublicKey  = crypto::ECC_ImportPublicKey(nullptr, serverPublicKey);
				ByteArray ourMasterSecretKey = crypto::ECDH_SharedSecret(ad.serverPublicKey, ad.devicePrivateKey);
				ByteArray reducedMasterSecretKey = protocol::ReduceSharedSecret(ourMasterSecretKey);
				ccstAssertEqual(reducedMasterSecretKey, masterSecretKey);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2MasterSecretKeyComputation, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
