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
	
	class pa2ActivationOTPExpandingTests : public UnitTest
	{
	public:
		pa2ActivationOTPExpandingTests()
		{
			CC7_REGISTER_TEST_METHOD(testOTPExpansion)
		}
		
		void testOTPExpansion()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/encrypt-device-public-key.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				std::string activationIdShort = item.stringAtPath("input.activationIdShort");
				std::string activationOtp     = item.stringAtPath("input.activationOtp");
				ByteArray   activationNonce   = item.dataFromBase64StringAtPath("input.activationNonce");
                ByteArray   masterPublicKey   = item.dataFromBase64StringAtPath("input.masterPublicKey");
                ByteArray   ephPrivKey        = item.dataFromBase64StringAtPath("input.ephemeralPrivateKey");
				std::string applicationKey    = item.stringAtPath("input.applicationKey");
				std::string applicationSecret = item.stringAtPath("input.applicationSecret");
				ByteArray   pubKeyBytes       = item.dataFromBase64StringAtPath("input.devicePublicKey");
				ByteArray   expectedEncPubKey = item.dataFromBase64StringAtPath("output.cDevicePublicKey");
				std::string expectedAppSignat = item.stringAtPath("output.applicationSignature");

				protocol::ActivationData ad;
				ad.activationNonce     = activationNonce;
				ad.devicePublicKeyData = pubKeyBytes;
                ad.ephemeralDeviceKey  = crypto::ECC_ImportPrivateKey(nullptr, ephPrivKey);
                ad.masterServerPublicKey = crypto::ECC_ImportPublicKey(nullptr, masterPublicKey);
                
				ByteArray encPubKey   = protocol::EncryptDevicePublicKey(ad, activationIdShort, activationOtp);
				bool equal = encPubKey == expectedEncPubKey;
				
				// Backward operation, just to be sure that enc/dec with padding works
                ByteArray ephemeralKey = protocol::ReduceSharedSecret(crypto::ECDH_SharedSecret(ad.masterServerPublicKey, ad.ephemeralDeviceKey));
                ByteArray tmp   = crypto::AES_CBC_Decrypt_Padding(ephemeralKey, activationNonce, encPubKey);
				ByteArray decPubKey   = crypto::AES_CBC_Decrypt_Padding(ad.expandedOtp, activationNonce, tmp);
				ccstAssertEqual(decPubKey, pubKeyBytes);
				
				if (!equal) {
					ccstMessage("shortId  : %s", activationIdShort.c_str());
					ccstMessage("otp      : %s", activationOtp.c_str());
					ccstMessage("nonce    : %s", activationNonce.hexString().c_str());
					ccstMessage("exp OTP  : %s", ad.expandedOtp.hexString().c_str());
					ccstMessage("encrypted: %s", encPubKey.hexString().c_str());
					ccstMessage("expected : %s", expectedEncPubKey.hexString().c_str());
					
					ccstFailure();
					break;
				}
				
				// Validate application signature calculation
				std::string encPubKeyB64 = encPubKey.base64String();
				std::string activationNonceB64 = activationNonce.base64String();
				std::string applicationSignature = protocol::CalculateApplicationSignature(activationIdShort, activationNonceB64, encPubKeyB64, applicationKey, applicationSecret);
				
				ccstAssertEqual(applicationSignature,expectedAppSignat);
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ActivationOTPExpandingTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
