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
	
	class pa2SignatureCalculationTests : public UnitTest
	{
	public:
		pa2SignatureCalculationTests()
		{
			CC7_REGISTER_TEST_METHOD(testV2Signatures)
			CC7_REGISTER_TEST_METHOD(testV3Signatures)
			CC7_REGISTER_TEST_METHOD(testDataNormalization)
		}
		
		void testV2Signatures()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/signatures-v2.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				protocol::SignatureKeys keys;
				keys.possessionKey = item.dataFromBase64StringAtPath("input.signaturePossessionKey");
				keys.knowledgeKey  = item.dataFromBase64StringAtPath("input.signatureKnowledgeKey");
				keys.biometryKey   = item.dataFromBase64StringAtPath("input.signatureBiometryKey");
				std::string signatureType = item.stringAtPath("input.signatureType");
				uint64_t  counter         = std::stoull(item.stringAtPath("input.counter"));
				ByteArray data            = item.dataFromBase64StringAtPath("input.data");
				std::string expSignature  = item.stringAtPath("output.signature");
				
				SignatureFactor factor = factorFromString(signatureType);
				ccstAssertTrue(factor != protocol::SF_FirstLock);
				auto ctr_data = protocol::SignatureCounterToData(counter);
				std::string signature = protocol::CalculateSignature(keys, factor, ctr_data, data);
				bool match = signature == expSignature;
				if (!match) {
					ccstMessage("Doesn't match: Expected %s vs %s", expSignature.c_str(), signature.c_str());
					ccstMessage("possession : %s", keys.possessionKey.base64String().c_str());
					ccstMessage("knowledge  : %s", keys.knowledgeKey.base64String().c_str());
					ccstMessage("biometry   : %s", keys.biometryKey.base64String().c_str());
					ccstMessage("factor     : %04x (%s)", factor, signatureType.c_str());
					ccstFailure();
					break;
					//ccstMessage("Item %@", item); // we don't have dump of JSONValue to string
				}
			}
		}
		
		void testV3Signatures()
		{
			JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/signatures-v3.json");
			auto&& data = root.arrayAtPath("data");
			for (const JSONValue & item : data) {
				
				protocol::SignatureKeys keys;
				keys.possessionKey = item.dataFromBase64StringAtPath("input.signaturePossessionKey");
				keys.knowledgeKey  = item.dataFromBase64StringAtPath("input.signatureKnowledgeKey");
				keys.biometryKey   = item.dataFromBase64StringAtPath("input.signatureBiometryKey");
				std::string signatureType = item.stringAtPath("input.signatureType");
				ByteArray ctr_data		  = item.dataFromBase64StringAtPath("input.counterData");
				ByteArray data            = item.dataFromBase64StringAtPath("input.data");
				std::string expSignature  = item.stringAtPath("output.signature");
				
				SignatureFactor factor = factorFromString(signatureType);
				ccstAssertTrue(factor != protocol::SF_FirstLock);
				std::string signature = protocol::CalculateSignature(keys, factor, ctr_data, data);
				bool match = signature == expSignature;
				if (!match) {
					ccstMessage("Doesn't match: Expected %s vs %s", expSignature.c_str(), signature.c_str());
					ccstMessage("possession : %s", keys.possessionKey.base64String().c_str());
					ccstMessage("knowledge  : %s", keys.knowledgeKey.base64String().c_str());
					ccstMessage("biometry   : %s", keys.biometryKey.base64String().c_str());
					ccstMessage("factor     : %04x (%s)", factor, signatureType.c_str());
					ccstFailure();
					break;
					//ccstMessage("Item %@", item); // we don't have dump of JSONValue to string
				}
			}
		}
		
		SignatureFactor factorFromString(const std::string & factor)
		{
			static const SignatureFactor allFactors[] = {
				SF_Possession, SF_Knowledge, SF_Biometry,
				SF_Possession_Knowledge, SF_Possession_Biometry,
				SF_Possession_Knowledge_Biometry
			};
			
			for (size_t i = 0; i < sizeof(allFactors)/sizeof(SignatureFactor); i++) {
				std::string fa = protocol::ConvertSignatureFactorToString(allFactors[i]);
				if (factor == fa) {
					return allFactors[i];
				}
			}
			ccstFailure("Unable to convert factor %s to enum", factor.c_str());
			return protocol::SF_FirstLock;
		}
		
		void testDataNormalization()
		{
			std::string method("POST");
			std::string uri("/pa/activation/remove");
			std::string nonceB64("fNJQBWeKTG5Zp+zrdNu/PQ==");
			std::string secret("MDEyMzQ1Njc4OUFCQ0RFRg==");
			ByteArray body;
			ByteArray expectedNormalizedData(ByteRange("POST&L3BhL2FjdGl2YXRpb24vcmVtb3Zl&fNJQBWeKTG5Zp+zrdNu/PQ==&&MDEyMzQ1Njc4OUFCQ0RFRg=="));
			
			ByteArray normalizedData = protocol::NormalizeDataForSignature(method, uri, nonceB64, body, secret);
			ccstAssertEqual(normalizedData, expectedNormalizedData);
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2SignatureCalculationTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
