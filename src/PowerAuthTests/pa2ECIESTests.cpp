/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
#include <PowerAuth/ECIES.h>
#include "../PowerAuth/crypto/CryptoUtils.h"

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
	
	class pa2ECIESTests : public UnitTest
	{
	public:
		pa2ECIESTests()
		{
			CC7_REGISTER_TEST_METHOD(testEncryptorDecryptor)
		}
		
//#define TLOG	CC7_LOG
#define TLOG(fmt, ...)

		void testEncryptorDecryptor()
		{
			ErrorCode ec;
			
			static const struct Data {
				const char * requestData;
				const char * responseData;
				const char * sharedInfo2;
			} s_test_data[] = {
				{
					"hello world!", "hey there!", ""
				},
				{
					"All your base are belong to us!", "NOPE!", "very secret information"
				},
				{
					"It's over Johny! It's over.",
					"Nothing is over! Nothing! You just don't turn it off! It wasn't my war!"
					" You asked me, I didn't ask you! And I did what I had to do to win!",
					"0123456789abcdef"
				},
				{
					"", "", "12345-56789"
				},
				{
					"", "", ""
				},
				{
					"", "", ""
				},
				{ nullptr, nullptr }
			};
			
			EC_KEY * master_keypair = crypto::ECC_GenerateKeyPair();
			cc7::ByteArray master_public_key = crypto::ECC_ExportPublicKey(master_keypair);
			cc7::ByteArray master_private_key = crypto::ECC_ExportPrivateKey(master_keypair);
			EC_KEY_free(master_keypair);
			master_keypair = nullptr;

			TLOG("{");
			TLOG("   \"keys\": {");
			TLOG("       \"serverPrivateKey\": \"%s\",", master_private_key.base64String().c_str());
			TLOG("       \"serverPublicKey\": \"%s\"", master_public_key.base64String().c_str());
			TLOG("   },");
			TLOG("   \"data\": [");
			
			auto client_encryptor = ECIESEncryptor(master_public_key, cc7::ByteRange());
			auto server_decryptor = ECIESDecryptor(master_private_key, cc7::ByteRange());
			
			const Data * p_data = s_test_data;
			while (p_data->requestData != nullptr) {
				//
				auto shared_info2 = cc7::MakeRange(p_data->sharedInfo2);
				auto request_data = cc7::MakeRange(p_data->requestData);
				auto response_data = cc7::MakeRange(p_data->responseData);
				p_data++;
				//
				ECIESCryptogram request;
				client_encryptor.setSharedInfo2(shared_info2);
				ec = client_encryptor.encryptRequest(request_data, request);
				ccstAssertEqual(ec, EC_Ok);
				ccstAssertFalse(request.body.empty());
				ccstAssertFalse(request.mac.empty());
				ccstAssertFalse(request.key.empty());
				//
				cc7::ByteArray server_received_data;
				server_decryptor.setSharedInfo2(shared_info2);
				ec = server_decryptor.decryptRequest(request, server_received_data);
				ccstAssertEqual(ec, EC_Ok);
				ccstAssertEqual(cc7::CopyToString(request_data), cc7::CopyToString(server_received_data));
				
				
				ECIESCryptogram response;
				ec = server_decryptor.encryptResponse(response_data, response);
				ccstAssertEqual(ec, EC_Ok);
				ccstAssertFalse(response.body.empty());
				ccstAssertFalse(response.mac.empty());
				ccstAssertTrue(response.key.empty());
				
				cc7::ByteArray client_received_data;
				ec = client_encryptor.decryptResponse(response, client_received_data);
				ccstAssertEqual(ec, EC_Ok);
				
				ccstAssertEqual(cc7::CopyToString(response_data), cc7::CopyToString(client_received_data));
				
				TLOG("      {");
				TLOG("         \"input\": {");
				TLOG("            \"request.plainText\" : \"%s\",", request_data.base64String().c_str());
				TLOG("            \"response.plainText\" : \"%s\",", response_data.base64String().c_str());
				TLOG("            \"sharedInfo2\" : \"%s\"", shared_info2.base64String().c_str());
				TLOG("         },");
				TLOG("         \"output\": {");
				TLOG("            \"request\" : {");
				TLOG("                 \"data\": \"%s\",", request.body.base64String().c_str());
				TLOG("                 \"mac\" : \"%s\",", request.mac.base64String().c_str());
				TLOG("                 \"key\" : \"%s\"", request.key.base64String().c_str());
				TLOG("            },");
				TLOG("            \"response\" : {");
				TLOG("                 \"data\": \"%s\",", response.body.base64String().c_str());
				TLOG("                 \"mac\" : \"%s\"", response.mac.base64String().c_str());
				TLOG("            },");
				TLOG("            \"internals\" : {");
				TLOG("                 \"k_mac\" : \"%s\",", client_encryptor.envelopeKey().macKey().base64String().c_str());
				TLOG("                 \"k_enc\" : \"%s\"", client_encryptor.envelopeKey().encKey().base64String().c_str());
				TLOG("            }");
				TLOG("         }");
				TLOG("      },");
			}
			TLOG("   ]");
			TLOG("}");
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ECIESTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
