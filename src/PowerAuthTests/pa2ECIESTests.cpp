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
		
		void testEncryptorDecryptor()
		{
			ErrorCode ec;
			
			EC_KEY * master_keypair = crypto::ECC_GenerateKeyPair();
			cc7::ByteArray master_public_key = crypto::ECC_ExportPublicKey(master_keypair);
			cc7::ByteArray master_private_key = crypto::ECC_ExportPrivateKey(master_keypair);
			EC_KEY_free(master_keypair);
			master_keypair = nullptr;

			// With SharedInfo2
			{
				auto test_data = cc7::MakeRange("All your base are belong to us!");
				
				auto client_encryptor = ECIESEncryptor(master_public_key);
				auto server_decryptor = ECIESDecryptor(master_private_key);
				
				const char * sharedInfos[] = {
					"hello world",
					"short",
					"0123456789abcdef",
					"very long shared info",
					"",		// empty
					NULL	// end of table
				};
				const char ** p_info = sharedInfos;
				while (const char * sinfo2 = *p_info++) {
					//
					ECIESCryptogram request;
					auto shared_info2 = cc7::MakeRange(sinfo2);
					ec = client_encryptor.encryptRequest(test_data, shared_info2, request);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(request.body.empty());
					ccstAssertFalse(request.mac.empty());
					ccstAssertFalse(request.key.empty());
					//
					
					cc7::ByteArray server_received_data;
					ec = server_decryptor.decryptRequest(request, shared_info2, server_received_data);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual("All your base are belong to us!",       cc7::CopyToString(server_received_data));
					
					// Prepare response data & Encrypt them with decryptor
					auto server_response_data = server_received_data;
					server_response_data.append(cc7::MakeRange(" NOPE!"));
					
					ECIESCryptogram response;
					ec = server_decryptor.encryptResponse(server_response_data, shared_info2, response);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(response.body.empty());
					ccstAssertFalse(response.mac.empty());
					ccstAssertTrue(response.key.empty());
					
					cc7::ByteArray client_received_data;
					ec = client_encryptor.decryptResponse(response, shared_info2, client_received_data);
					ccstAssertEqual(ec, EC_Ok);
					
					ccstAssertEqual("All your base are belong to us! NOPE!", cc7::CopyToString(client_received_data));
				}
			}
		}
	};
	
	CC7_CREATE_UNIT_TEST(pa2ECIESTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
