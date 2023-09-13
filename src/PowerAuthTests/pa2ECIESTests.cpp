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
#include <cc7tests/detail/StringUtils.h>
#include <PowerAuth/ECIES.h>
#include <cc7/HexString.h>
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

#define PRINT_TLOG 1
#if PRINT_TLOG == 1
    #define TLOG ccstMessage
#else
    #define TLOG(fmt, ...)
#endif
    
    extern TestDirectory g_pa2Files;
    
    class pa2ECIESTests : public UnitTest
    {
    public:
        pa2ECIESTests()
        {
            CC7_REGISTER_TEST_METHOD(testEncryptorDecryptor)
            CC7_REGISTER_TEST_METHOD(testInvalidCurve)
        }
        
        void testEncryptorDecryptor()
        {
            ErrorCode ec;
            
            static const struct Data {
                const char * requestData;
                const char * responseData;
                const char * sharedInfo1;
                const char * sharedInfo2;
                const char * associatedData;
                const cc7::U64 timestamp;
            } s_test_data[] = {
                {
                    "hello world!", "hey there!", "", "", "", 1000UL
                },
                {
                    "All your base are belong to us!", "NOPE!", "very secret information", "not-so-secret", "associated-data", 329847329UL
                },
                {
                    "It's over Johny! It's over.",
                    "Nothing is over! Nothing! You just don't turn it off! It wasn't my war!"
                    " You asked me, I didn't ask you! And I did what I had to do to win!",
                    "0123456789abcdef",
                    "John Tramonta",
                    "associated_data",
                    0UL
                },
                {
                    "", "", "12345-56789", "ZX128", "C64", 9998UL
                },
                {
                    "{}", "{}", "", "", "", 771006UL
                },
                {
                    "{}", "", "", "", "", 20201116UL
                },
                { nullptr, nullptr }
            };
            
            EC_KEY * master_keypair = crypto::ECC_GenerateKeyPair();
            cc7::ByteArray master_public_key = crypto::ECC_ExportPublicKey(master_keypair);
            cc7::ByteArray master_private_key = crypto::ECC_ExportPrivateKey(master_keypair);
            EC_KEY_free(master_keypair);
            master_keypair = nullptr;
            // Make the private key compatible with Java. We need to force the big number as always positive,
            // because Java's using signed bytes. So, If the sequence of bytes in big number begins with
            // value greater than 127, then the whole big number is treated as negative.
            // Fortunately, we have to do this trick only for the testing purposes, because normally,
            // we don't exchange the private keys :)
            if (master_private_key[0] > 0x7F) {
                master_private_key.insert(master_private_key.begin(), 0x00);
            }
            TLOG("{");
            TLOG("   \"keys\": {");
            TLOG("       \"serverPrivateKey\": \"%s\",", master_private_key.base64String().c_str());
            TLOG("       \"serverPublicKey\": \"%s\"", master_public_key.base64String().c_str());
            TLOG("   },");
            TLOG("   \"data\": [");
            
            auto client_encryptor = ECIESEncryptor(master_public_key, cc7::ByteRange(), cc7::ByteRange());
            auto server_decryptor = ECIESDecryptor(master_private_key, cc7::ByteRange(), cc7::ByteRange());
            
            const Data * p_data = s_test_data;
            while (p_data->requestData != nullptr) {
                //
                auto shared_info1 = cc7::MakeRange(p_data->sharedInfo1);
                auto shared_info2 = cc7::MakeRange(p_data->sharedInfo2);
                auto request_data = cc7::MakeRange(p_data->requestData);
                auto response_data = cc7::MakeRange(p_data->responseData);
                auto associated_data = cc7::MakeRange(p_data->associatedData);
                auto timestamp_req = p_data->timestamp;
                auto timestamp_res = timestamp_req + 1;
                p_data++;
                //
                ECIESCryptogram request;
                ECIESParameters request_params;
                request_params.associatedData = associated_data;
                request_params.timestamp = timestamp_req;
                client_encryptor.setSharedInfo1(shared_info1);
                client_encryptor.setSharedInfo2(shared_info2);
                ec = client_encryptor.encryptRequest(request_data, request_params, request);
                ccstAssertEqual(ec, EC_Ok);
                ccstAssertFalse(request.body.empty());
                ccstAssertFalse(request.mac.empty());
                ccstAssertFalse(request.key.empty());
                ccstAssertFalse(request.nonce.empty());
                // Keep internal values for test-data generator purposes
                auto request_iv = client_encryptor.envelopeKey().deriveIvForNonce(request.nonce).base64String();
                auto k_enc = client_encryptor.envelopeKey().encKey().base64String();
                auto k_mac = client_encryptor.envelopeKey().macKey().base64String();
                auto k_iv = client_encryptor.envelopeKey().ivKey().base64String();
                
                //
                cc7::ByteArray server_received_data;
                server_decryptor.setSharedInfo1(shared_info1);
                server_decryptor.setSharedInfo2(shared_info2);
                ec = server_decryptor.decryptRequest(request, request_params, server_received_data);
                ccstAssertEqual(ec, EC_Ok);
                ccstAssertEqual(cc7::CopyToString(request_data), cc7::CopyToString(server_received_data));
                
                
                ECIESCryptogram response;
                ECIESParameters response_params;
                response_params.associatedData = associated_data;
                response_params.timestamp = timestamp_res;
                ec = server_decryptor.encryptResponse(response_data, response_params, response);
                ccstAssertEqual(ec, EC_Ok);
                ccstAssertFalse(response.body.empty());
                ccstAssertFalse(response.mac.empty());
                ccstAssertTrue(response.key.empty());
                ccstAssertFalse(response.nonce.empty());
                // Keep internal values for test-data generator
                auto response_iv = client_encryptor.envelopeKey().deriveIvForNonce(response.nonce).base64String();
                
                cc7::ByteArray client_received_data;
                ec = client_encryptor.decryptResponse(response, response_params, client_received_data);
                ccstAssertEqual(ec, EC_Ok);
                
                ccstAssertEqual(cc7::CopyToString(response_data), cc7::CopyToString(client_received_data));
                
                TLOG("      {");
                TLOG("         \"input\": {");
                TLOG("            \"request.plainText\" : \"%s\",", request_data.base64String().c_str());
                TLOG("            \"response.plainText\" : \"%s\",", response_data.base64String().c_str());
                TLOG("            \"sharedInfo1\" : \"%s\",", shared_info1.base64String().c_str());
                TLOG("            \"sharedInfo2\" : \"%s\",", shared_info2.base64String().c_str());
                TLOG("            \"associatedData\" : \"%s\"", associated_data.base64String().c_str());
                TLOG("         },");
                TLOG("         \"output\": {");
                TLOG("            \"request\" : {");
                TLOG("                 \"key\" : \"%s\",", request.key.base64String().c_str());
                TLOG("                 \"mac\" : \"%s\",", request.mac.base64String().c_str());
                TLOG("                 \"data\": \"%s\",", request.body.base64String().c_str());
                TLOG("                 \"nonce\" : \"%s\",", request.nonce.base64String().c_str());
                TLOG("                 \"timestamp\" : %s", std::to_string(timestamp_req).c_str());
                TLOG("            },");
                TLOG("            \"response\" : {");
                TLOG("                 \"data\": \"%s\",", response.body.base64String().c_str());
                TLOG("                 \"mac\" : \"%s\",", response.mac.base64String().c_str());
                TLOG("                 \"nonce\" : \"%s\",", response.nonce.base64String().c_str());
                TLOG("                 \"timestamp\" : %s", std::to_string(timestamp_res).c_str());
                TLOG("            },");
                TLOG("            \"internals\" : {");
                TLOG("                 \"k_enc\" : \"%s\",", k_enc.c_str());
                TLOG("                 \"k_mac\" : \"%s\",", k_mac.c_str());
                TLOG("                 \"k_iv\" : \"%s\",", k_iv.c_str());
                TLOG("                 \"request_iv\" : \"%s\",", request_iv.c_str());
                TLOG("                 \"response_iv\" : \"%s\"", response_iv.c_str());
                TLOG("            }");
                TLOG("         }");
                TLOG("      },");
            }
            TLOG("   ]");
            TLOG("}");
        }
        
        void testInvalidCurve()
        {
            auto invalid_public_key = cc7::FromHexString("02B70BF043C144935756F8F4578C369CF960EE510A5A0F90E93A373A21F0D1397F");
            auto encryptor = ECIESEncryptor(invalid_public_key, cc7::ByteRange(), cc7::ByteRange());        
            ECIESCryptogram cryptogram;
            auto code = encryptor.encryptRequest(cc7::MakeRange("should not be encrypted"), ECIESParameters(), cryptogram);
            ccstAssertTrue(code == EC_Encryption);
        }
    };
    
    CC7_CREATE_UNIT_TEST(pa2ECIESTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
