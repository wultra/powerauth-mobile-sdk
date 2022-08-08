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
#include <cc7/HexString.h>
#include "crypto/CryptoUtils.h"
#include "crypto/PKCS7Padding.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2CryptoAESTests : public UnitTest
    {
    public:
        
        pa2CryptoAESTests()
        {
            CC7_REGISTER_TEST_METHOD(testWithPaddings)
            CC7_REGISTER_TEST_METHOD(testWithoutPaddings)
        }
        
        // unit tests
        
        struct TestData
        {
            const char * plain;
            const char * key;
            const char * iv;
            const char * enc;
        };

        void testWithPaddings()
        {
            static const TestData vectors[] =
            {
                {
                    "",
                    "be0d465f8004d636d90e3f9f6a9063d2",
                    "748869ca52f219b4764c9ae986fa821b",
                    "790511b7776b98be3d0a4861b7f1c8bb"
                },
                {
                    "f6cee5ff28fd",
                    "ac5800ac3cb59c7c14f36019e43b44fe",
                    "f013ce1ec901b5b60a85a986b3b72eba",
                    "e8a846fd9718507371604504d4ca1ac7",
                },
                {   "76cdfdf52a9753",
                    "24c4328aeffc0ca354a3215a3da23a38",
                    "c43c6269bb8c1dbba3bc22b7ba7e24b1",
                    "009e935f3fe4d57b57fc3127a8873d8c",
                },
                {
                    "b103c928531d8875",
                    "4035227440a779dbd1ed75c6ae78cef5",
                    "8faff161a5ec06e051066a571d1729d9",
                    "b3d8df2c3147b0752a7e6bbbcc9d5758",
                },
                {
                    "590b10224087872724",
                    "507008732ea559915e5e45d9710e3ed2",
                    "342b22c1cbf1c92b8e63a38de99ffb09",
                    "c11a034ed324aeae9cd5857ae4cd776f",
                },
                {
                    "ccecfa22708b6d06439c",
                    "a060441b1b7cc2af405be4f6f5c58e22",
                    "429d3240207e77e9b9dade05426fe3cb",
                    "b61ff0a956b420347daa25bb76964b51",
                },
                {   "8ff539940bae985f2f88f3",
                    "721888e260b8925fe51183b88d65fb17",
                    "5308c58068cbc05a5461a43bf744b61e",
                    "3ee8bdb21b00e0103ccbf9afb9b5bd9a",
                },
                {
                    "4c84974b5b2109d5bc90e1f0",
                    "80ba985c93763f99ff4be6cdee6ab977",
                    "ca8e99719be2e842e81bf15c606bb916",
                    "3e087f92a998ad531e0ff8e996098382",
                },
                {
                    "13eb26baf2b688574cadac6dba",
                    "1fe107d14dd8b152580f3dea8591fc3b",
                    "7b6070a896d41d227cc0cebbd92d797e",
                    "a4bfd6586344bcdef94f09d871ca8a16",
                },
                {
                    "5fcb46a197ddf80a40f94dc21531",
                    "4d3dae5d9e19950f278b0dd4314e3768",
                    "80190b58666f15dbaf892cf0bceb2a50",
                    "2b166eae7a2edfea7a482e5f7377069e",
                },
                {
                    "6842455a2992c2e5193056a5524075",
                    "0784fa652e733cb699f250b0df2c4b41",
                    "106519760fb3ef97e1ccea073b27122d",
                    "56a8e0c3ee3315f913693c0ca781e917",
                },
                {
                    "c9a44f6f75e98ddbca7332167f5c45e3",
                    "04952c3fcf497a4d449c41e8730c5d9a",
                    "53549bf7d5553b727458c1abaf0ba167",
                    "7fa290322ca7a1a04b61a1147ff20fe66fde58510a1d0289d11c0ddf6f4decfd",
                },
                {
                    "1ba93ee6f83752df47909585b3f28e56693f89e169d3093eee85175ea3a46cd3",
                    "2ae7081caebe54909820620a44a60a0f",
                    "fc5e783fbe7be12f58b1f025d82ada50",
                    "7944957a99e473e2c07eb496a83ec4e55db2fb44ebdd42bb611e0def29b23a73ac37eb0f4f5d86f090f3ddce3980425a",
                },
                {
                    "0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d",
                    "898be9cc5004ed0fa6e117c9a3099d31",
                    "9dea7621945988f96491083849b068df",
                    "e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34",
                },
                
                { nullptr, nullptr, nullptr, nullptr }
            };
            
            const TestData * td = vectors;
            while (td->plain) {
                cc7::ByteArray plain = cc7::FromHexString(td->plain);
                cc7::ByteArray key   = cc7::FromHexString(td->key);
                cc7::ByteArray iv    = cc7::FromHexString(td->iv);
                cc7::ByteArray enc   = cc7::FromHexString(td->enc);
                
                cc7::ByteArray ourENC = crypto::AES_CBC_Encrypt_Padding(key, iv, plain);
                cc7::ByteArray ourDEC = crypto::AES_CBC_Decrypt_Padding(key, iv, enc);
                
                bool encrypted_eqal = ourENC == enc;
                bool decrypted_eqal = ourDEC == plain;
                ccstAssertTrue(encrypted_eqal, "Failed at plain %s", td->plain);
                ccstAssertTrue(decrypted_eqal, "Failed at plain %s", td->plain);
                td++;
            }
        }
        
        
        void testWithoutPaddings()
        {
            static const TestData vectors[] =
            {
                {
                    "6BC1BEE22E409F96E93D7E117393172A",     // plain
                    "2B7E151628AED2A6ABF7158809CF4F3C",     // key
                    "000102030405060708090A0B0C0D0E0F",     // iv
                    "7649ABAC8119B246CEE98E9B12E9197D",     // ct
                },
                {
                    "AE2D8A571E03AC9C9EB76FAC45AF8E51",     // plain
                    "2B7E151628AED2A6ABF7158809CF4F3C",     // key
                    "7649ABAC8119B246CEE98E9B12E9197D",     // iv
                    "5086CB9B507219EE95DB113A917678B2",     // ct
                },
                {
                    "30C81C46A35CE411E5FBC1191A0A52EF",     // plain
                    "2B7E151628AED2A6ABF7158809CF4F3C",     // key
                    "5086CB9B507219EE95DB113A917678B2",     // iv
                    "73BED6B8E3C1743B7116E69E22229516",     // ct
                },
                {
                    "F69F2445DF4F9B17AD2B417BE66C3710",     // plain
                    "2B7E151628AED2A6ABF7158809CF4F3C",     // key
                    "73BED6B8E3C1743B7116E69E22229516",     // iv
                    "3FF1CAA1681FAC09120ECA307586E1A7",     // ct
                },
                { nullptr, nullptr, nullptr, nullptr }
            };
            
            const TestData * td = vectors;
            while (td->plain) {
                cc7::ByteArray plain = cc7::FromHexString(td->plain);
                cc7::ByteArray key   = cc7::FromHexString(td->key);
                cc7::ByteArray iv    = cc7::FromHexString(td->iv);
                cc7::ByteArray enc   = cc7::FromHexString(td->enc);
                
                cc7::ByteArray ourENC = crypto::AES_CBC_Encrypt(key, iv, plain);
                cc7::ByteArray ourDEC = crypto::AES_CBC_Decrypt(key, iv, enc);
                
                bool encrypted_eqal = ourENC == enc;
                bool decrypted_eqal = ourDEC == plain;
                ccstAssertTrue(encrypted_eqal, "Failed at plain %s", td->plain);
                ccstAssertTrue(decrypted_eqal, "Failed at plain %s", td->plain);
                td++;
            }
        }

        
    };
    
    CC7_CREATE_UNIT_TEST(pa2CryptoAESTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
