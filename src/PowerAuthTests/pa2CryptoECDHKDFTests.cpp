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
#include "crypto/KDF.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2CryptoECDHKDFTests : public UnitTest
    {
    public:
        
        pa2CryptoECDHKDFTests()
        {
            CC7_REGISTER_TEST_METHOD(testECDH_KDF_SHA256)
        }
        
        // unit tests
        
        struct TestData
        {
            const char * secret;
            const char * sinfo;
            const char * expected;
        };

        void testECDH_KDF_SHA256()
        {
            //
            // Source of test data: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing
            // File: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ansx963_2001.zip
            //
            static const TestData s_tests[] = {
                
                // [shared secret length = 192]
                // [SharedInfo length = 0]
                // [key data length = 128]

                {
                    "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
                    "",
                    "443024c3dae66b95e6f5670601558f71",
                },
                {
                    "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4",
                    "",
                    "b6295162a7804f5667ba9070f82fa522",
                },
                {
                    "de4ec3f6b2e9b7b5b6160acd5363c1b1f250e17ee731dbd6",
                    "",
                    "c8df626d5caaabf8a1b2a3f9061d2420",
                },
                {
                    "d38bdbe5c4fc164cdd967f63c04fe07b60cde881c246438c",
                    "",
                    "5e674db971bac20a80bad0d4514dc484",
                },
                {
                    "693937e6e8e89606df311048a59c4ab83e62c56d692e05ce",
                    "",
                    "5c3016128b7ee53a4d3b14c344b4db09",
                },
                {
                    "be91c4f176b067f465244742a9df72ca921a6acf462739a4",
                    "",
                    "41476c80696df4e87fb83e55524b89ce",
                },
                {
                    "1d5b0ad85bc7859ada93dd5ccaf9536761f3c1a49a42f642",
                    "",
                    "650192990bfcaf7366f536aa89f27dbc",
                },
                {
                    "265c33d66b341c3f5ae2497a4eff1bed1cd3e549095bb32a",
                    "",
                    "0066528a1bd57cd92bd619e60b605f1e",
                },
                {
                    "03213ad997fdd6921c9ffb440db597a5d867d9d232dd2e99",
                    "",
                    "5a00bd1c812c579507314b491e4e1dfc",
                },
                {
                    "3ede6083cd256016f820b69ea0dcd09f57cdab011a80bb6e",
                    "",
                    "026454370775578e3b4a3e09e97a67d2",
                },
                
                // [shared secret length = 192]
                // [SharedInfo length = 128]
                // [key data length = 1024]
                {
                    "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
                    "75eef81aa3041e33b80971203d2c0c52",
                    "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
                },
                {
                    "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a",
                    "d65a4812733f8cdbcdfb4b2f4c191d87",
                    "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b",
                },
                {
                    "f148942fe6acdcd55d9196f9115b78f068da9b163a380fcf",
                    "6d2748de2b48bb21fd9d1be67c0c68af",
                    "6f61dcc517aa6a563dcadeabe1741637d9a6b093b68f19eb4311e0e7cc5ce704274331526ad3e3e0c8172ff2d92f7f07463bb4043e459ad4ed9ddffb9cc8690536b07379ba4aa8204ca25ec68c0d3639362fddf6648bcd2ce9334f091bd0167b7d38c771f632596599ef61ae0a93131b76c80d34e4926d26659ed57db7ba7555",
                },
                {
                    "fd4413d60953a7f9358492046109f61253ceef3c0e362ba0",
                    "824d7da4bc94b95259326160bf9c73a4",
                    "1825f49839ae8238c8c51fdd19dddc46d309288545e56e29e31712fd19e91e5a3aeee277085acd7c055eb50ab028bbb9218477aeb58a5e0a130433b2124a5c3098a77434a873b43bd0fec8297057ece049430d37f8f0daa222e15287e0796434e7cf32293c14fc3a92c55a1c842b4c857dd918819c7635482225fe91a3751eba",
                },
                {
                    "f365fe5360336c30a0b865785e3162d05d834596bb4034d0",
                    "0530781d7d765d0d9a82b154eec78c3c",
                    "92227b24b58da94b2803f6e7d0a8aab27e7c90a5e09afaecf136c3bab618104a694820178870c10b2933771aab6dedc893688122fffc5378f0eb178ed03bac4bfd3d7999f97c39aed64eeadb6801206b0f75cbd70ef96ae8f7c69b4947c1808ffc9ca589047803038d6310006924b934e8f3c1a15a59d99755a9a4e528daa201",
                },
                {
                    "65989811f490718caa70d9bdca753f6c5bd44e4d7b7a0c98",
                    "264a09349830c51726ca8918ae079e4a",
                    "f5f6ef377871830807c741560a955542dcedb662784c3e87fba06bff83db0d9753b92a540e5c86acfe4a80e7657109ee3178879748d967635a0122dbf37d3158c2d214c3dcba8cc29d6292250f51a3b698280744f81040275e9a8b6ee5c9b0307db176364868deade3becc0711c1fb9028c79abad086459c3843f804db928c49",
                },
                {
                    "9d598818649fc81b8c59f60dfd41784790c971eefcff6419",
                    "435f06ac33386eaf3af9042d70b93b08",
                    "970845c707dafb8699fa26b9f6c181f358ebed337f9504b04b515c9f01db12dd4965e65e8750af575c0934527183ccbe8e243f26398906089c11bc8a8f69bedbbcf651c19c219b5bd0dc1829931cc6994d71f0000b7e42b1b994aa332b4a0bc506cde8723cd8da879826c585ae12fafb3f3daf5784007006878f4ebc4eda7db2",
                },
                {
                    "4f9c0a5c03c8c3a23f06847d0e1f86f7df8da47bf3ccde99",
                    "45672212c5af77d7eb5c90c38e125b52",
                    "80fd7658118370a7d790d708ddafe6e7a5ba22caaacbf46e73fce6d6e1516a465d8264b75b5286067ac57863949aae984dc00653bf151930b398d7f5478c7b954565c584c8ad36fe59692781f2398d71e0234cff09d3c175d86a6c7c0f1e387eda55da8300caee4173ad7ff74b2effd723defc20060fa69f92b8af858a87a4f7",
                },
                {
                    "1980d2966d59ccbbf89f7fe9a5943da886f232ac02ee69ce",
                    "c8af6665439efbbee8660701681d54ce",
                    "2120434e863d1df7b9748a3cbc73d2680ede19437a13230a9dc4ef692feb5197afd4e9275d6ed00e1ff3a0fd026dc8a2adefc90bf0e8656912849094d7a515bf45dda69e574bf33211255dd78bfc2b83434f1e0f7795d468dd09c4ed88b691b3fb9ce876161b2f26b41614ff05228b3402f0d1f3044c2c3f9f7136c7aca53356",
                },
                {
                    "0eaabe1f7ab668ccf171547d8d08f6f2e06bc5e5f32d521c",
                    "e4e98a7d346906518305de3798959070",
                    "b90a0069ad42b964e96d392e0f13c39e43203371b1eba48f7c41fbfd83df7505d564ce4bf0cf8d956d2a1e9aee6308471d22f70aedd19b24566974f54db2849a79528c9e3f5d4f93c2f6f0862311fca14a2df91635d112fbb05dcd7c0ee72a6d8e713216bc8777596244f724e4046ba134f9a811f8f504ee67b1683041690921",
                },
                // End of table
                { NULL, NULL, NULL}
            };
            
            const TestData * td = s_tests;
            while (td->secret != NULL) {
                auto secret = cc7::FromHexString(td->secret);
                auto sinfo  = cc7::FromHexString(td->sinfo);
                auto key_expected = cc7::FromHexString(td->expected);
                auto key_length = key_expected.size();
                auto key = crypto::ECDH_KDF_X9_63_SHA256(secret, sinfo, key_length);
                bool equal = key == key_expected;
                if (!equal) {
                    auto key_string = key.hexString();
                    ccstMessage("ECDH_KDF_X9_63_SHA256 derivation failed");
                    ccstMessage("  expected: %s", key_expected.hexString().c_str());
                    ccstMessage("  derived : %s", key_string.c_str());
                    ccstFailure();
                    break;
                }
                td++;
            }
            
        }


    };
    
    CC7_CREATE_UNIT_TEST(pa2CryptoECDHKDFTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io

