/*
 * Copyright 2023 Wultra s.r.o.
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

#include <PowerAuth/PowerAuth.h>
#include <cc7/CC7.h>

#include "../PowerAuth/utils/DataWriter.h"
#include "../PowerAuth/crypto/PRNG.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    class pa2SessionSetupTests : public UnitTest
    {
    public:
        
        pa2SessionSetupTests()
        {
            CC7_REGISTER_TEST_METHOD(testSimplifiedConfiguration)
            CC7_REGISTER_TEST_METHOD(testGeneratedVectors)
            //CC7_REGISTER_TEST_METHOD(testVectorsForBE)
            //CC7_REGISTER_TEST_METHOD(testVectorsForFE)
        }
        
        void testSimplifiedConfiguration()
        {
            auto config = "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==";
            SessionSetup setup;
            auto result = setup.loadFromConfiguration(config);
            ccstAssertTrue(result);
            ccstAssertEqual("w4+hAeogFLTZjcSjPwbG2g==", setup.applicationKey);
            ccstAssertEqual("Szls/7JWbKN+FAOijHcsPA==", setup.applicationSecret);
            ccstAssertEqual("BEEOwljSgItBIAnzr3f7K36s+KKoUzC8LE+K+7Dy0X6iAkcPXAjLP1KKPxdqyM/iihHAcW5x/WzJPCbtytcJo2w=", setup.masterServerPublicKey);
            
            auto generated = setup.saveConfiguration();
            ccstAssertEqual(config, generated);
        }
        
        void testGeneratedVectors()
        {
            // SessionSetup test vectors for SDK
            // [ 1 ] VALID CONFIGS
            const char * validConfigs[] = {
               /* validV3 */ "ARCerSCymKwmdXXakCxpvGpHEBSiMV5W2w/mCR3vLm3IM0sBAUGwfOPQqq6lO0ZXPzh/zwlIKnJ3wW1eM2rXk+WF/5U91oNrQCFr4DUtc+BdaN/sagyN12Gm8s5VKkahsOuzIjOt5Q==",
               /* validV4 */ "ARBR33RUAsQ38ndQYmtJZmodEDmzLdrLNLkhjajpUBwaxYYCIEFQoJW4sLvDAp3DOzSvJb9q6YG0jzSG1mfNDGzW9+70vcsCZon+cYcN8bIZ3sXHfLmcRumie+wA8hFe5/RVkCqq7QFBHF507ViMB9o2GdDm+DEGvJY2PP6z+bHS/SOWPIvb1RwGjksD1rFSYWqlA5hM8PY2VnevJ3vJAHm32TdCQbfyI6g=",
               NULL
            };
            // [ 2 ] INVALID CONFIGS
            const char * invalidConfigs[] = {
               /* badVersion       */ "AhBQnJ1yWytWB13ARL3AqSxEEPBBidKT92P07ABl9u+UBNcBAUHu6k/wJH8c/qbczBbreF6Gui6X0gyOZYugN77sOCaDXN8r4q6MnsxNb31Xy95ZTrZrPSxEVR77oBJGhus9T9XG0w==",
               /* appKeyTooLong    */ "ARG2IueSajHNVygx6z42bHEE7hDpI+naUifMSpBF4IAUu9NEAQFB+giPcnJr4ZDPocgEtNLHzh4Z9L1XhCrmUzBjKNliDPqycwllAdwy2K1y+2mvYLgtlzNpGXbAzV1eQkruCE5wOQw=",
               /* appKeyTooShort   */ "AQ9MKVSquvEs7PFEoiLe9QAQIyCEpjnnw+JoAdEpqRAKBgEBQRIuf1EegLTc+6I7tjWZT/Kno6+PbX0w+GA8a1XERHbR2QSOIsoVhLHTUKn9cFWWYtOvXmXTjWzhbOojFEILzlLI",
               /* appKeyIncomplete */ "ARCEuVTbQw3ESdve/M/K9W0=",
               /* appSecTooLong    */ "ARCuz73FKX3tC4fOtPSoNGN6EfFcGuES+0e74QmfC/A9e/7uAQFBih2QT11pTEBvfAWDVcCg3cLDGK4JKP2XIb23WW2Zqo1r+9pPpG3RWER50M7iHjmjNhL2JNl1UORjFA9qoua23oo=",
               /* appSecTooShort   */ "ARA0Bo5m7wqALKWT/YfGg2jgD+47wy2aDInhst2BNv5sAwEBQd1Ry6YtFCaA6dyOR/BMkUigHIBdYoSLgT5ncIUJMJDYI/CGRGQq/4TSdtRKV8K69hWx/K125GjPYJnQnTVn7/G+",
               /* appSecIncomplete */ "ARAjrzYiRGpMWNm60rTEMSl9ECCqHMjRfeTvSWwnOZ+6yQ==",
               /* noKeys           */ "ARDBboKaM9dnPiYR9PEvYHNMEEe0apJ3QQijoU/Wairll6EA",
               /* p256Missing      */ "ARB7Qu2aH82o+LFF88cIDZClEBAZwMgStK1EXjub7mUQJKIBIEEkiSrBgaTZmn4H8p0NEXwmhfZrmwnHUwoaaAaSsAmoBEa1W69As59VISJMREMLUNFXdUdZALEHR1mjKDlNnVuR4g==",
               /* p256Incomplete   */ "ARAqPe4+Jnc0qpoZ96akrJWvEGVD2W4BgMYCLqN0+py/Qa0BAUHYLlvVDSRWspVFPVLOei+VVmWg34hZr4ibQgDghxG8WPUBqvseDZJUmrCuEWK41AIUwc6PAV1FB86NVFZCg+3F",
               NULL
            };
            const char ** p = validConfigs;
            while (const char * cfg = *p++) {
                SessionSetup setup;
                ccstAssertTrue(setup.loadFromConfiguration(cfg));
            }
            p = invalidConfigs;
            while (const char * cfg = *p++) {
                SessionSetup setup;
                ccstAssertFalse(setup.loadFromConfiguration(cfg));
            }
        }
        
        // Test function must be enabled in constructor.
        void testVectorsForBE()
        {
            // Generate test vector that validates server's count serialization.
            size_t data[] = {
                0,
                1,
                0x7F,
                0x80,
                0xFF,
                0x100,
                0x101,
                0x3FFF,
                0x4000,
                0xFFFF,
                0x10000,
                0xFFFFFF,
                0x1000000,
                0x1020304,
                0x10203040,
                0x3FFFFFFF
            };
            auto writer = powerAuth::utils::DataWriter();
            for (size_t i = 0; i < sizeof(data)/sizeof(size_t); i++) {
                writer.writeCount(data[i]);
            }
            //printf("Test data: %s\n", writer.serializedData().base64String().c_str());
            ccstAssertEqual("AAF/gICA/4EAgQG//8AAQADAAP//wAEAAMD////BAAAAwQIDBNAgMED/////", writer.serializedData().base64String())
        }
        
        // Test function must be enabled in constructor.
        void testVectorsForFE()
        {
            printf("// SessionSetup test vectors for SDK\n");
            printf("// [ 1 ] VALID CONFIGS\n");
            printf("const char * validConfigs[] = {\n");
            printf("   /* validV3 */ \"%s\",\n", buildConfig(0).c_str());
            printf("   /* validV4 */ \"%s\",\n", buildConfig(1).c_str());
            printf("   NULL\n");
            printf("};\n");
            printf("// [ 2 ] INVALID CONFIGS\n");
            printf("const char * invalidConfigs[] = {\n");
            printf("   /* badVersion       */ \"%s\",\n", buildConfig(11).c_str());
            printf("   /* appKeyTooLong    */ \"%s\",\n", buildConfig(12).c_str());
            printf("   /* appKeyTooShort   */ \"%s\",\n", buildConfig(13).c_str());
            printf("   /* appKeyIncomplete */ \"%s\",\n", buildConfig(14).c_str());
            printf("   /* appSecTooLong    */ \"%s\",\n", buildConfig(15).c_str());
            printf("   /* appSecTooShort   */ \"%s\",\n", buildConfig(16).c_str());
            printf("   /* appSecIncomplete */ \"%s\",\n", buildConfig(17).c_str());
            printf("   /* noKeys           */ \"%s\",\n", buildConfig(18).c_str());
            printf("   /* p256Missing      */ \"%s\",\n", buildConfig(19).c_str());
            printf("   /* p256Incomplete   */ \"%s\",\n", buildConfig(20).c_str());
            printf("   NULL\n");
            printf("};\n");
        }

        // Broken step:
        //  0 - OK
        //  1 - OK with next key
        //
        //  11 - Bad version
        //  12 - App key too long
        //  13 - App key too short
        //  14 - App key incomplete
        //  15 - App secret too long
        //  16 - App secret too short
        //  17 - App secret incomplete
        //  18 - no keys
        //  19 - P256 missing
        //  20 - P256 incomplete
        //  21 - include additional data (ignored)
        
        std::string buildConfig(int broken_step) {
            
            cc7::byte version = 0x01;
            size_t app_key_len = 16;
            size_t app_sec_len = 16;
            cc7::ByteArray app_key = crypto::GetRandomData(app_key_len);
            cc7::ByteArray app_sec = crypto::GetRandomData(app_sec_len);
            
            size_t include_p256_key = 1;
            size_t include_next_key = 0;
            
            cc7::byte p256_key_id    = 0x01;
            size_t p256_key_len = 65;
            cc7::ByteArray p256_key  = crypto::GetRandomData(p256_key_len);
            cc7::byte next_key_id   = 0x20;
            cc7::ByteArray next_key = crypto::GetRandomData(65);
            
            cc7::ByteArray additional_data;
            
            switch (broken_step) {
                case 0:
                    break;
                case 1:
                    include_next_key = 1;
                    break;
                case 11:
                    // Bad version
                    version = 0x02;
                    break;
                case 12:
                    // App key too long
                    app_key.push_back(0xee);
                    app_key_len++;
                    break;
                case 13:
                    // App key too short
                    app_key.pop_back();
                    app_key_len--;
                    break;
                case 14:
                    // App key incomplete
                    app_key.pop_back();
                    break;
                case 15:
                    // App secret too long
                    app_sec.push_back(0xee);
                    app_sec_len++;
                    break;
                case 16:
                    // App secret too short
                    app_sec.pop_back();
                    app_sec_len--;
                    break;
                case 17:
                    // App secret incomplete
                    app_sec.pop_back();
                    break;
                case 18:
                    // no keys
                    include_p256_key = 0;
                    break;
                case 19:
                    // p256 missing
                    include_p256_key = 0;
                    include_next_key = 1;
                    break;
                case 20:
                    // P256 incomplete
                    p256_key.pop_back();
                    break;
                default:
                    break;
            }
            auto writer = utils::DataWriter();
            do {
                writer.writeByte(version);
                writer.writeCount(app_key_len);
                writer.writeMemory(app_key);
                if (broken_step == 14) break;
                writer.writeCount(app_sec_len);
                writer.writeMemory(app_sec);
                if (broken_step == 17) break;
                writer.writeCount(include_next_key + include_p256_key);
                if (include_next_key) {
                    writer.writeByte(next_key_id);
                    writer.writeData(next_key);
                }
                if (include_p256_key) {
                    writer.writeByte(p256_key_id);
                    writer.writeCount(p256_key_len);
                    writer.writeMemory(p256_key);
                }
                writer.writeMemory(additional_data);
            } while(false);
            
            return writer.serializedData().base64String();
        }
    };

    CC7_CREATE_UNIT_TEST(pa2SessionSetupTests, "pa2")

} // io::getlime::powerAuthTests
} // io::getlime
} // io
