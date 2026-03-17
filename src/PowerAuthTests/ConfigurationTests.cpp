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
#include <PowerAuth/Session.h>
#include <cc7/CC7.h>
#include <cc7/utils/DataWriter.h>
#include <cc7/detail/StringUtils.h>
#include <cc7/json/Json.h>

using namespace cc7;
using namespace cc7::tests;
using namespace cc7::crypto;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class ConfigurationTests : public UnitTest
{
public:
    
    ConfigurationTests()
    {
        CC7_REGISTER_TEST_METHOD(testBuilder)
        CC7_REGISTER_TEST_METHOD(testGeneratedVectors)
        //CC7_REGISTER_TEST_METHOD(testVectorsForBE)
        //CC7_REGISTER_TEST_METHOD(testVectorsForFE)
    }
    
    void testBuilder()
    {
        testBuilderWithConfig(0);
        testBuilderWithConfig(1);
        testBuilderWithConfig(2);
        testBuilderWithConfig(3);
    }
    
    void testBuilderWithConfig(int step)
    {
        auto data = buildConfig(0, true);
        auto builder = Configuration::Builder(data["config"].asString())
            .withDeviceSpecificData(MakeRange("specific-data"));
        auto config = builder.build();
        ccstAssertEqual("default", config->instanceId());
        ccstAssertEqual(PowerAuthSpec::EC_P384_ML_L3, config->algorithm());
        ccstAssertEqual(data["app_key"].asString(),                         config->applicationKey());
        ccstAssertEqual(data["app_secret"].asString(),                      config->applicationSecret());
        ccstAssertEqual(cc7::Base64::decode(data["app_key"].asString()),    config->applicationKeyBytes());
        ccstAssertEqual(cc7::Base64::decode(data["app_secret"].asString()), config->applicationSecretBytes());
        ccstAssertEqual(cc7::Base64::decode(data["p256_key"].asString()),   config->p256MasterServerPublicKey());
        ccstAssertEqual(cc7::Base64::decode(data["p384_key"].asString()),   config->p384MasterServerPublicKey());
        ccstAssertEqual(cc7::Base64::decode(data["mldsa65_key"].asString()),config->mldsa65MasterServerPublicKey());
        ccstAssertEqual(cc7::Base64::decode(data["mldsa87_key"].asString()),config->mldsa87MasterServerPublicKey());
        
        // Other builder params
        config = Configuration::Builder(data["config"].asString())
            .withInstanceId("instance-id")
            .withDeviceSpecificData(MakeRange("device-specific"))
            .build();
        ccstAssertEqual("instance-id", config->instanceId());
        ccstAssertEqual(MakeRange("device-specific"), config->deviceSpecificData());
        
        config = Configuration::Builder(data["config"].asString(), PowerAuthSpec::EC_P384)
            .withInstanceId("instance4")
            .withDeviceSpecificData(MakeRange("device-specific-data"))
            .build();
        ccstAssertEqual("instance4", config->instanceId());
        ccstAssertEqual(MakeRange("device-specific-data"), config->deviceSpecificData());
        ccstAssertEqual(PowerAuthSpec::EC_P384, config->algorithm());
        
        // Wrong params
        ccstMustThrow(Exception, Configuration::Builder(data["config"].asString())
            .withInstanceId("")
            .withDeviceSpecificData(MakeRange("device-specific-data"))
            .build());
        ccstMustThrow(Exception, Configuration::Builder(data["config"].asString(), PowerAuthSpec::EC_P384)
            .withDeviceSpecificData(ByteRange())
            .build());
    }
            
    void testGeneratedVectors()
    {
        // To regenerate the following file, uncomment CC7_REGISTER_TEST_METHOD(testVectorsForFE)
        // in the test class constructor.
        auto root = JSON_ParseFile(g_pa2Files, "pa2/session-setup-v4.json");
        auto&& data = root.arrayAtPath("data");
        for (const auto& item : data) {
            auto sdk_config = item.stringAtPath("config");
            auto success = item.booleanAtPath("success");
            auto comment = item.stringAtPath("info");
            auto algorithm = PowerAuthSpec::specForAlgorithmName(item["algorithm"].asString())->algorithm();
            ccstMessage("%s", comment.c_str());
            if (success) {
                
                Configuration::Builder(sdk_config, algorithm)
                    .withDeviceSpecificData(MakeRange("data"))
                    .build();
            } else {
                ccstMustThrow(Exception, Configuration::Builder(sdk_config, algorithm)
                              .withDeviceSpecificData(MakeRange("data"))
                              .build());
            }
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
        auto writer = cc7::utils::DataWriter();
        for (size_t i = 0; i < sizeof(data)/sizeof(size_t); i++) {
            writer.writeCount(data[i]);
        }
        //printf("Test data: %s\n", writer.serializedData().base64String().c_str());
        ccstAssertEqual("AAF/gICA/4EAgQG//8AAQADAAP//wAEAAMD////BAAAAwQIDBNAgMED/////", writer.serializedData().base64String())
    }
    
    // Test function must be enabled in constructor.
    void testVectorsForFE()
    {
        auto testData = json::JsonValue::array();
        auto& array = testData.asMutableArray();
        // valid
        for (int step = 0; step <= 10; step++) {
            array.push_back(buildConfig(step));
        }
        // invalid
        for (int step = 20; step <= 34; step++) {
            array.push_back(buildConfig(step));
        }
        auto object = json::JsonValue::object();
        object["description"] = json::JsonValue("Test vectors for application configuration string");
        object["data"] = testData;
        object.debugDump();
    }

    // Broken step:
    //  0 - Valid V4
    //  1,2,3 - OK but different order
    //  5 - Valid V3
    //  6 - V3 with unknown key
    //  7 - V3 same as 6, different order
    //  8 - L5 without L3 key
    //  9 - L3 without L5 key
    //  10 - P384 only
    //
    // --- all tests below should fail ---
    //
    //  20 - Bad version
    //  21 - App key too long
    //  22 - App key too short
    //  23 - App key incomplete
    //  24 - App secret too long
    //  25 - App secret too short
    //  26 - App secret incomplete
    //  27 - no keys
    //  28 - P256 missing
    //  29 - P256 only
    //  30 - P256 incomplete
    //  31 - P384 missing
    //  32 - MLDSA65 missing
    //  33 - MLDSA87 missing
    //  34 - P256 triple

    
    cc7::json::JsonValue buildConfig(int broken_step, bool out_params = false) {
        
        std::string info;
        PowerAuthSpec::Algorithm algorithm = PowerAuthSpec::EC_P384_ML_L3;
        cc7::byte version = 0x01;
        size_t app_key_len = 16;
        size_t app_sec_len = 16;
        auto app_key = cc7::crypto::GetRandomData(app_key_len);
        auto app_sec = cc7::crypto::GetRandomData(app_sec_len);
        
        cc7::byte      p256_key_id  = 0x01;
        cc7::ByteArray p256_key     = algorithms().v3.p256().generateKeyPair()->getPublicKey().exportKey(KEY_FORMAT_X963);
        size_t         p256_key_len = p256_key.size();
        cc7::byte      p384_key_id  = 0x02;
        cc7::ByteArray p384_key     = algorithms().v4.p384().generateKeyPair()->getPublicKey().exportKey(KEY_FORMAT_X963);
        cc7::byte      mldsa65_key_id = 0x03;
        cc7::ByteArray mldsa65_key    = algorithms().v4.mldsa65key().generateKeyPair()->getPublicKey().exportKey();
        cc7::byte      mldsa87_key_id = 0x04;
        cc7::ByteArray mldsa87_key    = algorithms().v4.mldsa87key().generateKeyPair()->getPublicKey().exportKey();
        cc7::byte      other_key_id = 0x05; // simulate other key id, not supported by this SDK. Must be ignored
        cc7::ByteArray other_key    = cc7::crypto::GetRandomData(48);
        
        std::vector<cc7::byte> keys_order { p384_key_id, mldsa65_key_id, mldsa87_key_id, p256_key_id };

        cc7::ByteArray additional_data;
        
        switch (broken_step) {
            case 0:
                info = "validV4";
                break;
            case 1:
                info = "validV4 - different order 1";
                keys_order = { mldsa87_key_id, mldsa65_key_id, p256_key_id, p384_key_id };
                break;
            case 2:
                info = "validV4 - different order 2";
                keys_order = { mldsa65_key_id, p384_key_id, p256_key_id, mldsa87_key_id };
                break;
            case 3:
                info = "validV4 - different order 3";
                keys_order = { p256_key_id, p384_key_id, mldsa87_key_id, mldsa65_key_id };
                break;
            case 4:
                info = "validV4 - unknown key";
                keys_order.push_back(other_key_id);
                break;
            case 5:
                info = "validV3";
                algorithm = PowerAuthSpec::LEGACY_P256;
                keys_order = { p256_key_id };
                break;
            case 6:
                info = "validV3 - unknown key";
                algorithm = PowerAuthSpec::LEGACY_P256;
                keys_order = { p256_key_id, other_key_id };
                break;
            case 7:
                info = "validV3 - different order";
                algorithm = PowerAuthSpec::LEGACY_P256;
                keys_order = { other_key_id, p256_key_id };
                break;
            case 8:
                info = "validV4 - L5 without L3";
                algorithm = PowerAuthSpec::EC_P384_ML_L5;
                keys_order = { p256_key_id, p384_key_id, mldsa87_key_id };
                break;
            case 9:
                info = "validV4 - L3 without L5";
                algorithm = PowerAuthSpec::EC_P384_ML_L3;
                keys_order = { p256_key_id, p384_key_id, mldsa65_key_id };
                break;
            case 10:
                info = "validV4 - P384 only";
                algorithm = PowerAuthSpec::EC_P384;
                keys_order = { p256_key_id, p384_key_id };
                break;
                
            case 20:
                info = "Bad version";
                version = 0x02;
                break;
            case 21:
                info = "App key too long";
                app_key.push_back(0xee);
                app_key_len++;
                break;
            case 22:
                info = "App key too short";
                app_key.pop_back();
                app_key_len--;
                break;
            case 23:
                info = "App key incomplete";
                app_key.pop_back();
                break;
            case 24:
                info = "App secret too long";
                app_sec.push_back(0xee);
                app_sec_len++;
                break;
            case 25:
                info = "App secret too short";
                app_sec.pop_back();
                app_sec_len--;
                break;
            case 26:
                info = "App secret incomplete";
                app_sec.pop_back();
                break;
            case 27:
                info = "no keys";
                keys_order.clear();
                break;
            case 28:
                info = "P256 missing";
                keys_order = { mldsa65_key_id, mldsa87_key_id, p384_key_id };
                break;
            case 29:
                info = "P256 only";
                keys_order = { p256_key_id };
                break;
            case 30:
                info = "P256 incomplete";
                p256_key.pop_back();
                break;
            case 31:
                info = "P384 missing";
                keys_order = { mldsa65_key_id, mldsa87_key_id, p256_key_id };
                break;
            case 32:
                info = "MLDSA65 missing";
                keys_order = { p384_key_id, mldsa87_key_id, p256_key_id };
                break;
            case 33:
                info = "MLDSA87 missing";
                algorithm = PowerAuthSpec::EC_P384_ML_L5;
                keys_order = { p384_key_id, mldsa65_key_id, p256_key_id };
                break;
            case 34:
                info = "P256 triple";
                keys_order = { p256_key_id, p256_key_id, p256_key_id };
                break;
            default:
                break;
        }
        auto writer = cc7::utils::DataWriter();
        do {
            writer.writeByte(version);
            writer.writeCount(app_key_len);
            writer.writeMemory(app_key);
            if (broken_step == 14) break;
            writer.writeCount(app_sec_len);
            writer.writeMemory(app_sec);
            if (broken_step == 17) break;
            writer.writeCount(keys_order.size());
            for (auto key_id : keys_order) {
                writer.writeByte(key_id);
                if (key_id == p256_key_id) {
                    writer.writeCount(p256_key_len);
                    writer.writeMemory(p256_key);
                } else if (key_id == p384_key_id) {
                    writer.writeData(p384_key);
                } else if (key_id == mldsa65_key_id) {
                    writer.writeData(mldsa65_key);
                } else if (key_id == mldsa87_key_id) {
                    writer.writeData(mldsa87_key);
                } else if (key_id == other_key_id) {
                    writer.writeData(other_key);
                }
            }
            writer.writeMemory(additional_data);
        } while(false);
        
        auto obj = json::JsonValue::object();
        obj["info"]     = json::JsonValue(info);
        obj["success"]  = json::JsonValue(broken_step < 20);
        obj["config"]   = json::JsonValue(writer.serializedData().base64String());
        obj["algorithm"] = json::JsonValue(PowerAuthSpec::specForAlgorithm(algorithm)->algorithmName());
        if (out_params) {
            obj["app_key"] = json::JsonValue(app_key.base64());
            obj["app_secret"] = json::JsonValue(app_sec.base64());
            obj["p256_key"] = json::JsonValue(p256_key.base64());
            obj["p384_key"] = json::JsonValue(p384_key.base64());
            obj["mldsa65_key"] = json::JsonValue(mldsa65_key.base64());
            obj["mldsa87_key"] = json::JsonValue(mldsa87_key.base64());
        }
        return obj;
    }
};

CC7_CREATE_UNIT_TEST(ConfigurationTests, "pa2")

} // namespace powerAuthTests
