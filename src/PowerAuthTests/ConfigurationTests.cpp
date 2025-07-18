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
        auto data = buildConfig("success", 0, true);
        auto builder = Configuration::Builder(data["config"].asString())
            .withDeviceSpecificData(MakeRange("specific-data"));
        auto config = builder.build();
        ccstAssertEqual("default", config->instanceId());
        ccstAssertEqual(PowerAuthSpec::EC_P384_ML_L3, config->algorithm());
        ccstAssertEqual(data["app_key"].asString(),                         config->applicationKey());
        ccstAssertEqual(data["app_secret"].asString(),                      config->applicationSecret());
        ccstAssertEqual(cc7::Base64::decode(data["app_key"].asString()),    config->applicationKeyBytes());
        ccstAssertEqual(cc7::Base64::decode(data["app_secret"].asString()), config->applicationSecretBytes());
        ccstAssertEqual(cc7::Base64::decode(data["p256_key"].asString()),   config->legacyMasterServerPublicKey());
        ccstAssertEqual(cc7::Base64::decode(data["p384_key"].asString()),   config->ecdsaMasterServerPublicKey());
        ccstAssertEqual(cc7::Base64::decode(data["mldsa_key"].asString()),  config->mldsaMasterServerPublicKey());
        
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
        auto root = JSON_ParseFile(g_pa2Files, "pa2/session-setup-v4.json");
        auto&& data = root.arrayAtPath("data");
        for (const auto& item : data) {
            auto sdk_config = item.stringAtPath("config");
            auto success = item.booleanAtPath("success");
            auto comment = item.stringAtPath("info");
            auto protocol = item["protocol"].asInteger() == 4 ? PowerAuthSpec::EC_P384_ML_L3 : PowerAuthSpec::LEGACY_P256;
            if (success) {
                
                Configuration::Builder(sdk_config, protocol)
                    .withDeviceSpecificData(MakeRange("data"))
                    .build();
            } else {
                ccstMustThrow(Exception, Configuration::Builder(sdk_config)
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
        array.push_back(buildConfig("validV4", 0));
        array.push_back(buildConfig("validV4 - different order 1", 1));
        array.push_back(buildConfig("validV4 - different order 2", 2));
        array.push_back(buildConfig("validV4 - different order 3", 3));
        array.push_back(buildConfig("validV4 - unknown key",       4));
        array.push_back(buildConfig("validV3",                     5));
        array.push_back(buildConfig("validV3 - unknown key",       6));
        array.push_back(buildConfig("validV3 - different order",   7));
        // broken
        array.push_back(buildConfig("badVersion       ", 11));
        array.push_back(buildConfig("appKeyTooLong    ", 12));
        array.push_back(buildConfig("appKeyTooShort   ", 13));
        array.push_back(buildConfig("appKeyIncomplete ", 14));
        array.push_back(buildConfig("appSecTooLong    ", 15));
        array.push_back(buildConfig("appSecTooShort   ", 16));
        array.push_back(buildConfig("appSecIncomplete ", 17));
        array.push_back(buildConfig("noKeys           ", 18));
        array.push_back(buildConfig("p256Missing      ", 19));
        array.push_back(buildConfig("p256Only         ", 20));
        array.push_back(buildConfig("p256Incomplete   ", 21));
        array.push_back(buildConfig("p384Missing      ", 22));
        array.push_back(buildConfig("mldsaMissing     ", 23));
        array.push_back(buildConfig("p256triple       ", 24));
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
    //  20 - P256 only
    //  21 - P256 incomplete
    //  22 - P384 missing
    //  23 - MLDSA65 missing
    //  24 - P256 triple

    
    cc7::json::JsonValue buildConfig(const std::string& comment, int broken_step, bool out_params = false) {
        
        int64_t proto_version = 4;
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
        cc7::byte      mldsa_key_id = 0x03;
        cc7::ByteArray mldsa_key    = algorithms().v4.mldsa65key().generateKeyPair()->getPublicKey().exportKey();
        cc7::byte      other_key_id = 0x04; // simulate other key id, not supported by this SDK. Must be ignored
        cc7::ByteArray other_key    = cc7::crypto::GetRandomData(48);
        
        std::vector<cc7::byte> keys_order { p384_key_id, mldsa_key_id, p256_key_id };

        cc7::ByteArray additional_data;
        
        switch (broken_step) {
            case 0:
                break;
            case 1:
                keys_order = { mldsa_key_id, p256_key_id, p384_key_id };
                break;
            case 2:
                keys_order = { mldsa_key_id, p384_key_id, p256_key_id };
                break;
            case 3:
                keys_order = { p256_key_id, p384_key_id, mldsa_key_id };
                break;
            case 4:
                keys_order.push_back(other_key_id);
                break;
            case 5:
                proto_version = 3;
                keys_order = { p256_key_id };
                break;
            case 6:
                proto_version = 3;
                keys_order = { p256_key_id, other_key_id };
                break;
            case 7:
                proto_version = 3;
                keys_order = { other_key_id, p256_key_id };
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
                keys_order.clear();
                break;
            case 19:
                //  19 - P256 missing
                keys_order = { mldsa_key_id, p384_key_id };
                break;
            case 20:
                //  20 - P256 only
                keys_order = { p256_key_id };
                break;
            case 21:
                //  21 - P256 incomplete
                p256_key.pop_back();
                break;
            case 22:
                //  22 - P384 missing
                keys_order = { mldsa_key_id, p256_key_id };
                break;
            case 23:
                //  23 - MLDSA65 missing
                keys_order = { p384_key_id, p256_key_id };
                break;
            case 24:
                //  23 - P256 triple
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
                } else if (key_id == mldsa_key_id) {
                    writer.writeData(mldsa_key);
                } else if (key_id == other_key_id) {
                    writer.writeData(other_key);
                }
            }
            writer.writeMemory(additional_data);
        } while(false);
        
        auto obj = json::JsonValue::object();
        obj["info"]     = json::JsonValue(comment);
        obj["success"]  = json::JsonValue(broken_step < 11);
        obj["config"]   = json::JsonValue(writer.serializedData().base64String());
        obj["protocol"] = json::JsonValue(proto_version);
        if (out_params) {
            obj["app_key"] = json::JsonValue(app_key.base64());
            obj["app_secret"] = json::JsonValue(app_sec.base64());
            obj["p256_key"] = json::JsonValue(p256_key.base64());
            obj["p384_key"] = json::JsonValue(p384_key.base64());
            obj["mldsa_key"] = json::JsonValue(mldsa_key.base64());
        }
        return obj;
    }
};

CC7_CREATE_UNIT_TEST(ConfigurationTests, "pa2")

} // namespace powerAuthTests
