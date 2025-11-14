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
#include <PowerAuth/Algorithms.h>
#include <PowerAuth/SharedSecret.h>

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class SharedSecretTests : public UnitTest
{
public:
    
    SharedSecretTests()
    {
        CC7_REGISTER_TEST_METHOD(test_EC_P384)
        CC7_REGISTER_TEST_METHOD(test_EC_P384_ML_L3)
        CC7_REGISTER_TEST_METHOD(testVectorsFromServer)
        //CC7_REGISTER_TEST_METHOD(generateTestVectorsForServer)
    }
    
    void test_EC_P384()
    {
        auto algorithm = ISharedSecret::getInstance(PowerAuthSpec::EC_P384);
        for (int i = 0; i < 100; i++) {
            auto req = algorithm->generateRequestCryptogram();
            auto client_request = req.first;
            auto client_ctx = req.second;
            ccstAssertEqual("EC_P384", client_request.algorithm);
            ccstAssertEqual(1, client_request.encapsulationKeys.size());
                
            auto resp = algorithm->generateResponseCryptogram(client_request);
            auto server_response = resp.first;
            auto server_ss = resp.second;
            ccstAssertEqual(1, server_response.encapsulatedKeys.size());
            
            auto client_ss = algorithm->computeSharedSecret(client_ctx, server_response);
            ccstAssertEqual(client_ss, server_ss);
            ccstAssertEqual(32, client_ss.size());
            
            // Serialize and deserialize client context
            auto serialized_ctx = algorithm->serializeContext(client_ctx);
            auto deserialized_ctx = algorithm->deserializeContext(serialized_ctx);
            auto client_ss_2 = algorithm->computeSharedSecret(deserialized_ctx, server_response);
            ccstAssertEqual(client_ss, client_ss_2);
            
            // JSON convertors
            // request
            auto client_req_json = client_request.toJson();
            ccstAssertEqual(client_req_json["algorithm"].asString(), "EC_P384");
            ccstAssertEqual(client_req_json["encapsulationKeys"].asArray()[0].asString(), client_request.encapsulationKeys[0]);
            ccstAssertEqual(2, client_req_json.asObject().size());
            auto server_req_json = SharedSecretRequest::fromJson(client_req_json);
            ccstAssertEqual(client_request.algorithm, server_req_json.algorithm);
            ccstAssertEqual(client_request.encapsulationKeys, server_req_json.encapsulationKeys);
            // response
            auto server_res_json = server_response.toJson();
            ccstAssertEqual(server_res_json["encapsulatedKeys"].asArray()[0].asString(), server_response.encapsulatedKeys[0]);
            ccstAssertEqual(1, server_res_json.asObject().size());
            auto client_res_json = SharedSecretResponse::fromJson(server_res_json);
            ccstAssertEqual(server_response.encapsulatedKeys, client_res_json.encapsulatedKeys);
        }
    }
            
    void test_EC_P384_ML_L3()
    {
        auto algorithm = ISharedSecret::getInstance(PowerAuthSpec::EC_P384_ML_L3);
        for (int i = 0; i < 2; i++) {
            auto req = algorithm->generateRequestCryptogram();
            auto client_request = req.first;
            auto client_ctx = req.second;
            ccstAssertEqual("EC_P384_ML_L3", client_request.algorithm);
            ccstAssertEqual(2, client_request.encapsulationKeys.size());
    
            auto resp = algorithm->generateResponseCryptogram(client_request);
            auto server_response = resp.first;
            auto server_ss = resp.second;
            ccstAssertEqual(2, server_response.encapsulatedKeys.size());
            
            auto client_ss = algorithm->computeSharedSecret(client_ctx, server_response);
            ccstAssertEqual(client_ss, server_ss);
            ccstAssertEqual(32, client_ss.size());
            
            // Serialize and deserialize client context
            auto serialized_ctx = algorithm->serializeContext(client_ctx);
            auto deserialized_ctx = algorithm->deserializeContext(serialized_ctx);
            auto client_ss_2 = algorithm->computeSharedSecret(deserialized_ctx, server_response);
            ccstAssertEqual(client_ss, client_ss_2);
            
            // JSON convertors
            // request
            auto client_req_json = client_request.toJson();
            ccstAssertEqual(client_req_json["algorithm"].asString(), "EC_P384_ML_L3");
            ccstAssertEqual(client_req_json["encapsulationKeys"].asArray()[0].asString(), client_request.encapsulationKeys[0]);
            ccstAssertEqual(client_req_json["encapsulationKeys"].asArray()[1].asString(), client_request.encapsulationKeys[1]);
            ccstAssertEqual(2, client_req_json.asObject().size());
            auto server_req_json = SharedSecretRequest::fromJson(client_req_json);
            ccstAssertEqual(client_request.algorithm, server_req_json.algorithm);
            ccstAssertEqual(client_request.encapsulationKeys, server_req_json.encapsulationKeys);
            // response
            auto server_res_json = server_response.toJson();
            ccstAssertEqual(server_res_json["encapsulatedKeys"].asArray()[0].asString(), server_response.encapsulatedKeys[0]);
            ccstAssertEqual(server_res_json["encapsulatedKeys"].asArray()[1].asString(), server_response.encapsulatedKeys[1]);
            ccstAssertEqual(1, server_res_json.asObject().size());
            auto client_res_json = SharedSecretResponse::fromJson(server_res_json);
            ccstAssertEqual(server_response.encapsulatedKeys, client_res_json.encapsulatedKeys);
        }
    }
    
    void testVectorsFromServer()
    {
        auto root = JSON_ParseFile(g_pa2Files, "pa2/SharedSecret_Client_Vectors.json");
        auto&& data = root.arrayAtPath("testData");
        for (const auto& item : data) {
            auto algorithm = item.stringAtPath("algorithm");
            ccstMessage("%s", algorithm.c_str());
            auto&& vectors = item.arrayAtPath("testVectors");
            auto spec = PowerAuthSpec::specForAlgorithmName(algorithm);
            auto ss = ISharedSecret::getInstance(spec->algorithm());
            for (const auto& entry : vectors) {
                auto expected_shared_secret = entry["sharedSecret"].asBase64();
                auto ctx = ss->deserializeContext(entry["clientContext"].asBase64());
                auto response = SharedSecretResponse::fromJson(entry["response"]);
                auto shared_secret = ss->computeSharedSecret(ctx, response);
                if (expected_shared_secret != shared_secret) {
                    ccstAssertEqual(expected_shared_secret, shared_secret);
                }
            }
        }
    }
    
    void generateTestVectorsForServer()
    {
        // You must enable this test function in the constructor.
        
        auto algorithms = std::vector<PowerAuthSpec::Algorithm> {
            PowerAuthSpec::EC_P384,
            PowerAuthSpec::EC_P384_ML_L3,
            PowerAuthSpec::EC_P384_ML_L5,
            // Experimental algorithms
            PowerAuthSpec::ML_L3,
            PowerAuthSpec::ML_L5,
        };
        
        auto testData = json::JsonValue::array();
        for (auto alg_i = 0; alg_i < algorithms.size(); alg_i++) {
            auto alg = algorithms[alg_i];
            auto spec = PowerAuthSpec::specForAlgorithm(alg);
            auto secret_algorithm = ISharedSecret::getInstance(alg);
            auto alg_string = json::JsonValue(spec->algorithmName());

            auto testVectors = json::JsonValue::array();
            for (int i = 1; i <= 4; i++) {
                auto request = secret_algorithm->generateRequestCryptogram();
                auto client_request = request.first;
                auto ctx_data = secret_algorithm->serializeContext(request.second);
                auto encapsulationKeys = json::JsonValue::array();
                for (auto& key : client_request.encapsulationKeys) {
                    encapsulationKeys.pushBack(json::JsonValue(key));
                }
                testVectors.pushBack(json::JsonValue::object({
                    { "clientContext", json::JsonValue::base64(ctx_data) },
                    { "request", json::JsonValue::object({
                        { "algorithm", alg_string },
                        { "encapsulationKeys", encapsulationKeys }
                    })}
                }));
            }
            testData.pushBack(json::JsonValue::object({
                { "algorithm",   alg_string  },
                { "testVectors", testVectors }
            }));
        }
        
        auto root = json::JsonValue::object({{"testData", testData }});
        auto out = json::JsonWriter(json::JsonWriter::PrettyOutput).toString(root);
        
        fprintf(stdout, "\n%s\n", out.c_str());
        fflush(stdout);
    }
    
    void generateTestVectors()
    {
    }
};

CC7_CREATE_UNIT_TEST(SharedSecretTests, "pa2")
    
} // namespace powerAuthTests
