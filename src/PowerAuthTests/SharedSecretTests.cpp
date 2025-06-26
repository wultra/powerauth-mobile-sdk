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
        CC7_REGISTER_TEST_METHOD(testVectors_EC_P384)
        CC7_REGISTER_TEST_METHOD(testVectors_EC_P384_ML_L3)
        CC7_REGISTER_TEST_METHOD(testVectors_EC_P384_ML_L3_Client)
        //CC7_REGISTER_TEST_METHOD(genTestVectors_EC_P384_ML_L3)
    }
    
    void test_EC_P384()
    {
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384);
        for (int i = 0; i < 100; i++) {
            auto req = algorithm->generateRequestCryptogram();
            auto client_request = req.first;
            auto client_ctx = req.second;
            ccstAssertEqual("EC_P384", client_request.algorithm);
            ccstAssertFalse(client_request.ecdhe.empty());
            ccstAssertTrue(client_request.mlkem.empty());
                
            auto resp = algorithm->generateResponseCryptogram(client_request);
            auto server_response = resp.first;
            auto server_ss = resp.second;
            ccstAssertFalse(client_request.ecdhe.empty());
            ccstAssertTrue(client_request.mlkem.empty());
            
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
            ccstAssertEqual(client_req_json["ecdhe"].asString(), client_request.ecdhe);
            ccstAssertEqual(2, client_req_json.asObject().size());
            auto server_req_json = SharedSecretRequest::fromJson(client_req_json);
            ccstAssertEqual(client_request.algorithm, server_req_json.algorithm);
            ccstAssertEqual(client_request.ecdhe, server_req_json.ecdhe);
            ccstAssertEqual(client_request.mlkem, server_req_json.mlkem);
            // response
            auto server_res_json = server_response.toJson();
            ccstAssertEqual(server_res_json["ecdhe"].asString(), server_response.ecdhe);
            ccstAssertEqual(1, server_res_json.asObject().size());
            auto client_res_json = SharedSecretResponse::fromJson(server_res_json);
            ccstAssertEqual(server_response.ecdhe, client_res_json.ecdhe);
            ccstAssertEqual(server_response.mlkem, client_res_json.mlkem);
        }
    }
            
    void test_EC_P384_ML_L3()
    {
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384_ML_L3);
        for (int i = 0; i < 2; i++) {
            auto req = algorithm->generateRequestCryptogram();
            auto client_request = req.first;
            auto client_ctx = req.second;
            ccstAssertEqual("EC_P384_ML_L3", client_request.algorithm);
            ccstAssertFalse(client_request.ecdhe.empty());
            ccstAssertFalse(client_request.mlkem.empty());
    
            auto resp = algorithm->generateResponseCryptogram(client_request);
            auto server_response = resp.first;
            auto server_ss = resp.second;
            ccstAssertFalse(client_request.ecdhe.empty());
            ccstAssertFalse(client_request.mlkem.empty());
            
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
            ccstAssertEqual(client_req_json["ecdhe"].asString(), client_request.ecdhe);
            ccstAssertEqual(client_req_json["mlkem"].asString(), client_request.mlkem);
            ccstAssertEqual(3, client_req_json.asObject().size());
            auto server_req_json = SharedSecretRequest::fromJson(client_req_json);
            ccstAssertEqual(client_request.algorithm, server_req_json.algorithm);
            ccstAssertEqual(client_request.ecdhe, server_req_json.ecdhe);
            ccstAssertEqual(client_request.mlkem, server_req_json.mlkem);
            // response
            auto server_res_json = server_response.toJson();
            ccstAssertEqual(server_res_json["ecdhe"].asString(), server_response.ecdhe);
            ccstAssertEqual(server_res_json["mlkem"].asString(), server_response.mlkem);
            ccstAssertEqual(2, server_res_json.asObject().size());
            auto client_res_json = SharedSecretResponse::fromJson(server_res_json);
            ccstAssertEqual(server_response.ecdhe, client_res_json.ecdhe);
            ccstAssertEqual(server_response.mlkem, client_res_json.mlkem);
        }
    }
    
    void testVectors_EC_P384()
    {
        // Original set from powerauth-crypto project
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384);
        auto root = JSON_ParseFile(g_pa2Files, "pa2/ECDHE_P384_Test_Vectors.json");
        auto&& data = root.arrayAtPath("ecdhe_test_vectors");
        std::map<std::string, std::string> params;
        for (const auto& item : data) {
            auto expected_shared_secret = item.dataFromBase64StringAtPath("sharedSecret");
            params.clear();
            params["ecdhe_client_private_key"] = item.stringAtPath("ecClientPrivateKey");
            auto client_ctx = algorithm->importContextForTest(params);
            auto server_response = SharedSecretResponse {
                item.stringAtPath("ecServerPublicKey"),
                ""
            };
            auto shared_secret = algorithm->computeSharedSecret(client_ctx, server_response);
            ccstAssertEqual(expected_shared_secret, shared_secret);
        }
    }

    void testVectors_EC_P384_ML_L3()
    {
        // Original set from powerauth-crypto project
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384_ML_L3);
        auto root = JSON_ParseFile(g_pa2Files, "pa2/ECDHE_P384_MLKEM_768_Test_Vectors.json");
        auto&& data = root.arrayAtPath("ecdhe_mlkem_test_vectors");
        std::map<std::string, std::string> params;
        for (const auto& item : data) {
            auto expected_shared_secret = item.dataFromBase64StringAtPath("sharedSecret");
            params.clear();
            params["ecdhe_client_private_key"] = item.stringAtPath("ecClientPrivateKey");
            params["kem_client_private_key"]   = item.stringAtPath("pqcClientPrivateKey");
            auto client_ctx = algorithm->importContextForTest(params);
            auto server_response = SharedSecretResponse {
                item.stringAtPath("ecServerPublicKey"),
                item.stringAtPath("pqcCiphertext")
            };
            auto shared_secret = algorithm->computeSharedSecret(client_ctx, server_response);
            ccstAssertEqual(expected_shared_secret, shared_secret);
        }
    }

    void testVectors_EC_P384_ML_L3_Client()
    {
        // Set generated in OpenSSL (request) and counterpart response generated in powerauth-crypto.
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384_ML_L3);
        auto root = JSON_ParseFile(g_pa2Files, "pa2/ECDHE_P384_MLKEM_768_Client_Vectors.json");
        auto&& data = root.arrayAtPath("testData");
        for (const auto& item : data) {
            auto expected_shared_secret = item.dataFromBase64StringAtPath("sharedSecret");
            auto client_ctx = item.dataFromBase64StringAtPath("clientContext");
            auto ctx = algorithm->deserializeContext(client_ctx);
            auto response = SharedSecretResponse {
                item.stringAtPath("response.ecServerPublicKey"),
                item.stringAtPath("response.pqcCiphertext")
            };
            auto shared_secret = algorithm->computeSharedSecret(ctx, response);
            if (expected_shared_secret != shared_secret) {
                ccstAssertEqual(expected_shared_secret, shared_secret);
            }
        }
    }
    
    void genTestVectors_EC_P384_ML_L3()
    {
        // Generate request vectors for `testVectors_EC_P384_ML_L3_Client()`
        auto algorithm = SharedSecret::getInstance(SharedSecret::EC_P384_ML_L3);
        std::string out;
        std::string tb  = "  ";
        std::string nl  = "\n";
        out += "{" + nl;
        out += tb + "\"testData\" : [{" + nl;
        for (int i = 1; i <= 10; i++) {
            auto request = algorithm->generateRequestCryptogram();
            auto client_request = request.first;
            auto ctx_data = algorithm->serializeContext(request.second);
            if (i > 1) {
                out += tb + "},{" + nl;
            }
            out += tb + tb + "\"clientContext\" : \"" + ctx_data.base64String() + "\"," + nl;
            out += tb + tb + "\"request\" : {" + nl;
            out += tb + tb + tb + "\"ecClientPublicKey\" : \"" + client_request.ecdhe + "\"," + nl;
            out += tb + tb + tb + "\"pqcEncapsulationKey\" : \"" + client_request.mlkem + "\"" + nl;
            out += tb + tb + "}" + nl;
        }
        out += tb + "}]" + nl;
        out += "}";
        
        fprintf(stdout, "EC_P384_ML_L3: \n%s", out.c_str());
        fflush(stdout);
    }
};

CC7_CREATE_UNIT_TEST(SharedSecretTests, "pa2")
    
} // namespace powerAuthTests
