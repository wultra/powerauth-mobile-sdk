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
#include "../PowerAuth/v4/EncryptorV4.h"
#include "../PowerAuth/v4/E2EEUtilsV4.h"
#include "TestTimeProvider.h"
#include <cc7/HexString.h>

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;
// Unit test

class ClientEncryptorV4Tests : public UnitTest
{
public:
    
    ClientEncryptorV4Tests()
    {
        CC7_REGISTER_TEST_METHOD(testEncryptDecrypt)
        CC7_REGISTER_TEST_METHOD(testVectors)
    }
    
    std::shared_ptr<TestTimeProvider> timeProvider;
    TimeServicePtr timeService;
    cc7::crypto::NonceGeneratorPtr nonceGenerator;
    
    void setUp() override
    {
        timeProvider = std::make_shared<TestTimeProvider>();
        timeService = std::make_shared<TimeService>(timeProvider);
        nonceGenerator = cc7::crypto::DefaultNonceGenerator::getInstance(12);
    }
    
    void SleepThread(TimeInterval interval)
    {
        timeProvider->sleepThread(interval);
    }

    TimeInterval Date(void)
    {
        return timeProvider->getCurrentTime();
    }

    void ResetDate(void)
    {
        timeProvider->setTime(cc7::GetCurrentTime());
    }

    
    void testEncryptDecrypt()
    {
        for (int i = 0; i < 100; i++) {
            auto app_scope = (i & 1) == 0;
            
            auto client_plaintext = getRandomData();
            auto server_plaintext = getRandomData();
            
            auto appKey    = cc7::crypto::GetRandomData(16).base64();
            auto appSecret = cc7::crypto::GetRandomData(16);
            auto actId = app_scope ? std::string() : getRandomString(36);
            auto sharedInfo1 = getRandomSharedInfo1();
            auto envelope_key = cc7::crypto::GetRandomData(32);
            auto e2ee_key = cc7::crypto::GetRandomData(32);
            auto nonce = getNewNonce();
            
            auto keyId = getRandomString(36);
            
            auto client_enc_params = EncryptorParameters::makeParameters("4.0", appKey, keyId, sharedInfo1, actId);
            auto client_enc_secrets = app_scope ? v4::E2EE_ApplicationScopeSecrets(envelope_key, appSecret) : v4::E2EE_ActivationScopeSecrets(envelope_key, appSecret, e2ee_key);
            
            auto client_encryptor = v4::ClientEncryptor(client_enc_params, client_enc_secrets, nonce, timeService);
            ccstAssertTrue(client_encryptor.canEncryptRequest());
            ccstAssertFalse(client_encryptor.canDecryptResponse());
            
            auto request = client_encryptor.encryptRequest(client_plaintext);
            ccstAssertFalse(client_encryptor.canEncryptRequest());
            ccstAssertTrue(client_encryptor.canDecryptResponse());

            SleepThread(0.1);
            
            auto server_enc_params = EncryptorParameters::makeParameters("4.0", appKey, keyId, sharedInfo1, actId);
            auto server_enc_secrets = app_scope ? v4::E2EE_ApplicationScopeSecrets(envelope_key, appSecret) : v4::E2EE_ActivationScopeSecrets(envelope_key, appSecret, e2ee_key);
            
            auto server_encryptor = v4::ServerEncryptor(server_enc_params, server_enc_secrets, timeProvider);
            ccstAssertTrue(server_encryptor.canDecryptRequest());
            ccstAssertFalse(server_encryptor.canEncryptResponse());
            
            auto plaintext = server_encryptor.decryptRequest(request);
            ccstAssertFalse(server_encryptor.canDecryptRequest());
            ccstAssertTrue(server_encryptor.canEncryptResponse());

            ccstAssertEqual(client_plaintext, plaintext);
            
            auto response = server_encryptor.encryptResponse(server_plaintext);
            ccstAssertFalse(server_encryptor.canDecryptRequest());
            ccstAssertFalse(server_encryptor.canEncryptResponse());
            
            SleepThread(0.1);
            
            plaintext = client_encryptor.decryptResponse(response);
            ccstAssertFalse(client_encryptor.canEncryptRequest());
            ccstAssertFalse(client_encryptor.canDecryptResponse());

            ccstAssertEqual(server_plaintext, plaintext);
        }
    }

    void testVectors()
    {
        ccstMessage("Application scope");
        runBatch( JSON_ParseFile(g_pa2Files, "pa2/E2ee_Application_Scope_Test_Vectors.json").valueAtPath("e2ee_test_vectors_application_scope"), false);
        ccstMessage("Activation scope");
        runBatch( JSON_ParseFile(g_pa2Files, "pa2/E2ee_Activation_Scope_Test_Vectors.json").valueAtPath("e2ee_test_vectors_activation_scope"), true);
    }
    
    void runBatch(const cc7::json::JsonValue& data, bool activation_scope)
    {
        for (const auto& item : data.asArray()) {
            const auto encryptorId = item["encryptorId"].asString();
            const auto activationId = activation_scope ? item["activationId"].asString() : std::string();
            const auto applicationKey = item["applicationKey"].asString();
            const auto applicationSecret = item["applicationSecret"].asString();
            const auto appSecretBytes = item.dataFromBase64StringAtPath("applicationSecret");
            const auto temporaryKeyId = item["temporaryKeyId"].asString();
            const auto envelopeKey = item.dataFromBase64StringAtPath("envelopeKey");
            const auto sharedInfo2Key = activation_scope ? item.dataFromBase64StringAtPath("sharedInfo2Key") : ByteArray();
            const auto requestData = ByteArray(MakeRange(item["requestData"].asString()));
            const auto responseData = ByteArray(MakeRange(item["responseData"].asString()));
            const auto timestampRequest = std::stoll(item["timestampRequest"].asString());
            const auto timestampResponse = std::stoll(item["timestampResponse"].asString());
            const auto nonce = item.dataFromBase64StringAtPath("nonce");
            const auto encryptedDataRequest = item.dataFromBase64StringAtPath("encryptedDataRequest");
            const auto encryptedDataResponse = item.dataFromBase64StringAtPath("encryptedDataResponse");
            
            auto enc_spec = EncryptorSpec::specForName(encryptorId);
            
            auto client_enc_params = EncryptorParameters::makeParameters("4.0", applicationKey, temporaryKeyId, enc_spec->sharedInfo, activationId);
            auto client_enc_secrets = activation_scope ? v4::E2EE_ActivationScopeSecrets(envelopeKey, appSecretBytes, sharedInfo2Key) : v4::E2EE_ApplicationScopeSecrets(envelopeKey, appSecretBytes);
            
            auto client_encryptor = v4::ClientEncryptor(client_enc_params, client_enc_secrets, nonce, timeService);
            
            // Enforce time in testing time provider
            timeProvider->setTimestamp(timestampRequest);
            timeService->resetTimeSynchronization();
            // Encrypt request
            auto request = client_encryptor.encryptRequest(requestData);
            // Validate request
            auto request_ciphertext = request.requestPayload.dataFromBase64StringAtPath("encryptedData");
            if (request_ciphertext != encryptedDataRequest) {
                ccstMessage("Ciphertext doesn't match");
                ccstMessage(" - expected: %s", encryptedDataRequest.hexString().c_str());
                ccstMessage(" - ours    : %s", request_ciphertext.hexString().c_str());
                ccstAssertEqual(encryptedDataRequest, request_ciphertext);
            }
            ccstAssertEqual(timestampRequest, request.requestPayload["timestamp"].asInteger());
            ccstAssertEqual(nonce.base64(), request.requestPayload["nonce"].asString());
            ccstAssertEqual(temporaryKeyId, request.requestPayload["temporaryKeyId"].asString());
            
            // Prepare response
            auto response_object = json::JsonValue::object();
            response_object["encryptedData"] = json::JsonValue(encryptedDataResponse.base64());
            response_object["timestamp"] = json::JsonValue(timestampResponse);
            auto response = EncryptedResponse { response_object };
            
            auto response_data = client_encryptor.decryptResponse(response);
            ccstAssertEqual(responseData, response_data);
        }
    }
    
    static ByteArray getRandomData()
    {
        return crypto::GetRandomData(arc4random_uniform(257));
    }
    
    static std::string getRandomString(size_t size)
    {
        assert((size & 1) == 0);
        return cc7::ToHexString(cc7::crypto::GetRandomData(size/2));
    }
    
    static std::string getRandomSharedInfo1()
    {
        static const EncryptorId ids[] = {
            EncryptorId::ACTIVATION_SCOPE_GENERIC,
            EncryptorId::APPLICATION_SCOPE_GENERIC,
            EncryptorId::ACTIVATION_LAYER_2,
            EncryptorId::UPGRADE,
            EncryptorId::CREATE_TOKEN,
            EncryptorId::VAULT_UNLOCK,
        };
        auto enc_id = ids[arc4random_uniform(sizeof(ids)/sizeof(ids[0]))];
        auto spec = EncryptorSpec::specForId(enc_id);
        assert(spec);
        return spec->sharedInfo;
    }
    
    cc7::ByteArray getNewNonce()
    {
        auto request_nonce = nonceGenerator->getNonce();
        auto response_nonce = nonceGenerator->getNonce();
        return ConcatByteRanges({ request_nonce, response_nonce });
    }
};

CC7_CREATE_UNIT_TEST(ClientEncryptorV4Tests, "pa2")
    
} // namespace powerAuthTests
