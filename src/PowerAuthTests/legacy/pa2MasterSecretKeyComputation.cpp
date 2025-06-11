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
#include <cc7/crypto/Crypto.h>
#include "../PowerAuth/protocol/ProtocolUtils.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class pa2MasterSecretKeyComputation : public UnitTest
{
public:
    pa2MasterSecretKeyComputation()
    {
        CC7_REGISTER_TEST_METHOD(testMasterSecretKeyComputation)
    }
    
    void testMasterSecretKeyComputation()
    {
        auto p256 = cc7::crypto::KeyPairFactory::getInstance("P-256");
        auto ecdh = cc7::crypto::KeyAgreement::getInstance("ECDH");
        JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/compute-master-secret-key.json");
        auto&& data = root.arrayAtPath("data");
        for (const JSONValue & item : data) {
            auto devicePrivateKey = p256->newPrivateKey(item.dataFromBase64StringAtPath("input.devicePrivateKey"), cc7::crypto::KEY_FORMAT_RAW);
            auto devicePublicKey  = p256->newPublicKey(item.dataFromBase64StringAtPath("input.devicePublicKey"), cc7::crypto::KEY_FORMAT_X963);
            auto serverPrivateKey = p256->newPrivateKey(item.dataFromBase64StringAtPath("input.serverPrivateKey"), cc7::crypto::KEY_FORMAT_RAW);
            auto serverPublicKey  = p256->newPublicKey(item.dataFromBase64StringAtPath("input.serverPublicKey"), cc7::crypto::KEY_FORMAT_X963);
            auto masterSecretKey  = item.dataFromBase64StringAtPath("output.masterSecretKey");
            
            auto ourMasterSecretKey = ecdh->phase(*devicePrivateKey, *serverPublicKey)->getKeyData();
            auto reducedMasterSecretKey = protocol::ReduceSharedSecret(ourMasterSecretKey);
            ccstAssertEqual(reducedMasterSecretKey, masterSecretKey);
        }
    }
};

CC7_CREATE_UNIT_TEST(pa2MasterSecretKeyComputation, "pa2")

} // namespace powerAuthTests
