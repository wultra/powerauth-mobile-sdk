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
#include "../PowerAuth/v4/PowerAuthKDF.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class PowerAuthAEADTests : public UnitTest
{
public:
    
    PowerAuthAEADTests()
    {
        CC7_REGISTER_TEST_METHOD(testSealOpen)
        CC7_REGISTER_TEST_METHOD(testVectors)
    }
    
    ByteArray getRandomData(size_t min, size_t max)
    {
        size_t size = min == max ? max : min + (size_t)arc4random_uniform((uint32_t)(max - min));
        return cc7::crypto::GetRandomData(size);
    }
    
    void testSealOpen()
    {
        const auto& aead = algorithms().v4.aead();
        auto key = cc7::crypto::SymmetricKey::getInstance("AES-256");
        for (int i = 0; i < 100; i++) {
            key->setKeyData(getRandomData(32, 32));
            key->setKeyContext(getRandomData(1, 48));
            auto nonce = getRandomData(12, 12);
            auto aad = getRandomData(0, 64);
            auto plaintext = getRandomData(0, 256);
            auto ciphertext = aead.seal(*key, nonce, aad, plaintext);
            auto opened = aead.open(*key, aad, ciphertext);
            ccstAssertEqual(plaintext, opened);
        }
    }
    
    void testVectors()
    {
        const auto& aead = algorithms().v4.aead();
        auto key = cc7::crypto::SymmetricKey::getInstance("AES-256");
        auto root = JSON_ParseFile(g_pa2Files, "pa2/v4-aead.json");
        auto&& data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto key_data       = item.dataFromBase64StringAtPath("input.key");
            auto key_ctx        = item.dataFromBase64StringAtPath("input.keyContext");
            auto nonce          = item.dataFromBase64StringAtPath("input.nonce");
            auto aad            = item.dataFromBase64StringAtPath("input.associatedData");
            auto expected_pt    = item.dataFromBase64StringAtPath("input.plaintext");
            auto expected_ct    = item.dataFromBase64StringAtPath("output.ciphertext");
            key->setKeyData(key_data);
            key->setKeyContext(key_ctx);
            
            auto ct = aead.seal(*key, nonce, aad, expected_pt);
            if (expected_ct != ct) {
                ccstFailure("PowerAuthAEAD encryption is broken");
                ccstMessage("Key  : %s", key_data.base64String().c_str());
                ccstMessage(" exp : %s", expected_ct.hexString().c_str());
                ccstMessage(" act : %s", ct.hexString().c_str());
                return;
            }
            auto pt = aead.open(*key, aad, expected_ct);
            if (expected_pt != pt) {
                ccstFailure("PowerAuthAEAD decryption is broken");
                ccstMessage("Key  : %s", key_data.base64String().c_str());
                ccstMessage(" exp : %s", expected_pt.hexString().c_str());
                ccstMessage(" act : %s", pt.hexString().c_str());
                return;
            }
        }
    }
    
};

CC7_CREATE_UNIT_TEST(PowerAuthAEADTests, "pa2")
    
} // namespace powerAuthTests
