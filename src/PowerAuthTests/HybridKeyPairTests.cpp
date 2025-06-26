/*
 * Copyright 2025 Wultra s.r.o.
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
#include <../PowerAuth/v4/HybridKeyPair.h>

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;
using namespace powerAuth::v4;

namespace powerAuthTests {

class HybridKeyPairTests : public UnitTest
{
public:
    
    HybridKeyPairTests()
    {
        CC7_REGISTER_TEST_METHOD(testSingleAlgorithm)
        CC7_REGISTER_TEST_METHOD(testHybrid)
    }

    void testSingleAlgorithm()
    {
        const auto alg1 = "ML-DSA-65";
        const auto alg2 = "";
        const auto hybridAlg = "HYBRID:ML-DSA-65";
        
        auto factory = HybridKeyPairFactory::getInstance(alg1, alg2);
        ccstAssertEqual(hybridAlg, factory->getAlgorithmName());
        auto pair = factory->generateKeyPair();
        ccstAssertNotNull(pair);
        auto public_key = pair->getPublicKeyPtr();
        auto private_key = pair->getPrivateKeyPtr();
        ccstAssertNotNull(public_key);
        ccstAssertNotNull(private_key);
        ccstAssertEqual(hybridAlg, public_key->getKeyType());
        ccstAssertEqual(hybridAlg, private_key->getKeyType());

        auto public_exported = public_key->exportKey();
        auto private_exported = private_key->exportKey();
        
        auto public_imported = factory->cc7::crypto::KeyPairFactory::newPublicKey(public_exported);
        auto private_imported = factory->cc7::crypto::KeyPairFactory::newPrivateKey(private_exported);
        ccstAssertEqual(hybridAlg, public_imported->getKeyType());
        ccstAssertEqual(hybridAlg, private_imported->getKeyType());

        ccstAssertEqual(public_exported, public_imported->exportKey());
        ccstAssertEqual(private_exported, private_imported->exportKey());

        auto public_key1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(public_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_1).asObject());
        ccstAssertNotNull(public_key1);
        ccstAssertEqual(alg1, public_key1->getKeyType());
        auto public_key2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(public_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_2).asObject());
        ccstAssertNull(public_key2);

        auto private_key1 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(private_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_1).asObject());
        ccstAssertNotNull(private_key1);
        ccstAssertEqual(alg1, private_key1->getKeyType());
        auto private_key2 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(private_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_2).asObject());
        ccstAssertNull(private_key2);
        
        auto public_key1_exported = public_key1->exportKey();
        auto private_key1_exported = private_key1->exportKey();
        
        auto raw_public_import = factory->newPublicKeyFromData(public_key1->exportKey(),
                                                               cc7::crypto::KEY_FORMAT_DEFAULT,
                                                               ByteRange(),
                                                               cc7::crypto::KEY_FORMAT_DEFAULT);
        ccstAssertEqual(public_exported, raw_public_import->exportKey());
        
        // reimport original key
        auto factory1 = cc7::crypto::KeyPairFactory::getInstance(alg1);
        factory1->newPublicKey(public_key1_exported);
        factory1->newPrivateKey(private_key1_exported);
    }
    
    void testHybrid()
    {
        const auto alg1 = "P-384";
        const auto alg2 = "ML-DSA-65";
        const auto hybridAlg = "HYBRID:P-384+ML-DSA-65";
        
        auto factory = HybridKeyPairFactory::getInstance(alg1, alg2);
        ccstAssertEqual(hybridAlg, factory->getAlgorithmName());
        auto pair = factory->generateKeyPair();
        ccstAssertNotNull(pair);
        auto public_key = pair->getPublicKeyPtr();
        auto private_key = pair->getPrivateKeyPtr();
        ccstAssertNotNull(public_key);
        ccstAssertNotNull(private_key);
        ccstAssertEqual(hybridAlg, public_key->getKeyType());
        ccstAssertEqual(hybridAlg, private_key->getKeyType());

        auto public_exported = public_key->exportKey();
        auto private_exported = private_key->exportKey();
        
        auto public_imported = factory->cc7::crypto::KeyPairFactory::newPublicKey(public_exported);
        auto private_imported = factory->cc7::crypto::KeyPairFactory::newPrivateKey(private_exported);
        ccstAssertEqual(hybridAlg, public_imported->getKeyType());
        ccstAssertEqual(hybridAlg, private_imported->getKeyType());

        ccstAssertEqual(public_exported, public_imported->exportKey());
        ccstAssertEqual(private_exported, private_imported->exportKey());

        auto public_key1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(public_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_1).asObject());
        ccstAssertNotNull(public_key1);
        ccstAssertEqual(alg1, public_key1->getKeyType());
        auto public_key2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(public_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_2).asObject());
        ccstAssertNotNull(public_key2);
        ccstAssertEqual(alg2, public_key2->getKeyType());

        auto private_key1 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(private_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_1).asObject());
        ccstAssertNotNull(private_key1);
        ccstAssertEqual(alg1, private_key1->getKeyType());
        auto private_key2 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(private_key->getKeyParameter(KEY_PARAM_HYBRID_KEY_2).asObject());
        ccstAssertNotNull(private_key2);
        ccstAssertEqual(alg2, private_key2->getKeyType());
        
        auto public_key1_exported = public_key1->exportKey();
        auto public_key2_exported = public_key2->exportKey();
        auto private_key1_exported = private_key1->exportKey();
        auto private_key2_exported = private_key2->exportKey();

        auto raw_public_import = factory->newPublicKeyFromData(public_key1->exportKey(),
                                                               cc7::crypto::KEY_FORMAT_DEFAULT,
                                                               public_key2->exportKey(),
                                                               cc7::crypto::KEY_FORMAT_DEFAULT);
        ccstAssertEqual(public_exported, raw_public_import->exportKey());
        
        // reimport original keys
        auto factory1 = cc7::crypto::KeyPairFactory::getInstance(alg1);
        auto factory2 = cc7::crypto::KeyPairFactory::getInstance(alg2);
        factory1->newPublicKey(public_key1_exported);
        factory2->newPublicKey(public_key2_exported);
        factory1->newPrivateKey(private_key1_exported);
        factory2->newPrivateKey(private_key2_exported);
    }
};

CC7_CREATE_UNIT_TEST(HybridKeyPairTests, "pa2")
    
} // namespace powerAuthTests
