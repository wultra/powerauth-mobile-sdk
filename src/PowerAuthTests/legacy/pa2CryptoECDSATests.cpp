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
#include <cc7/CC7.h>
#include "../PowerAuth/crypto/JOSE.h"

// legacy test

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class pa2CryptoECDSATests : public UnitTest
{
public:
    
    pa2CryptoECDSATests()
    {
        CC7_REGISTER_TEST_METHOD(testEcdsaSignVerify)
        //CC7_REGISTER_TEST_METHOD(ecdsaTestDataGenerator)
    }
    
    void testEcdsaSignVerify()
    {
        auto ecdsa = cc7::crypto::Signature::getInstance("ECDSA-SHA-256");
        auto curve = cc7::crypto::KeyPairFactory::getInstance("P-256");
        // Generate key-pair
        auto key_pair = curve->generateKeyPair();
        auto public_key_export = key_pair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963);
        // Import public & private key back to OpenSSL structure.
        auto public_key = curve->newPublicKey(public_key_export, cc7::crypto::KEY_FORMAT_RAW);
        
        // Compute signature
        auto message = getRandomData();
        auto signature = ecdsa->sign(key_pair->getPrivateKey(), message);
        
        // convert to JOSE and back to DER
        auto jose_signature = powerAuth::crypto::ECDSA_DERtoJOSE(signature);
        ccstAssertFalse(jose_signature.empty());
        auto der_signature = powerAuth::crypto::ECDSA_JOSEtoDER(jose_signature);
        ccstAssertEqual(signature, der_signature);
        
        // Validate signature
        auto result = ecdsa->verify(*public_key, signature, message);
        ccstAssertTrue(result);
        
        // Validate corrupted data
        auto bad_message = message;
        bad_message[12]++;
        result = ecdsa->verify(*public_key, signature, bad_message);
        ccstAssertFalse(result);
        auto bad_signature = signature;
        bad_signature[12]++;
        result = ecdsa->verify(*public_key, bad_signature, message);
        ccstAssertFalse(result);
        result = ecdsa->verify(*public_key, bad_signature, bad_message);
        ccstAssertFalse(result);
    }
    
    void ecdsaTestDataGenerator()
    {
        auto ecdsa = cc7::crypto::Signature::getInstance("ECDSA-SHA-256");
        auto curve = cc7::crypto::KeyPairFactory::getInstance("P-256");

        // This function generates a test data for high level functions to test
        // JNI and ObjC wrappers.
        const bool hex_output = false;
        for (int i = 0; i < 10; i++) {
            auto key_pair = curve->generateKeyPair();
            auto key = key_pair->getPublicKey().exportKeyToBase64(cc7::crypto::KEY_FORMAT_X963);
            auto data = getRandomData();
            auto signature = ecdsa->sign(key_pair->getPrivateKey(), data);
            printf("Iteration %d\n", i);
            if (hex_output) {
                auto key_hex = FromBase64String(key).hexString();
                printf("  - Message    : %s\n", data.hexString().c_str());
                printf("  - Signature  : %s\n", signature.hexString().c_str());
                printf("  - Public Key : %s\n", key_hex.c_str());
            } else {
                printf("  - Message    : %s\n", data.base64String().c_str());
                printf("  - Signature  : %s\n", signature.base64String().c_str());
                printf("  - Public Key : %s\n", key.c_str());
            }
        }
    }
    
private:
    cc7::ByteArray getRandomData()
    {
        size_t count = (cc7::crypto::GetRandomData(1)[0] & 63) + 13;
        return cc7::crypto::GetRandomData(count);
    }
};

CC7_CREATE_UNIT_TEST(pa2CryptoECDSATests, "pa2")

} // namespace powerAuthTests
