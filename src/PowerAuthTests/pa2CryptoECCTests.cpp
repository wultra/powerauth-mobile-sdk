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

// legacy test

using namespace cc7;
using namespace cc7::tests;

namespace powerAuthTests {

class pa2CryptoECCTests : public UnitTest
{
public:
    
    pa2CryptoECCTests()
    {
        CC7_REGISTER_TEST_METHOD(testPubKeyImport)
    }

    struct test_data {
        const char * point;
        bool import_result;
    };
    
            
    void testPubKeyImport()
    {
        auto p256 = cc7::crypto::KeyPairFactory::getInstance("P-256");
        
        const test_data test_vectors[] = {
            // Valid points
            { "ApwBezqIdwCdmcjfysfrCaWZ5h9LttqP2RvCjapdKrLd", true },
            { "A/CR2dXXwpj+Y2Kb3eytxmbBEv4/mqQxYW7N5oNg+iea", true },
            { "Ag0TRAqRbD/KVDVeFDhhZX49Wk2X+NitEx7Au7KWMTWi", true },
            { "A5kU3PmJii+kdPVoqtufs9apFbeum43Pz2WnqMyrb2Hp", true },
            { "AxAR3xlwvz9BiFEtRkXx7unhQ5/BmEfrtkM+Z0zzpe8U", true },
            { "AlasqZKRDyk+VUtdrQzSGbF1ATHZ3PYvyUdx3X+rdQsB", true },
            { "A+zDDUcBMErVtKLGT3wrqssQPWgBIlfqZ8cOsU2LARRo", true },
            { "AwOmvwWIIsvPTDcRzz9ZCEOd/CorfSE0AWIJlacCl/NO", true },
            { "Ah6xT4mYIAa5eRRThVFwu5DH5PfWHApOUV/O46EfqKfU", true },
            { "A83L0L6idMpdFbPsB6Btolaa33y1SztWLeE/LoYbI8Ih", true },
            // Invalid points
            { "ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/=", false }, // invalid Base64
            { "ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/", false }, // invalid compressed point
            { "BMa1eFhnJNtFLU6yFeFgcHMt9iPg074ZUKM9D8tX3nuNk7cKwTbbQG8uHItW8NxvPaMYo0WM87eV5Ud9dB3/14Q=", false }, // point is not on curve
            { "Pes+/6wnmrjwVa2L9v2wqUDBYMCtq0qvQ7JIZ6+nZe6fsT+vr85+rUPunAIaK3tRAuIkIROUwYEvj/TlcemQ5Q==", false }, // invalid encoding
            { "BGjj8wAErlEt1FNJzH8uhpWN2GSd9apNK0tWaDAN+Bukt5EwKZ6l3YzX475apYQdVbzmg0X2mRysqrvTEPRj8b8=", false }, // point is not on curve
            { "BLcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/Si4N7VelFWu4LrQxTDf9QVU5Wn5RmIryiczlMbnBcZI=", false }, // point is not on curve
            { "AA==", false }, // infinity
            { nullptr, false }
        };

        int i = 0;
        while (true) {
            const test_data & td = test_vectors[i++];
            const char * test_key = td.point;
            if (!test_key) {
                break;
            }
            bool imported = false;
            std::string error;
            cc7::crypto::PublicKeyPtr pub_key;
            try {
                pub_key = p256->newPublicKey();
                pub_key->importKeyFromBase64(test_key, cc7::crypto::KEY_FORMAT_X963);
                imported = true;
            } catch (std::exception & e) {
                error = e.what();
            }
            if (imported != td.import_result) {
                if (imported) {
                    ccstFailure("Public key '%s' should not be imported.", test_key);
                } else {
                    ccstMessage("Public key '%s' should be imported: %s", test_key, error.c_str());
                    ccstFailure("Import routine is broken");
                }
            }
        }
    }
};

CC7_CREATE_UNIT_TEST(pa2CryptoECCTests, "pa2")
    
} // namespace powerAuthTests
