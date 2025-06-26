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
#include "../PowerAuth/v4/PowerAuthUKE.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class PowerAuthUKETests : public UnitTest
{
public:
    
    PowerAuthUKETests()
    {
        CC7_REGISTER_TEST_METHOD(testWrapUnwrap)
    }
    
    void testWrapUnwrap()
    {
        auto aes_ctr = cc7::crypto::Cipher::getInstance("AES-256-CTR");
        auto alg = v4::PowerAuthUKE(nullptr);
        for (int i = 0; i < 100; i++) {
            auto key = crypto::GetRandomData(32);
            auto kek = crypto::GetRandomData(32);
            auto wrapped_key = alg.wrap(kek, key);
            auto unwrapped   = alg.unwrap(kek, wrapped_key);
            ccstAssertEqual(key, unwrapped);
            for (int j = 0; i < 10; j++) {
                auto wrapped_other = alg.wrap(kek, key);
                ccstAssertNotEqual(wrapped_key, wrapped_other);
            }
            // Alternative unwrap
            auto alt_unwrapped = aes_ctr->decrypt(kek,
                                                  wrapped_key.byteRange().subRangeTo(16),
                                                  wrapped_key.byteRange().subRangeFrom(16));
            ccstAssertEqual(key, alt_unwrapped);
        }
    }
};

CC7_CREATE_UNIT_TEST(PowerAuthUKETests, "pa2")
    
} // namespace powerAuthTests
