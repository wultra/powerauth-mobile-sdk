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
#include "../PowerAuth/crypto/PowerAuthKDF.h"

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
    extern TestDirectory g_pa2Files;

    class PowerAuthKDFTests : public UnitTest
    {
    public:
        
        PowerAuthKDFTests()
        {
            CC7_REGISTER_TEST_METHOD(testKDF)
            CC7_REGISTER_TEST_METHOD(testPBKDF)
        }
        
        void testKDF()
        {
            const auto& kdf = algorithms().v4.kdf();
            JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/v4-kdf.json");
            auto&& data = root.arrayAtPath("data");
            for (const JSONValue & item : data) {
                auto key        = item.dataFromBase64StringAtPath("input.key");
                auto custom     = item.dataFromBase64StringAtPath("input.custom");
                auto label      = item.stringAtPath("input.label");
                auto out_size   = static_cast<size_t>(std::atoi(item.stringAtPath("input.outSize").c_str()));
                auto expected_derived = item.dataFromBase64StringAtPath("output.derivedKey");
                auto derived = kdf.derive(key, label, custom, out_size);
                ccstAssertEqual(expected_derived, derived);
            }
        }
        
        void testPBKDF()
        {
            const auto& kdf = algorithms().v4.pbkdf();
            JSONValue root = JSON_ParseFile(g_pa2Files, "pa2/v4-pbkdf.json");
            auto&& data = root.arrayAtPath("data");
            for (const JSONValue & item : data) {
                auto key        = item.stringAtPath("input.password");
                auto salt       = item.dataFromBase64StringAtPath("input.salt");
                auto out_size   = static_cast<size_t>(std::atoi(item.stringAtPath("input.outSize").c_str()));
                auto expected_derived = item.dataFromBase64StringAtPath("output.derivedKey");
                auto derived = kdf.derive(MakeRange(key), salt, out_size);
                ccstAssertEqual(expected_derived, derived);
            }
        }
        
    };
    
    CC7_CREATE_UNIT_TEST(PowerAuthKDFTests, "pa2")
    
} // io::getlime::powerAuthTests
} // io::getlime
} // io
