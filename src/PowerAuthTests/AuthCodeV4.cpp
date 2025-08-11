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
#include <../PowerAuth/v4/FunctionsV4.h>

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;
using namespace powerAuth::v4;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class AuthCodeV4 : public UnitTest
{
public:
    
    AuthCodeV4()
    {
        CC7_REGISTER_TEST_METHOD(testAuthenticationCodeV4)
    }

    void testAuthenticationCodeV4()
    {
        auto root = JSON_ParseFile(g_pa2Files, "pa2/Auth_Code_Test_Vectors.json");
        auto&& data = root.arrayAtPath("auth_code_test_vectors");
        for (const auto& item : data) {
            auto key1 = item["key1"].asBase64();
            auto key2 = item["key2"].asBase64();
            auto key3 = item["key3"].asBase64();
            auto ctrData = item["ctrData"].asBase64();
            auto input = item["inputData"].asBase64();
            auto authCodeOnline = item["authCodeOnline"].asBase64();
            auto authCodeOffline = item["authCodeOffline"].asString();
            auto online = CalculateOnlineAuthorizationCode({key1, key2, key3}, ctrData, input);
            auto offline = CalculateOfflineAuthorizationCode({key1, key2, key3}, ctrData, input, 8);
            ccstAssertEqual(authCodeOnline, online);
            ccstAssertEqual(authCodeOffline, offline);
        }
    }
};

CC7_CREATE_UNIT_TEST(AuthCodeV4, "pa2")
    
} // namespace powerAuthTests
