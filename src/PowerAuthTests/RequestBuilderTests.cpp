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
#include <PowerAuth/Credentials.h>
#include <cc7/crypto/Crypto.h>
#include "../src/PowerAuth/request/RequestBuilder.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class RequestBuilderTests : public UnitTest
{
public:
    
    RequestBuilderTests()
    {
        CC7_REGISTER_TEST_METHOD(testRequestBuilder)
    }
    
    const EndpointSpec SPEC1 {
        Version_V4, "/pa/hello/world", "GET", "", EncryptorId::NONE, 0
    };
    
    void testRequestBuilder()
    {
    }
};

CC7_CREATE_UNIT_TEST(RequestBuilderTests, "pa2")
    
} // namespace powerAuthTests
