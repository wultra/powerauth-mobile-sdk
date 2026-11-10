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
        CC7_REGISTER_TEST_METHOD(testActivationRenameEndpoints)
    }
    
    const EndpointSpec SPEC1 {
        Version_V4, "/pa/hello/world", "", EncryptorId::NONE, 0, "GET"
    };
    
    void testRequestBuilder()
    {
    }

    void testActivationRenameEndpoints()
    {
        validateActivationRenameEndpoint(v3::Endpoint_ActivationRename, Version_V3, "/pa/v3/activation/rename");
        validateActivationRenameEndpoint(v4::Endpoint_ActivationRename, Version_V4, "/pa/v4/activation/rename");
        ccstAssertFalse(v3::Endpoint_TokenCreate.authenticateBeforeEncryption());
        ccstAssertFalse(v4::Endpoint_TokenCreate.authenticateBeforeEncryption());
    }

    void validateActivationRenameEndpoint(const EndpointSpec& spec, ProtocolVersion version, const std::string& path)
    {
        ccstAssertEqual(version, spec.version);
        ccstAssertEqual(path, spec.relativePath);
        ccstAssertEqual(std::string("/pa/activation/rename"), spec.uriId);
        ccstAssertEqual(EncryptorId::ACTIVATION_SCOPE_GENERIC, spec.encryptorId);
        ccstAssertTrue(spec.isEncrypted());
        ccstAssertTrue(spec.isAuthenticated());
        ccstAssertTrue(spec.isPublicResponseJson());
        ccstAssertTrue(spec.requireSerialQueue());
        ccstAssertFalse(spec.requireWrappedRequestResponse());
        ccstAssertFalse(spec.forceEncryptionHeader());
        ccstAssertTrue(spec.authenticateBeforeEncryption());
    }
};

CC7_CREATE_UNIT_TEST(RequestBuilderTests, "pa2")
    
} // namespace powerAuthTests
