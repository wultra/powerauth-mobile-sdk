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
#include <PowerAuth/Authentication.h>
#include <cc7/crypto/Crypto.h>

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class AuthenticationTests : public UnitTest
{
public:
    
    AuthenticationTests()
    {
        CC7_REGISTER_TEST_METHOD(testAuthenticationV2)
        CC7_REGISTER_TEST_METHOD(testAuthenticationV3)
        CC7_REGISTER_TEST_METHOD(testAuthenticationV4)
    }
    
    struct AuthFactorKEKs
    {
        cc7::ByteArray possession;
        cc7::ByteArray knowledge;
        cc7::ByteArray biometry;
    };

    AuthFactorKEKs v3;
    AuthFactorKEKs v3_bad;
    AuthFactorKEKs v4;
    AuthFactorKEKs v4_bad;
    ByteArray empty;
    
    void setUp() override
    {
        v3.biometry = cc7::crypto::GetRandomData(16);
        v3.knowledge = cc7::crypto::GetRandomData(8);
        v3.possession = cc7::crypto::GetRandomData(16);
        
        v4.biometry = cc7::crypto::GetRandomData(32);
        v4.knowledge = cc7::crypto::GetRandomData(8);
        v4.possession = cc7::crypto::GetRandomData(32);
        
        v3_bad = v4;
        v3_bad.knowledge = cc7::crypto::GetRandomData(3);
        v4_bad = v3;
        v4_bad.knowledge = cc7::crypto::GetRandomData(3);
    }
    
    // unit tests

    void validateAuthentication(ProtocolVersion version, const AuthFactorKEKs& good, const AuthFactorKEKs& bad)
    {
        auto auth = Authentication::possession(good.possession);
        auth.validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION, auth.factors());
        ccstAssertEqual("possession", auth.factorsString());
        ccstAssertEqual(good.possession, auth.possessionKEK());
        ccstMustThrow(Exception, auth.knowledgeKEK());
        ccstMustThrow(Exception, auth.biometryKEK());

        auth = Authentication::knowledge(good.possession, good.knowledge);
        auth.validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION_KNOWLEDGE, auth.factors());
        ccstAssertEqual("possession_knowledge", auth.factorsString());
        ccstAssertEqual(good.possession, auth.possessionKEK());
        ccstAssertEqual(good.knowledge, auth.knowledgeKEK());
        ccstMustThrow(Exception, auth.biometryKEK());
        
        auth = Authentication::knowledge(good.possession, Password(good.knowledge));
        auth.validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION_KNOWLEDGE, auth.factors());
        ccstAssertEqual("possession_knowledge", auth.factorsString());
        ccstAssertEqual(good.possession, auth.possessionKEK());
        ccstAssertEqual(good.knowledge, auth.knowledgeKEK());
        ccstMustThrow(Exception, auth.biometryKEK());
        
        auth = Authentication::biometry(good.possession, good.biometry);
        auth.validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION_BIOMETRY, auth.factors());
        ccstAssertEqual("possession_biometry", auth.factorsString());
        ccstAssertEqual(good.possession, auth.possessionKEK());
        ccstMustThrow(Exception, auth.knowledgeKEK());
        ccstAssertEqual(good.biometry, auth.biometryKEK());
        
        
        // bad scenarios
        auth = Authentication::possession(bad.possession);
        ccstMustThrow(Exception, auth.validate(version));

        auth = Authentication::knowledge(bad.possession, good.knowledge);
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::knowledge(good.possession, bad.knowledge);
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::knowledge(bad.possession, bad.knowledge);
        ccstMustThrow(Exception, auth.validate(version));

        auth = Authentication::knowledge(bad.possession, Password(good.knowledge));
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::knowledge(good.possession, Password(bad.knowledge));
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::knowledge(bad.possession, Password(bad.knowledge));
        ccstMustThrow(Exception, auth.validate(version));
                
        auth = Authentication::biometry(bad.possession, good.biometry);
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::biometry(bad.possession, bad.biometry);
        ccstMustThrow(Exception, auth.validate(version));
        auth = Authentication::biometry(good.possession, bad.biometry);
        ccstMustThrow(Exception, auth.validate(version));
    }

    void testAuthenticationV2()
    {
        // In case that somehow V2 protocol is used, then validation must always fail
        ccstMustThrow(std::exception, validateAuthentication(Version_V2, v3, v3_bad));
    }
    
    void testAuthenticationV3()
    {
        validateAuthentication(Version_V3, v3, v3_bad);
    }
    
    void testAuthenticationV4()
    {
        validateAuthentication(Version_V4, v4, v4_bad);
    }
};

CC7_CREATE_UNIT_TEST(AuthenticationTests, "pa2")
    
} // namespace powerAuthTests
