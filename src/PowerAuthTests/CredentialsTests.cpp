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

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class CredentialsTests : public UnitTest
{
public:
    
    CredentialsTests()
    {
        CC7_REGISTER_TEST_METHOD(testCredentialsV2)
        CC7_REGISTER_TEST_METHOD(testCredentialsV3)
        CC7_REGISTER_TEST_METHOD(testCredentialsV4)
        CC7_REGISTER_TEST_METHOD(testInitialCredentialsV2)
        CC7_REGISTER_TEST_METHOD(testInitialCredentialsV3)
        CC7_REGISTER_TEST_METHOD(testInitialCredentialsV4)
    }
    
    struct AuthFactorKEKs
    {
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
        
        v4.biometry = cc7::crypto::GetRandomData(32);
        v4.knowledge = cc7::crypto::GetRandomData(8);
        
        v3_bad = v4;
        v3_bad.knowledge = cc7::crypto::GetRandomData(3);
        v4_bad = v3;
        v4_bad.knowledge = cc7::crypto::GetRandomData(3);
    }
    
    // unit tests

    void validateCredentials(ProtocolVersion version, const AuthFactorKEKs& good, const AuthFactorKEKs& bad)
    {
        auto auth = Credentials::possession();
        auth->validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION, auth->factors());
        ccstAssertEqual("possession", auth->factorsString());
        ccstMustThrow(Exception, auth->knowledgeKEK());
        ccstMustThrow(Exception, auth->biometryKEK());

        auth = Credentials::knowledge(good.knowledge);
        auth->validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION_KNOWLEDGE, auth->factors());
        ccstAssertEqual("possession_knowledge", auth->factorsString());
        ccstAssertEqual(good.knowledge, auth->knowledgeKEK());
        ccstMustThrow(Exception, auth->biometryKEK());
                
        auth = Credentials::biometry(good.biometry);
        auth->validate(version);
        ccstAssertEqual(AuthFactors::POSSESSION_BIOMETRY, auth->factors());
        ccstAssertEqual("possession_biometry", auth->factorsString());
        ccstMustThrow(Exception, auth->knowledgeKEK());
        ccstAssertEqual(good.biometry, auth->biometryKEK());
        
        
        // bad scenarios
        auth = Credentials::knowledge(bad.knowledge);
        ccstMustThrow(Exception, auth->validate(version));
                
        auth = Credentials::biometry(bad.biometry);
        ccstMustThrow(Exception, auth->validate(version));
    }

    void testCredentialsV2()
    {
        // In case that somehow V2 protocol is used, then validation must always fail
        ccstMustThrow(std::exception, validateCredentials(Version_V2, v3, v3_bad));
    }
    
    void testCredentialsV3()
    {
        validateCredentials(Version_V3, v3, v3_bad);
    }
    
    void testCredentialsV4()
    {
        validateCredentials(Version_V4, v4, v4_bad);
    }
    
    void validateInitialCredentials(ProtocolVersion version, const AuthFactorKEKs& good, const AuthFactorKEKs& bad)
    {
        auto cred = InitialCredentials::credentials(good.knowledge, good.biometry);
        cred->validate(version);
        ccstAssertTrue(cred->hasBiometryKEK());
        ccstAssertEqual(good.knowledge, cred->knowledgeKEK());
        ccstAssertEqual(good.biometry, cred->biometryKEK());
        
        cred = InitialCredentials::credentials(good.knowledge);
        cred->validate(version);
        ccstAssertFalse(cred->hasBiometryKEK());
        ccstAssertEqual(good.knowledge, cred->knowledgeKEK());
        ccstAssertEqual(cc7::ByteRange(), cred->biometryKEK());
        
        cred = InitialCredentials::credentials(bad.knowledge);
        ccstMustThrow(Exception, cred->validate(version));
        cred = InitialCredentials::credentials(good.knowledge, bad.biometry);
        ccstMustThrow(Exception, cred->validate(version));
        cred = InitialCredentials::credentials(bad.knowledge, good.biometry);
        ccstMustThrow(Exception, cred->validate(version));
        cred = InitialCredentials::credentials(bad.knowledge, bad.biometry);
        ccstMustThrow(Exception, cred->validate(version));
    }
    
    void testInitialCredentialsV2()
    {
        // In case that somehow V2 protocol is used, then validation must always fail
        ccstMustThrow(std::exception, validateInitialCredentials(Version_V2, v3, v3_bad));
    }
    
    void testInitialCredentialsV3()
    {
        validateInitialCredentials(Version_V3, v3, v3_bad);
    }
    
    void testInitialCredentialsV4()
    {
        validateInitialCredentials(Version_V4, v4, v4_bad);
    }
};

CC7_CREATE_UNIT_TEST(CredentialsTests, "pa2")
    
} // namespace powerAuthTests
