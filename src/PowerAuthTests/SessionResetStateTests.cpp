/*
 * Copyright 2026 Wultra s.r.o.
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
#include <PowerAuth/Session.h>
#include "ConfigurationGenerator.h"
#include "../PowerAuth/Context.h"
#include "../PowerAuth/model/Constants.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class SessionResetStateTests : public UnitTest
{
public:
    
    SessionResetStateTests()
    {
        CC7_REGISTER_TEST_METHOD(test_ResetStateWithV3ActivationOnV4Config)
        CC7_REGISTER_TEST_METHOD(test_ResetStateWithMatchingV3Config)
    }
    
    /// Create serialized session state containing a valid V3 activation. The activation
    /// is fabricated locally, with no server key-exchange involved.
    cc7::ByteArray createSerializedV3ActivationState(ConfigurationGenerator& generator)
    {
        auto v3_config = Configuration::Builder(generator.sdkConfiguration, PowerAuthSpec::LEGACY_P256)
                            .withDeviceSpecificData(generator.deviceSpecificData)
                            .withInstanceId(generator.configuration->instanceId())
                            .build();
        auto context = Context::getInstance(v3_config);
        
        auto device_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        auto server_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        auto shared_secret = cc7::crypto::GetRandomData(16);
        
        auto rd = RegistrationData::create(Version_V3);
        rd->v3() = {
            cc7::crypto::GetRandomData(16).base64(),                                // activation ID
            cc7::crypto::GetRandomData(v3::HASH_COUNTER_SIZE),                      // hash counter
            server_key_pair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_RAW), // server public (direct key data)
            device_key_pair,                                                        // device pair
            server_key_pair->getPublicKeyPtr(),                                     // server public
            shared_secret
        };
        context->sessionData().setRegistrationData(rd);
        
        // "Commit" the activation. The key provider is responsible for the persistent
        // data creation at the end of the operation.
        auto creds = InitialCredentials::credentials(cc7::MakeRange("secret.password"));
        auto secrets = context->keyProvider().unlockInitialSecretKeys(*creds, shared_secret);
        context->keyProvider().lockSecretKeys(secrets);
        ccstAssertTrue(context->sessionData().hasPersistentData());
        
        return context->sessionData().serialize();
    }
    
    void test_ResetStateWithV3ActivationOnV4Config()
    {
        ConfigurationGenerator generator(PowerAuthSpec::EC_P384_ML_L3);
        auto serialized_state = createSerializedV3ActivationState(generator);
        
        // Create session with V4-capable configuration and load state with V3 activation.
        // This simulates an application configured for V4 with an older V3 activation.
        auto session = Session::createInstance(generator.configuration);
        session->loadState(serialized_state);
        ccstAssertTrue(session->hasValidActivationData());
        ccstAssertEqual(Version_V3, session->getProtocolVersion());
        
        // Reset must remove the activation data even though the current specification
        // differs from the initial one.
        session->resetState();
        ccstAssertFalse(session->hasValidActivationData());
        ccstAssertTrue(session->canCreateActivation());
        ccstAssertEqual(Version_V4, session->getProtocolVersion());
        
        // The removed activation must not survive the save & restore roundtrip.
        auto saved_state = session->saveState();
        auto restored_session = Session::createInstance(generator.configuration);
        restored_session->loadState(saved_state);
        ccstAssertFalse(restored_session->hasValidActivationData());
        ccstAssertTrue(restored_session->canCreateActivation());
    }
    
    void test_ResetStateWithMatchingV3Config()
    {
        ConfigurationGenerator generator(PowerAuthSpec::LEGACY_P256);
        auto serialized_state = createSerializedV3ActivationState(generator);
        
        // Create session with V3 configuration matching the protocol version of the activation.
        auto session = Session::createInstance(generator.configuration);
        session->loadState(serialized_state);
        ccstAssertTrue(session->hasValidActivationData());
        ccstAssertEqual(Version_V3, session->getProtocolVersion());
        
        session->resetState();
        ccstAssertFalse(session->hasValidActivationData());
        ccstAssertTrue(session->canCreateActivation());
    }
};

CC7_CREATE_UNIT_TEST(SessionResetStateTests, "pa2")

} // namespace powerAuthTests
