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

#pragma once

#include <PowerAuth/Types.h>
#include <PowerAuth/Configuration.h>
#include <PowerAuth/TimeService.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/KeyProvider.h>
#include <PowerAuth/SharedSecret.h>
#include <PowerAuth/PowerAuthSpec.h>
#include <PowerAuth/ActivationService.h>
#include <PowerAuth/AuthenticationService.h>
#include <PowerAuth/TokenService.h>

#include "model/SessionData.h"

namespace powerAuth {

class Context : public std::enable_shared_from_this<Context>
{
public:

    /// Create instance of context object.
    /// - Parameters:
    ///   - specification: PowerAuth algorithm specification.
    ///   - configuration: Instance configuration.
    static std::shared_ptr<Context> getInstance(PowerAuthSpec::Algorithm algorithm,
                                                ConfigurationPtr configuration);

    /// Construct context object. Please use `getInstance()` method to properly construct context.
    /// - Parameters:
    ///   - specification: PowerAuth algorithm specification.
    ///   - configuration: Instance configuration.
    Context(PowerAuthSpecPtr specification, ConfigurationPtr configuration);
    

    ProtocolVersion protocolVersion() const noexcept;
    const Configuration& configuration() const noexcept;
    PowerAuthSpecPtr specification() const noexcept;

    TimeService& timeService() noexcept;
    IClientEncryptorFactory& encryptorFactory() noexcept;
    IActivationService& activationService() noexcept;
    IAuthenticationService& authenticationService() noexcept;
    ITokenService& tokenService() noexcept;
    
    ISharedSecret& sharedSecret();
    IKeyProvider& keyProvider();
    SessionData& sessionData();
    cc7::crypto::KeyPairFactory& signingKeyPairFactory();
    
    const SharedMutexPtr getSharedMutexPtr() const noexcept;
    const ConfigurationPtr& getConfigurationPtr() const noexcept;
    const SessionDataPtr& getSessionDataPtr() const noexcept;
    
    const TimeServicePtr& getTimeServicePtr() const noexcept;
    const IClientEncryptorFactoryPtr& getEncryptorFactoryPtr() const noexcept;
    const ISharedSecretPtr& getSharedSecretPtr() const noexcept;
    const IKeyProviderPtr& getKeyProviderPtr() const noexcept;
    
    const IActivationServicePtr& getActivationServicePtr() const noexcept;
    const IAuthenticationServicePtr& getAuthenticationServicePtr() const noexcept;
    const ITokenServicePtr& getTokenServicePtr() const noexcept;
    const cc7::crypto::KeyPairFactoryPtr& getSigningKeyPairFactoryPtr() const noexcept;
        
    void updateAfterProtocolVersionChange();
    
    void clearSensitiveData();
    void restoreSensitiveData();
    
private:
    
    void createBasicServices(bool initial_setup);
    void destroyServices();
    
    mutable SharedMutexPtr _shared_mutex;
    const ConfigurationPtr _configuration;
    PowerAuthSpecPtr _specification;
    SessionDataPtr _session_data;
    cc7::crypto::KeyPairFactoryPtr _signing_keys_factory;
    
    TimeServicePtr _time_service;
    IClientEncryptorFactoryPtr _encryptor_factory;
    IActivationServicePtr _activation_service;
    ISharedSecretPtr _shared_secret;
    IKeyProviderPtr _key_provider;
    IAuthenticationServicePtr _auth_service;
    ITokenServicePtr _token_service;
    
    std::vector<IServicePtr> _services;
};

CC7_SHARED_PTR(Context)

} // namespace powerAuth

