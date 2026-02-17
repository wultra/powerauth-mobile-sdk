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
#include <PowerAuth/VaultService.h>
#include <PowerAuth/SignatureService.h>

#include "model/SessionData.h"

namespace powerAuth {

class Context : public std::enable_shared_from_this<Context>
{
public:

    /// Create instance of context object.
    /// - Parameters:
    ///   - configuration: Instance configuration.
    static std::shared_ptr<Context> getInstance(ConfigurationPtr configuration);

    /// Construct context object. Please use `getInstance()` method to properly
    /// construct the context.
    /// - Parameters:
    ///   - specification: PowerAuth algorithm specification.
    ///   - configuration: Instance configuration.
    Context(PowerAuthSpecPtr specification, ConfigurationPtr configuration);
    
    /// Construct context object as a copy of an existing (primary) context object.
    /// During the copy-construction no services of the context are created.
    /// - Parameters:
    ///   - primary_context: Primary context.
    Context(const Context& primary_context);
    
    /// Create instance of context for the target algorithm based on this existing primary context.
    /// It is used when multiple algorithmic contexts are needed (e.g. protocol upgrade) that share
    /// common settings, while allowing specialization for the target algorithm.
    /// Returns the new context for the target algorithm.
    std::shared_ptr<Context> createTargetAlgorithmContext();
    
    /// Reset context state. This is identical to remove activation locally.
    void resetState() noexcept;
    
    void destroyTargetAlgorithmContext();
    
    /// Returns the target algorithm context if exists.
    std::shared_ptr<Context> getTargetAlgorithmContextPtr() const noexcept;
    
    /// Return configuration used to construct this context.
    const Configuration& configuration() const noexcept;
    /// Return current protocol version.
    ProtocolVersion protocolVersion() const noexcept;
    /// Return current specification.
    PowerAuthSpecPtr specification() const noexcept;

    
    /// Return reference to `TimeService`.
    TimeService& timeService() noexcept;
    
    /// Return reference to `IClientEncryptorFactory` implementation.
    IClientEncryptorFactory& encryptorFactory() noexcept;
    
    /// Return reference to `IActivationService` implementation.
    IActivationService& activationService() noexcept;
    
    /// Return reference to `IAuthenticationService` implementation.
    IAuthenticationService& authenticationService() noexcept;
    
    /// Return reference to `ITokenService` implementation.
    ITokenService& tokenService() noexcept;
    
    /// Return reference to `ISharedSecret` implementation.
    ISharedSecret& sharedSecret();
    
    /// Return reference to `IKeyProvider` implementation.
    IKeyProvider& keyProvider() noexcept;
    
    /// Return reference to `VaultService` implementation.
    VaultService& vaultService() noexcept;
    
    /// Return reference to `SignatureService` implementation.
    SignatureService& signatureService() noexcept;
    
    /// Return reference to `SessionData` object.
    SessionData& sessionData() noexcept;
    
    /// Return reference to `cc7::crypto::KeyPairFactory` implementation used for constructing keys
    /// for digital signatures.
    cc7::crypto::KeyPairFactory& signingKeyPairFactory() noexcept;
    
    const SharedMutexPtr& getSharedMutexPtr() const noexcept;
    const ConfigurationPtr& getConfigurationPtr() const noexcept;
    const SessionDataPtr& getSessionDataPtr() const noexcept;
    
    const TimeServicePtr& getTimeServicePtr() const noexcept;
    const IClientEncryptorFactoryPtr& getEncryptorFactoryPtr() const noexcept;
    const ISharedSecretPtr& getSharedSecretPtr() const noexcept;
    const IKeyProviderPtr& getKeyProviderPtr() const noexcept;
    const VaultServicePtr& getVaultServicePtr() const noexcept;
    const SignatureServicePtr& getSignatureServicePtr() const noexcept;
    
    const IActivationServicePtr& getActivationServicePtr() const noexcept;
    const IAuthenticationServicePtr& getAuthenticationServicePtr() const noexcept;
    const ITokenServicePtr& getTokenServicePtr() const noexcept;
    const cc7::crypto::KeyPairFactoryPtr& getSigningKeyPairFactoryPtr() const noexcept;
        
    void updateAfterProtocolVersionChange();
    
    void clearSensitiveData();
    void restoreSensitiveData();
    
    bool hasProtocolUpgradePending() const noexcept;

private:

    void createServices(bool initial_setup, ConstPowerAuthSpecPtr specification);
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
    VaultServicePtr _vault_service;
    SignatureServicePtr _signature_service;
    
    std::vector<IServicePtr> _services;
    
    std::shared_ptr<Context> _target_context;
};

CC7_SHARED_PTR(Context)

} // namespace powerAuth

