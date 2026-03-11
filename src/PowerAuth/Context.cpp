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

#include "Context.h"

#include "v4/KeyProviderV4.h"
#include "v4/AeadEncryptorFactory.h"
#include "v4/ActivationServiceV4.h"
#include "v4/AuthenticationServiceV4.h"
#include "v4/TokenServiceV4.h"

#include "v3/KeyProviderV3.h"
#include "v3/EciesEncryptorFactory.h"
#include "v3/ActivationServiceV3.h"
#include "v3/AuthenticationServiceV3.h"
#include "v3/TokenServiceV3.h"

namespace powerAuth {

#if defined(DEBUG)
// debug build
static void _DumpErr(const char * msg)
{
    CC7_LOG("%s", msg);
}
#define CHECK_OBJ_PTR(ptr)                                          \
    if (ptr == nullptr) {                                           \
        _DumpErr("ERROR: Context " #ptr ": Object is null");        \
    }
#define CHECK_AS_SERVICE_PTR(ptr)                                   \
    if (ptr == nullptr) {                                           \
        _DumpErr("ERROR: Context " #ptr ": Service is null");       \
    } else if (ptr->asService()->isServiceDestroyed()) {            \
        _DumpErr("ERROR: Context " #ptr ": Service is destroyed");  \
    }
#define CHECK_SERVICE_PTR(ptr)                                      \
    if (ptr == nullptr) {                                           \
        _DumpErr("ERROR: Context " #ptr ": Service is null");       \
    } else if (ptr->isServiceDestroyed()) {            \
        _DumpErr("ERROR: Context " #ptr ": Service is destroyed");  \
    }
#else
// release build
#define CHECK_OBJ_PTR(ptr)
#define CHECK_AS_SERVICE_PTR(ptr)
#define CHECK_SERVICE_PTR(ptr)
#endif

// MARK: - Configuration

ProtocolVersion Context::protocolVersion() const noexcept
{
    return specification()->protocolVersion();
}

const Configuration& Context::configuration() const noexcept
{
    return *_configuration;
}

PowerAuthSpecPtr Context::specification() const noexcept
{
    CHECK_OBJ_PTR(_specification)
    return _specification;
}


// MARK: - Basic services

TimeService& Context::timeService() noexcept
{
    CHECK_OBJ_PTR(_time_service)
    return *_time_service;
}

IClientEncryptorFactory& Context::encryptorFactory() noexcept
{
    CHECK_AS_SERVICE_PTR(_encryptor_factory)
    return *_encryptor_factory;
}

IActivationService& Context::activationService() noexcept
{
    CHECK_AS_SERVICE_PTR(_activation_service)
    return *_activation_service;
}

IAuthenticationService& Context::authenticationService() noexcept
{
    CHECK_AS_SERVICE_PTR(_auth_service)
    return *_auth_service;
}

ITokenService& Context::tokenService() noexcept
{
    CHECK_AS_SERVICE_PTR(_token_service)
    return *_token_service;
}

ISharedSecret& Context::sharedSecret()
{
    if (specification()->protocolVersion() == Version_V3) {
        throw Exception(EC_InternalError, "ISharedSecret is not available in legacy protocol");
    }
    return *_shared_secret;
}

cc7::crypto::KeyPairFactory& Context::signingKeyPairFactory() noexcept
{
    CHECK_OBJ_PTR(_signing_keys_factory)
    return *_signing_keys_factory;
}

IKeyProvider& Context::keyProvider() noexcept
{
    CHECK_AS_SERVICE_PTR(_key_provider)
    return *_key_provider;
}

VaultService& Context::vaultService() noexcept
{
    CHECK_SERVICE_PTR(_vault_service);
    return *_vault_service;
}

SignatureService& Context::signatureService() noexcept
{
    CHECK_SERVICE_PTR(_signature_service);
    return *_signature_service;
}

SessionData& Context::sessionData() noexcept
{
    CHECK_OBJ_PTR(_session_data)
    return *_session_data;
}

// MARK: - Object pointers

const SharedMutexPtr& Context::getSharedMutexPtr() const noexcept
{
    return _shared_mutex;
}

const ConfigurationPtr& Context::getConfigurationPtr() const noexcept
{
    return _configuration;
}

const SessionDataPtr& Context::getSessionDataPtr() const noexcept
{
    CHECK_OBJ_PTR(_session_data)
    return _session_data;
}

const TimeServicePtr& Context::getTimeServicePtr() const noexcept
{
    CHECK_OBJ_PTR(_time_service)
    return _time_service;
}

const IClientEncryptorFactoryPtr& Context::getEncryptorFactoryPtr() const noexcept
{
    /// During protocol upgrade we use the E2EE approach of the target algorithm.
    if (_session_data->hasUpgradeData() && _target_context) {
        CHECK_AS_SERVICE_PTR(_target_context->_encryptor_factory)
        return _target_context->_encryptor_factory;
    }
    
    CHECK_AS_SERVICE_PTR(_encryptor_factory)
    return _encryptor_factory;
}

const ISharedSecretPtr& Context::getSharedSecretPtr() const noexcept
{
    CHECK_OBJ_PTR(_shared_secret)
    return _shared_secret;
}

const IKeyProviderPtr& Context::getKeyProviderPtr() const noexcept
{
    CHECK_AS_SERVICE_PTR(_key_provider)
    return _key_provider;
}

const VaultServicePtr& Context::getVaultServicePtr() const noexcept
{
    CHECK_SERVICE_PTR(_vault_service);
    return _vault_service;
}

const SignatureServicePtr& Context::getSignatureServicePtr() const noexcept
{
    CHECK_SERVICE_PTR(_signature_service);
    return _signature_service;
}

const IActivationServicePtr& Context::getActivationServicePtr() const noexcept
{
    CHECK_AS_SERVICE_PTR(_activation_service)
    return _activation_service;
}

const IAuthenticationServicePtr& Context::getAuthenticationServicePtr() const noexcept
{
    CHECK_AS_SERVICE_PTR(_auth_service)
    return _auth_service;
}

const ITokenServicePtr& Context::getTokenServicePtr() const noexcept
{
    CHECK_AS_SERVICE_PTR(_token_service)
    return _token_service;
}

const cc7::crypto::KeyPairFactoryPtr& Context::getSigningKeyPairFactoryPtr() const noexcept
{
    CHECK_OBJ_PTR(_signing_keys_factory)
    return _signing_keys_factory;
}


// MARK: - Construction

Context::Context(PowerAuthSpecPtr specification, ConfigurationPtr configuration) :
    _shared_mutex(std::make_shared<std::recursive_mutex>()),
    _configuration(configuration),
    _specification(specification)
{
}

ContextPtr Context::getInstance(ConfigurationPtr configuration)
{
    auto spec = PowerAuthSpec::specForAlgorithm(configuration->algorithm());
    if (!spec) {
        throw Exception(EC_InternalError, "Unknown PowerAuth algorithm");
    }
    auto context = std::make_shared<Context>(spec, configuration);
    context->createServices(true, spec);
    return context;
}

Context::Context(const Context& primary_context) :
    _shared_mutex(primary_context.getSharedMutexPtr()),
    _configuration(primary_context.getConfigurationPtr()),
    _time_service(primary_context.getTimeServicePtr()),
    _session_data(primary_context.getSessionDataPtr())
{
}

std::shared_ptr<Context> Context::createTargetAlgorithmContext()
{
    _target_context = std::make_shared<Context>(*this);
    _target_context->createServices(false, _session_data->getTargetSpecification());
    return _target_context;
}

void Context::resetState() noexcept
{
    for (const auto& service : _services) {
        service->clearActivationData();
    }
}

void Context::destroyTargetAlgorithmContext()
{
    if (!_target_context) {
        return;
    }
    
    _target_context->destroyServices();
    _target_context = nullptr;
}

std::shared_ptr<Context> Context::getTargetAlgorithmContextPtr() const noexcept
{
    CHECK_OBJ_PTR(_target_context);
    return _target_context;
}

void Context::createServices(bool initial_setup, ConstPowerAuthSpecPtr specification)
{
    auto self = shared_from_this();
    auto version = specification->protocolVersion();
    if (initial_setup) {
        // Initial objects construction
        _time_service = std::make_shared<TimeService>(self);
        _session_data = std::make_shared<SessionData>(specification);
    }
    _specification = specification;
    _signing_keys_factory = _specification->getSigningKeyPairFactory();
    if (version == Version_V4) {
        // V4
        _shared_secret = ISharedSecret::getInstance(_specification->algorithm());
        _key_provider = std::make_shared<v4::KeyProviderV4>(self);
        _key_provider->asService()->restoreSensitiveData();
        _vault_service = std::make_shared<VaultService>(self, version);
        _encryptor_factory = std::make_shared<v4::AeadEncryptorFactory>(self);
        _activation_service = std::make_shared<v4::ActivationServiceV4>(self);
        _auth_service = std::make_shared<v4::AuthenticationServiceV4>(self);
        _token_service = std::make_shared<v4::TokenServiceV4>(self);
    } else {
        // V3
        _shared_secret = nullptr;
        _key_provider = std::make_shared<v3::KeyProviderV3>(self);
        _vault_service = std::make_shared<VaultService>(self, version);
        _encryptor_factory = std::make_shared<v3::EciesEncryptorFactory>(self);
        _activation_service = std::make_shared<v3::ActivationServiceV3>(self);
        _auth_service = std::make_shared<v3::AuthenticationServiceV3>(self);
        _token_service = std::make_shared<v3::TokenServiceV3>(self);
    }
    // Common
    _signature_service = std::make_shared<SignatureService>(self);
    
    // register services
    _services.push_back(_key_provider->asService());
    _services.push_back(_encryptor_factory->asService());
    _services.push_back(_activation_service->asService());
    _services.push_back(_auth_service->asService());
    _services.push_back(_token_service->asService());
    _services.push_back(_vault_service);
    _services.push_back(_signature_service);
}

void Context::destroyServices()
{
    for (auto& service : _services) {
        service->destroyService();
    }
    _services.clear();
    _shared_secret = nullptr;
}

// MARK: - Public interface

void Context::clearSensitiveData()
{
    for (auto& service : _services) {
        service->clearSensitiveData();
    }
}

void Context::clearActivationData()
{
    for (auto& service : _services) {
        service->clearActivationData();
    }
}

void Context::restoreSensitiveData()
{
    for (auto& service : _services) {
        service->restoreSensitiveData();
    }
}

void Context::updateAfterProtocolVersionChange()
{
    destroyServices();
    createServices(false, _session_data->getCurrentSpecification());
}

void Context::resetState() {
    clearActivationData();
    destroyServices();
    createServices(false, _session_data->getCurrentSpecification());
}

bool Context::hasProtocolUpgradePending() const noexcept
{
    return _session_data->hasUpgradeData() || _session_data->hasUpgradePendingFlag();
}

} // namespace powerAuth
