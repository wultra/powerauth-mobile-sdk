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

namespace powerAuth {

// MARK: - Configuration

ProtocolVersion Context::protocolVersion() const noexcept
{
    return _specification->protocolVersion();
}

const Configuration& Context::configuration() const noexcept
{
    return *_configuration;
}

PowerAuthSpecPtr Context::specification() const noexcept
{
    return _specification;
}


// MARK: - Basic services

TimeService& Context::timeService()
{
    return *_time_service;
}

IClientEncryptorFactory& Context::encryptorFactory()
{
    return *_encryptor_factory;
}

ISharedSecret& Context::sharedSecret()
{
    if (_specification->protocolVersion() == Version_V3) {
        throw Exception(EC_InternalError, "ISharedSecret is not available in legacy protocol");
    }
    return *_shared_secret;
}

cc7::crypto::KeyPairFactory& Context::signingKeyPairFactory()
{
    return *_signing_keys_factory;
}

IKeyProvider& Context::keyProvider()
{
    return *_key_provider;
}

SessionData& Context::sessionData()
{
    return *_session_data;
}

// MARK: - Object pointers

const SharedMutexPtr Context::getSharedMutexPtr() const noexcept
{
    return _shared_mutex;
}

const ConfigurationPtr& Context::getConfigurationPtr() const noexcept
{
    return _configuration;
}

const SessionDataPtr& Context::getSessionDataPtr() const noexcept
{
    return _session_data;
}

const TimeServicePtr& Context::getTimeServicePtr() const noexcept
{
    return _time_service;
}

const IClientEncryptorFactoryPtr& Context::getEncryptorFactoryPtr() const noexcept
{
    return _encryptor_factory;
}

const ISharedSecretPtr& Context::getSharedSecretPtr() const noexcept
{
    return _shared_secret;
}

const IKeyProviderPtr& Context::getKeyProviderPtr() const noexcept
{
    return _key_provider;
}

const IAuthHeaderCalculatorPtr& Context::getAuthHeaderCalculatorPtr() const noexcept
{
    return _auth_header_calculator;
}

const cc7::crypto::KeyPairFactoryPtr& Context::getSigningKeyPairFactoryPtr() const noexcept
{
    return _signing_keys_factory;
}


// MARK: - Construction

Context::Context(PowerAuthSpecPtr specification, ConfigurationPtr configuration) :
    _shared_mutex(std::make_shared<std::recursive_mutex>()),
    _configuration(configuration),
    _specification(specification)
{
}

ContextPtr Context::getInstance(PowerAuthSpec::Algorithm algorithm, ConfigurationPtr configuration)
{
    auto spec = PowerAuthSpec::specForAlgorithm(algorithm);
    if (!spec) {
        throw Exception(EC_InternalError, "Unknown PowerAuth algorithm");
    }
    auto context = std::make_shared<Context>(spec, configuration);
    context->createBasicServices(true);
    return context;
}

void Context::createBasicServices(bool initial_setup)
{
    auto self = shared_from_this();
    if (initial_setup) {
        // Initial objects construction
        _time_service = std::make_shared<TimeService>(self);
        _signing_keys_factory = _specification->getSigningKeyPairFactory();
    }
    _session_data = std::make_shared<SessionData>();
    if (protocolVersion() == Version_V4) {
        // V4
        _key_provider = std::make_shared<v4::KeyProviderV4>(self);
        _encryptor_factory = std::make_shared<v4::AeadEncryptorFactory>(self);
        _shared_secret = SharedSecret::getInstance(specification()->sharedSecret());
    } else {
        // V3
        throw Exception(EC_InternalError, "V3 is not implemented yet");
    }
    
    _services.push_back(_key_provider->asService());
    _services.push_back(_encryptor_factory->asService());
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

void Context::restoreSensitiveData()
{
    for (auto& service : _services) {
        service->restoreSensitiveData();
    }
}

void Context::updateAfterProtocolVersionChange()
{
    PowerAuthSpecPtr new_spec = _session_data->getSpecification();
    if (!new_spec) {
        // No persistent data available, fallback to specification from the configuration.
        new_spec = PowerAuthSpec::specForAlgorithm(_configuration->algorithm());
    }
    _specification = new_spec;
    destroyServices();
    createBasicServices(false);
}    

} // namespace powerAuth
