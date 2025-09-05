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

#include <PowerAuth/Session.h>
#include "task/GetActivationStatusTask.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

Session::Session(ContextPtr context) :
    _lock(context->getSharedMutexPtr()),
    _context(context)
{
}

SessionPtr Session::createInstance(ConfigurationPtr configuration)
{
    auto context = Context::getInstance(configuration);
    return std::make_shared<Session>(context);
}

// MARK: - State

ProtocolVersion Session::getProtocolVersion() const noexcept
{
    LOCK_GUARD();
    return _context->protocolVersion();
}

ConstPowerAuthSpecPtr Session::getPowerAuthSpec() const noexcept
{
    LOCK_GUARD();
    return _context->specification();
}

const ConfigurationPtr& Session::getConfiguration() const noexcept
{
    // Configuration is immutable, we don't need to acquire lock.
    return _context->getConfigurationPtr();
}

SessionData& Session::sessionData() noexcept
{
    return _context->sessionData();
}

const SessionData& Session::sessionData() const noexcept
{
    return _context->sessionData();
}


// MARK: - State serialization

bool Session::isModifiedState() const noexcept
{
    LOCK_GUARD();
    return sessionData().isModified();
}

void Session::loadState(const cc7::ByteRange &serialized_state)
{
    LOCK_GUARD();
    auto& sd = sessionData();
    auto spec_before = sd.getCurrentSpecification();
    sd.deserialize(serialized_state);
    if (spec_before != sd.getCurrentSpecification()) {
        _context->updateAfterProtocolVersionChange();
    }
    _context->restoreSensitiveData();
}

cc7::ByteArray Session::saveState()
{
    LOCK_GUARD();
    return sessionData().serialize();
}

void Session::resetState()
{
    LOCK_GUARD();
    _context->activationService().resetState();
}


// MARK: - Activation

bool Session::canCreateActivation() const noexcept
{
    LOCK_GUARD();
    const auto& sd = sessionData();
    return !sd.hasRegistrationData() && !sd.hasPersistentData();
}

bool Session::hasPendingCreateActivation() const noexcept
{
    LOCK_GUARD();
    return sessionData().hasRegistrationData();
}

RequestPtr Session::createActivation(const cc7::json::JsonValue& L1_data, const cc7::json::JsonValue& L2_data)
{
    LOCK_GUARD();
    if (!canCreateActivation()) {
        throw Exception(EC_WrongActivationState, "Cannot create activation");
    }
    return _context->activationService().createActivation(L1_data, L2_data);
}

RequestPtr Session::confirmActivation(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    // Validate credentials in advance. This is typically done also in key provider,
    // but we don't want to wait for the response from the server.
    credentials->validate(_context->protocolVersion());
    auto& sd = sessionData();
    if (!sd.hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. There's no pending activation");
    }
    auto& rd = sd.registrationData();
    if (rd.getActivationId().empty()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. Key-exchange is not completed yet");
    }
    return _context->activationService().confirmActivation(credentials);
}

bool Session::hasValidActivationData() const noexcept
{
    LOCK_GUARD();
    return sessionData().hasPersistentData();
}

std::string Session::activationId() const noexcept
{
    LOCK_GUARD();
    try {
        return sessionData().getActivationId();
    } catch (...) {
        return std::string();
    }
}

std::string Session::activationFingerprint() const noexcept
{
    LOCK_GUARD();
    try {
        const auto& sd = sessionData();
        if (sd.hasPersistentData() || sd.hasRegistrationData()) {
            return _context->activationService().calculateActivationFingerprint();
        }
    } catch (...) {
        // do nothing...
    }
    return std::string();
}

TaskPtr Session::fetchActivationStatus()
{
    LOCK_GUARD();
    checkActivationData();
    return std::make_shared<GetActivationStatusTask>(_context);
}

RequestPtr Session::removeActivation(const CredentialsPtr& credentials)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->activationService().removeActivation(credentials);
}

RequestPtr Session::verifyPassword(const PasswordPtr &password)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->authenticationService().verifyPassword(*password);
}

RequestPtr Session::changePassword(const PasswordPtr& old_password, const PasswordPtr& new_password)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->activationService().changePassword(old_password, new_password);
}

bool Session::hasBiometricFactor() const
{
    LOCK_GUARD();
    checkActivationData();
    return sessionData().persistentData().hasBiometricFactorKey();
}

RequestPtr Session::addBiometricFactor(const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    checkActivationData();
    if (sessionData().persistentData().hasBiometricFactorKey()) {
        throw Exception(EC_NotAllowed, "Biometric factor is already set");
    }
    // Check inputs in advance
    Credentials::validatePassword(*password);
    Credentials::validateFactorKek(new_biometry_kek, _context->protocolVersion());
    return _context->activationService().addBiometricFactor(password, new_biometry_kek);
}

RequestPtr Session::removeBiometricFactor()
{
    LOCK_GUARD();
    checkActivationData();
    if (!sessionData().persistentData().hasBiometricFactorKey()) {
        throw Exception(EC_NotAllowed, "Biometric factor is not set");
    }
    return _context->activationService().removeBiometricFactor();
}

void Session::checkActivationData() const
{
    if (!sessionData().hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
}

// MARK: - Authentication

HttpHeader Session::calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                                        const std::string_view& uri_identifier,
                                                        const std::string_view& http_method,
                                                        const cc7::ByteRange& request_body)
{
    LOCK_GUARD();
    return _context->authenticationService().calculateOnlineAuthenticationHeader(credentials, {
        uri_identifier,
        http_method,
        false,
        false
    }, request_body);
}


std::string Session::calculateOfflineAuthenticationCode(const Credentials& credentials,
                                                        const std::string_view& uri_identifier,
                                                        const std::string_view& offline_nonce,
                                                        const cc7::ByteRange& data,
                                                        size_t code_length)
{
    LOCK_GUARD();
    return _context->authenticationService().calculateOfflineAuthenticationCode(credentials, {
        uri_identifier,
        offline_nonce,
        code_length
    }, data);
}

// MARK: - Tokens

HttpHeader Session::calculateTokenHeader(const std::string_view &token_identifier,
                                         const cc7::ByteRange &token_secret)
{
    LOCK_GUARD();
    return _context->tokenService().calculateTokenHeader({ token_identifier, token_secret });
}

RequestPtr Session::createAccessToken(const CredentialsPtr &credentials)
{
    LOCK_GUARD();
    return _context->tokenService().createAccessToken(credentials);
}

RequestPtr Session::removeAccessToken(const std::string_view &token_identifier)
{
    LOCK_GUARD();
    return _context->tokenService().removeAccessToken(token_identifier);
}

// MARK: - Services

const TimeServicePtr& Session::getTimeService() const noexcept
{
    return _context->getTimeServicePtr();
}

const IClientEncryptorFactoryPtr& Session::getEncryptorFactory() const noexcept
{
    LOCK_GUARD();
    return _context->getEncryptorFactoryPtr();
}

const IAuthenticationServicePtr& Session::getAuthenticationService() const noexcept
{
    LOCK_GUARD();
    return _context->getAuthenticationServicePtr();
}

const ITokenServicePtr& Session::getTokenService() const noexcept
{
    LOCK_GUARD();
    return _context->getTokenServicePtr();
}

// Private service functions

IKeyProvider& Session::keyProvider() noexcept
{
    return _context->keyProvider();
}

IClientEncryptorFactory& Session::encryptorFactory() noexcept
{
    return _context->encryptorFactory();
}

} // namespace powerAuth
