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

#include <PowerAuth/EncryptorFactory.h>
#include <PowerAuth/Exception.h>

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)


// MARK: - EncryptorFactory

const Timestamp EncryptorFactory::KEY_EXPIRATION_THRESHOLD = 10000;
const size_t EncryptorFactory::GET_TEMP_KEY_CHALLENGE_SIZE = 32;

EncryptorFactory::EncryptorFactory(ConfigurationPtr configuration,
                                   ISharedSecretPtr shared_secret_algorithm,
                                   TimeServicePtr time_service,
                                   SharedMutexPtr shared_mutex) :
    _lock(shared_mutex == nullptr ? std::make_shared<SharedMutex>() : shared_mutex),
    _configuration(configuration),
    _time_service(time_service),
    _shared_secret_algorithm(shared_secret_algorithm),
    _application_key_info({ EncryptorScope::APPLICATION, DefaultNonceGenerator::getInstance(12) }),
    _activation_key_info({ EncryptorScope::ACTIVATION, DefaultNonceGenerator::getInstance(12) })
{
}

void EncryptorFactory::resetAllData()
{
    LOCK_GUARD();
    clearDataForScope(EncryptorScope::APPLICATION, false);
}

void EncryptorFactory::resetActivationData()
{
    LOCK_GUARD();
    clearDataForScope(EncryptorScope::ACTIVATION, false);
}

void EncryptorFactory::deleteTemporaryKey(EncryptorScope scope)
{
    LOCK_GUARD();
    keyInfo(scope).clear();
}

void EncryptorFactory::setActivationId(const std::string &activation_id)
{
    LOCK_GUARD();
    _activation_id = activation_id;
    resetActivationData();
}

// Getting temporary key

bool EncryptorFactory::hasTemporaryKey(EncryptorScope scope)
{
    LOCK_GUARD();
    auto& ki = keyInfo(scope);
    if (ki.isValid()) {
        if (!ki.isExpired(_time_service->currentTimeMillis())) {
            return true;
        }
        ki.clear();
    }
    return false;
}

GetTemporaryKeyRequest EncryptorFactory::getTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    const bool act_scope = scope == EncryptorScope::ACTIVATION;
    auto& ki = keyInfo(scope);
    if (ki.hasPendingRequest()) {
        throw Exception(EC_NotAllowed, "There's already pending request for temporary key");
    }
    if (act_scope && _activation_id.empty()) {
        throw Exception(EC_MissingActivation, "Activation is required for activation scoped temporary key");
    }
    // Generate shared info cryptogram and context
    auto secret_data = _shared_secret_algorithm->generateRequestCryptogram();
    // Prepare challenge
    auto challenge = cc7::crypto::GetRandomData(GET_TEMP_KEY_CHALLENGE_SIZE).base64();
    // Build request structure
    GetTemporaryKeyRequest request {
        _configuration->applicationKey(),
        act_scope ? _activation_id : "",
        challenge,
        secret_data.first
    };
    // At first, clear possible existing and valid key.
    clearDataForScope(scope, true);
    
    // Now store the creation data.
    ki.creationData = std::shared_ptr<GetKeyData>(new GetKeyData {
        _time_service->startTimeSynchronizationTask(),
        request,
        secret_data.second
    });
    return request;
}

bool EncryptorFactory::hasPendingTemporaryKeyRequest(EncryptorScope scope) const
{
    LOCK_GUARD();
    return keyInfo(scope).hasPendingRequest();
}

void EncryptorFactory::completeTemporaryKeyRequest(const GetTemporaryKeyResponse & response)
{
    LOCK_GUARD();
    // Validate input structure
    
    // The scope is determined by the presence of activation identifier.
    const auto act_scope = !response.activationId.empty();
    auto scope = act_scope ? EncryptorScope::ACTIVATION : EncryptorScope::APPLICATION;
    auto& ki = keyInfo(scope);
    if (!ki.hasPendingRequest()) {
        throw Exception(EC_NotAllowed, "There's no pending request for temporary key");
    }
    try {
        auto& cdata = *ki.creationData;
        auto valid_response = response.challenge == cdata.request.challenge &&
                              response.applicationKey == cdata.request.applicationKey &&
                             (act_scope ? response.activationId == cdata.request.activationId : true) &&
                             !response.keyId.empty();
        if (!valid_response) {
            ki.clear();
            throw Exception(EC_Cryptography, "Request and Response data doesn't match");
        }
        if (act_scope && _activation_id != response.activationId) {
            ki.clear();
            // This makes no sense, but it seems that
            throw Exception(EC_InternalError, "ActivationID from response is no longer valid");
        }
        _time_service->completeTimeSynchronizationTask(cdata.timeSynchronization, 0.001 * response.serverTime);
        auto secret = _shared_secret_algorithm->computeSharedSecret(cdata.sharedSecretContext, response.sharedSecretResponse);
        // Store all data
        ki.created = 0.001 * response.serverTime;
        ki.expires = 0.001 * response.expiration;
        ki.sharedSecret = secret;
        ki.keyIdentifier = response.keyId;
        // Reset information about pending request
        ki.creationData = nullptr;
        // Success
    } catch (...) {
        // Clear key info in case of failure
        clearDataForScope(scope, true);
        std::rethrow_exception(std::current_exception());
    }
}

void EncryptorFactory::cancelPendingTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    auto& ki = keyInfo(scope);
    if (ki.hasPendingRequest()) {
        clearDataForScope(scope, true);
    } else {
        CC7_LOG("Warning: There's no pending request for temporary key");
    }
}

// Getting encryptor

ClientEncryptorPtr EncryptorFactory::getClientEncryptor(EncryptorId encryptor_id)
{
    LOCK_GUARD();
//    const auto spec = EncryptorSpec::specForId(encryptor_id);
//    auto& ki = validKeyInfo(spec->scope);
    throw std::logic_error("Not implemented");
}

// MARK: Private functions

const EncryptorFactory::TemporaryKeyData& EncryptorFactory::keyInfo(EncryptorScope scope) const
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

EncryptorFactory::TemporaryKeyData& EncryptorFactory::keyInfo(EncryptorScope scope)
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

EncryptorFactory::TemporaryKeyData& EncryptorFactory::validKeyInfo(EncryptorScope scope)
{
    auto& ki = keyInfo(scope);
    if (ki.isExpired(_time_service->currentTimeMillis())) {
        ki.clear();
        throw Exception(EC_NotAllowed, "Temporary key is not valid or is expired");
    }
    if (ki.keyScope == EncryptorScope::ACTIVATION && _activation_id.empty()) {
        ki.clear();
        throw Exception(EC_MissingActivation, "Temporary key cannot be accessed due to missing activation");
    }
    return ki;
}

void EncryptorFactory::clearDataForScope(EncryptorScope scope, bool key_data_only)
{
    const bool clear_all = scope == EncryptorScope::APPLICATION;
    if (clear_all) {
        _application_key_info.clear();
    }
    if (clear_all || !key_data_only) {
        _activation_id.clear();
    }
    // Selecting APPLICATION scope means that we have to also clear activation's data.
    _activation_key_info.clear();
}



// MARK: TemporaryKeyInfo

bool EncryptorFactory::TemporaryKeyData::isValid() const
{
    return !(keyIdentifier.empty() || sharedSecret.empty() || created < 0.0 || expires < 0.0);
}

bool EncryptorFactory::TemporaryKeyData::isExpired(TimeInterval now) const
{
    if (isValid()) {
        return now >= expires - KEY_EXPIRATION_THRESHOLD;
    }
    return true;
}

bool EncryptorFactory::TemporaryKeyData::hasPendingRequest() const
{
    return creationData != nullptr;
}

void EncryptorFactory::TemporaryKeyData::clear()
{
    sharedSecret.secureClear();
    nonceGenerator->resetSavedState();
    keyIdentifier.clear();
    created = -1;
    expires = -1;
    creationData = nullptr;
}

} // namespace powerAuth
