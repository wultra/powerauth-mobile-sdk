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


#include "AeadEncryptorFactory.h"
#include "AeadEncryptor.h"
#include "../Context.h"
#include "../request/RequestBuilder.h"
#include "../request/EndpointSpec.h"

#include <cc7/jwt/Jwt.h>

using namespace cc7;

namespace powerAuth {
namespace v4 {

// MARK: - AeadEncryptorFactory

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

const Timestamp AeadEncryptorFactory::KEY_EXPIRATION_THRESHOLD = 10000;
const size_t AeadEncryptorFactory::GET_TEMP_KEY_CHALLENGE_SIZE = 32;

AeadEncryptorFactory::AeadEncryptorFactory(Context& context) :
    _lock(context.getSharedMutexPtr()),
    _configuration(context.getConfigurationPtr()),
    _session_data(context.getSessionDataPtr()),
    _key_provider(context.getKeyProviderPtr()),
    _time_service(context.getTimeServicePtr()),
    _shared_secret_algorithm(context.getSharedSecretPtr()),
    _application_key_info({EncryptorScope::APPLICATION}),
    _activation_key_info({EncryptorScope::ACTIVATION})
{
    if (_key_provider->protocolVersion() != Version_V4) {
        throw Exception(EC_InternalError, "Unsupported key provider");
    }
}

// MARK: - Public functions

void AeadEncryptorFactory::resetAllData()
{
    LOCK_GUARD();
    clearDataForScope(EncryptorScope::APPLICATION, false);
}

void AeadEncryptorFactory::resetActivationData()
{
    LOCK_GUARD();
    clearDataForScope(EncryptorScope::ACTIVATION, false);
}

bool AeadEncryptorFactory::hasTemporaryKey(EncryptorScope scope) noexcept
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

void AeadEncryptorFactory::deleteTemporaryKey(EncryptorScope scope)
{
    LOCK_GUARD();
    auto& ki = keyInfo(scope);
    if (ki.isValid()) {
        ki.clear();
    }
}

IClientEncryptorPtr AeadEncryptorFactory::getClientEncryptor(EncryptorId encryptor_id)
{
    LOCK_GUARD();
    auto spec = EncryptorSpec::specForId(encryptor_id);
    auto& ki = validKeyInfo(spec->scope);
    auto request_response_nonce = ConcatByteRanges({
        ki.nonceGenerator->getNonce(),
        ki.nonceGenerator->getNonce()
    });
    auto parameters = EncryptorParameters::makeParameters(Version_V4,
                                                          encryptor_id,
                                                          _configuration->applicationKey(),
                                                          _configuration->applicationSecret(),
                                                          ki.keyIdentifier,
                                                          activationId());
    ByteArray e2ee_shared_info2_key;
    if (spec->isActivationScoped()) {
        e2ee_shared_info2_key = _key_provider->unlockSecretKeys()->keyE2EESharedInfo2();
    }
    auto secrets = AEAD_BuildSecrets(*parameters, ki.sharedSecret, e2ee_shared_info2_key);
    return std::make_shared<AeadClientEncryptor>(parameters,
                                                 secrets,
                                                 request_response_nonce,
                                                 _time_service);
}

RequestPtr AeadEncryptorFactory::getTemporaryKeyRequest(Context& context, EncryptorScope scope)
{
    LOCK_GUARD();
    auto self = shared_from_this();
    return RequestBuilder(context, v4::Endpoint_TemporaryKey)
        .withJson(createTemporaryKeyRequest(scope))
        .withResponseCallback([self, scope](const Request& req, const cc7::json::JsonValue& resp) -> ResponseObjectPtr {
            self->completeTemporaryKeyRequest(scope, resp);
            // There's no external object created as a result of the response processing. Everything is encryptor's
            // internal data.
            return nullptr;
        })
        .withCancelCallback([self, scope]() {
            // the request has been canceled
            self->cancelPendingTemporaryKeyRequest(scope);
        })
        .build();
}

bool AeadEncryptorFactory::hasPendingTemporaryKeyRequest(EncryptorScope scope) noexcept
{
    LOCK_GUARD();
    return keyInfo(scope).hasPendingRequest();
}


// MARK: - Private request - response

cc7::json::JsonValue AeadEncryptorFactory::createTemporaryKeyRequest(EncryptorScope scope)
{
    const bool act_scope = scope == EncryptorScope::ACTIVATION;
    auto& ki = keyInfo(scope);
    if (ki.hasPendingRequest()) {
        throw Exception(EC_NotAllowed, "There's already pending request for temporary key");
    }
    auto activation_id = activationId();
    if (act_scope && activation_id.empty()) {
        throw Exception(EC_MissingActivation, "Activation is required for activation scoped temporary key");
    }
    try {
        // Generate shared info cryptogram and context
        auto secret_data = _shared_secret_algorithm->generateRequestCryptogram();
        // Prepare challenge
        auto challenge = crypto::GetRandomData(GET_TEMP_KEY_CHALLENGE_SIZE).base64();
        // Build request structure
        GetTemporaryKeyRequest request {
            _configuration->applicationKey(),
            activation_id,
            challenge,
            secret_data.first
        };
        // At first, clear possible existing and valid key.
        clearDataForScope(scope, true);
        
        // Now store the creation data.
        ki.creationData = std::unique_ptr<GetKeyData>(new GetKeyData {
            _time_service->startTimeSynchronizationTask(),
            request,
            secret_data.second
        });
        
        auto secrets = _key_provider->unlockSecretKeys();
        // begin secrets
        auto mac_key = act_scope ? secrets->keyMacGetActTempKey() : secrets->keyMacGetAppTempKey();
        // end secrets
        _key_provider->lockSecretKeys(secrets);
        
        auto jwt = jwt::JwtWriter()
            .withJsonPayload(request.toJson())
            .sign({ jwt::JwtKey::symmetricKey("HS256", mac_key) })
            .toCompact();
        
        // Build request payload
        return json::JsonValue::object({
            { "jwt",  json::JsonValue(jwt) }
        });
    } catch (...) {
        Exception::reThrowWrapped(EC_InternalError, "Failed to generate get temporary key request");
    }
}

/// Convert hybrid public key into list of JwtKey objects.
/// - Parameter pub_key: Hybrid public key.
static jwt::JwtKeyList _BuildKeyList(const cc7::crypto::PublicKey& pub_key)
{
    jwt::JwtKeyList list;
    auto key_obj = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(pub_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
    list.push_back(jwt::JwtKey::publicKey(key_obj));
    key_obj = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(pub_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
    if (key_obj) {
        list.push_back(jwt::JwtKey::publicKey(key_obj));
    }
    return list;
}

void AeadEncryptorFactory::completeTemporaryKeyRequest(EncryptorScope scope, const cc7::json::JsonValue & json)
{
    LOCK_GUARD();
    // Validate input structure
    const auto act_scope = scope == EncryptorScope::ACTIVATION;
    auto& ki = keyInfo(scope);
    if (!ki.hasPendingRequest()) {
        throw Exception(EC_NotAllowed, "There's no pending request for temporary key");
    }
    try {
        // verify JWS signatures
        auto jws_key_list = _BuildKeyList(act_scope ? _key_provider->serverPublicKey() : _key_provider->masterServerPublicKey());
        auto payload = jwt::JwtReader::fromJson(json["jwt"])
            .verify(jws_key_list)
            .getPayload();
        
        // Decode response structure
        auto response = GetTemporaryKeyResponse::fromJson(json::JsonReader::fromJsonData(payload));

        // Validate input structure
        auto& cdata = *ki.creationData;
        auto valid_response = response.challenge == cdata.request.challenge &&
                              response.applicationKey == cdata.request.applicationKey &&
                             (act_scope ? response.activationId == cdata.request.activationId : true) &&
                             !response.keyId.empty();
        if (!valid_response) {
            ki.clear();
            throw Exception(EC_Cryptography, "Request and Response data doesn't match");
        }
        if (act_scope && activationId() != response.activationId) {
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

void AeadEncryptorFactory::cancelPendingTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    auto& ki = keyInfo(scope);
    if (ki.hasPendingRequest()) {
        clearDataForScope(scope, true);
    }
}

json::JsonValue AeadEncryptorFactory::GetTemporaryKeyRequest::toJson() const noexcept
{
    auto root = json::JsonValue::object();
    root.insert("applicationKey", json::JsonValue(applicationKey));
    root.insert("challenge", json::JsonValue(challenge));
    if (!activationId.empty()) {
        root.insert("activationId", json::JsonValue(activationId));
    }
    root.insert("sharedSecretRequest", sharedSecretRequest.toJson());
    return root;
}

AeadEncryptorFactory::GetTemporaryKeyResponse AeadEncryptorFactory::GetTemporaryKeyResponse::fromJson(const cc7::json::JsonValue &json)
{
    return {
        json["applicationKey"].asString(),
        json.containsValueAtPath("activationId") ? json["activationId"].asString() : std::string(),
        json["challenge"].asString(),
        json["keyId"].asString(),
        SharedSecretResponse::fromJson(json["sharedSecretResponse"]),
        json["expiration"].asInteger(),
        json["serverTime"].asInteger()
    };
}

// MARK: - Private functions

std::string AeadEncryptorFactory::activationId() const noexcept
{
    if (_session_data->hasPersistentData() && _session_data->getProtocolVersion() == Version_V4) {
        return _session_data->persistentData().v4().activationId;
    }
    return std::string();
}

const AeadEncryptorFactory::TemporaryKeyData& AeadEncryptorFactory::keyInfo(EncryptorScope scope) const noexcept
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

AeadEncryptorFactory::TemporaryKeyData& AeadEncryptorFactory::keyInfo(EncryptorScope scope) noexcept
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

AeadEncryptorFactory::TemporaryKeyData& AeadEncryptorFactory::validKeyInfo(EncryptorScope scope)
{
    auto& ki = keyInfo(scope);
    if (ki.isExpired(_time_service->currentTimeMillis())) {
        ki.clear();
        throw Exception(EC_NotAllowed, "Temporary key is not valid or is expired");
    }
    if (ki.keyScope == EncryptorScope::ACTIVATION && !_session_data->hasPersistentData()) {
        ki.clear();
        throw Exception(EC_MissingActivation, "Temporary key cannot be accessed due to missing activation");
    }
    return ki;
}

void AeadEncryptorFactory::clearDataForScope(EncryptorScope scope, bool key_data_only)
{
    // TODO: key_data_only param?
    if (scope == EncryptorScope::APPLICATION) {
        _application_key_info.clear();
    }
    // Selecting APPLICATION scope means that we have to also clear activation's data.
    _activation_key_info.clear();
}



// MARK: - TemporaryKeyData

bool AeadEncryptorFactory::TemporaryKeyData::isValid() const noexcept
{
    return !(keyIdentifier.empty() || sharedSecret.empty() || created < 0.0 || expires < 0.0);
}

bool AeadEncryptorFactory::TemporaryKeyData::isExpired(TimeInterval now) const noexcept
{
    if (isValid()) {
        return now >= expires - KEY_EXPIRATION_THRESHOLD;
    }
    return true;
}

bool AeadEncryptorFactory::TemporaryKeyData::hasPendingRequest() const noexcept
{
    return creationData != nullptr;
}

void AeadEncryptorFactory::TemporaryKeyData::clear() noexcept
{
    sharedSecret.secureClear();
    nonceGenerator->resetSavedState();
    keyIdentifier.clear();
    created = -1;
    expires = -1;
    creationData = nullptr;
}

} // namespace v4
} // namespace powerAuth

