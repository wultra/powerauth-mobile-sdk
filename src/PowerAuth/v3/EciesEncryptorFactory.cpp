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

#include "EciesEncryptorFactory.h"
#include "EciesEncryptor.h"
#include "../Context.h"
#include "../request/RequestBuilder.h"
#include "../request/EndpointSpec.h"

#include <cc7/jwt/Jwt.h>

using namespace cc7;

namespace powerAuth {
namespace v3 {

// MARK: - EciesEncryptorFactory

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

const TimeInterval EciesEncryptorFactory::KEY_EXPIRATION_THRESHOLD = 10.0;
const size_t EciesEncryptorFactory::GET_TEMP_KEY_CHALLENGE_SIZE = 18;

EciesEncryptorFactory::EciesEncryptorFactory(const ContextPtr & context) :
    Service("EciesEncryptorFactory", context->getSharedMutexPtr()),
    _context(context),
    _configuration(context->getConfigurationPtr()),
    _session_data(context->getSessionDataPtr()),
    _key_provider(context->getKeyProviderPtr()),
    _time_service(context->getTimeServicePtr()),
    _application_key_info({EncryptorScope::APPLICATION}),
    _activation_key_info({EncryptorScope::ACTIVATION})
{
    if (_key_provider->protocolVersion() != Version_V3) {
        throw Exception(EC_InternalError, "Unsupported key provider");
    }
}

// MARK: - Service

void EciesEncryptorFactory::doServiceDestroy()
{
    resetAllData();
}

// MARK: - Public functions

IServicePtr EciesEncryptorFactory::asService()
{
    return shared_from_this();
}

void EciesEncryptorFactory::resetAllData()
{
    LOCK_GUARD();
    checkNotDestroyed();
    clearDataForScope(EncryptorScope::APPLICATION);
}

void EciesEncryptorFactory::resetActivationData()
{
    LOCK_GUARD();
    checkNotDestroyed();
    clearDataForScope(EncryptorScope::ACTIVATION);
}

bool EciesEncryptorFactory::hasTemporaryKey(EncryptorScope scope)
{
    LOCK_GUARD();
    checkNotDestroyed();
    auto& ki = keyInfo(scope);
    if (ki.isValid()) {
        if (!ki.isExpired(_time_service->currentTime())) {
            return true;
        }
        ki.clear();
    }
    return false;
}

void EciesEncryptorFactory::deleteTemporaryKey(EncryptorScope scope)
{
    LOCK_GUARD();
    checkNotDestroyed();
    auto& ki = keyInfo(scope);
    if (ki.isValid()) {
        ki.clear();
    }
}

RequestPtr EciesEncryptorFactory::getTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    checkNotDestroyed();
    if (auto context = _context.lock()) {
        auto self = shared_from_this();
        return RequestBuilder(*context, v3::Endpoint_TemporaryKey)
            .withJson(self->createTemporaryKeyRequest(scope))
            .withResponseCallback([self, scope](const Request& req, const json::JsonValue& resp) -> ResponseObjectPtr {
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
    } else {
        throw Exception(EC_NotAllowed, "Session object is destroyed");
    }
}

bool EciesEncryptorFactory::hasPendingTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    checkNotDestroyed();
    return keyInfo(scope).hasPendingRequest();
}

IClientEncryptorPtr EciesEncryptorFactory::getClientEncryptor(EncryptorId encryptor_id)
{
    LOCK_GUARD();
    checkNotDestroyed();
    auto spec = EncryptorSpec::specForId(encryptor_id);
    auto& ki = validKeyInfo(spec->scope);
    auto parameters = EncryptorParameters::makeParameters(Version_V3,
                                                          encryptor_id,
                                                          _configuration->applicationKey(),
                                                          _configuration->applicationSecret(),
                                                          ki.keyIdentifier,
                                                          activationId());

    ByteArray transport_key;
    if (spec->isActivationScoped()) {
        transport_key = _key_provider->unlockSecretKeys()->legacyKeyTransport();
    }

    auto secrets = ECIES_MakeClientSecrets(*parameters, *ki.publicKey, transport_key);

    return std::make_shared<EciesClientEncryptor>(parameters,
                                                  secrets,
                                                  _time_service);
}

// MARK: - Private request - response

cc7::json::JsonValue EciesEncryptorFactory::createTemporaryKeyRequest(EncryptorScope scope)
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
        auto challenge = crypto::GetRandomData(GET_TEMP_KEY_CHALLENGE_SIZE).base64();
        // Build request structure
        GetTemporaryKeyRequest request {
            _configuration->applicationKey(),
            activation_id,
            challenge,
        };
        // At first, clear possible existing and valid key.
        clearDataForScope(scope);

        // Now store the creation data.
        ki.creationData = std::unique_ptr<GetKeyData>(new GetKeyData {
            _time_service->startTimeSynchronizationTask(),
            request
        });

        auto secrets = _key_provider->unlockSecretKeys();
        // begin secrets
        auto mac_key = act_scope ? secrets->keyMacGetActTempKey() : secrets->keyMacGetAppTempKey();

        auto jwt = jwt::JwtWriter()
            .withJsonPayload(request.toJson())
            .sign({ jwt::JwtKey::symmetricKey("HS256", mac_key) })
            .toCompact();
        
        // end secrets
        _key_provider->lockSecretKeys(secrets);

        // Build request payload
        return json::JsonValue::object({
            { "jwt",  json::JsonValue(jwt) }
        });
    } catch (...) {
        Exception::reThrowWrapped(EC_InternalError, "Failed to generate get temporary key request");
    }
}

static jwt::JwtKeyList _BuildKeyList(const cc7::crypto::PublicKey& pub_key)
{
    auto key_obj = std::dynamic_pointer_cast<crypto::PublicKey>(pub_key.duplicate());
    return { jwt::JwtKey::publicKey(key_obj) };
}

void EciesEncryptorFactory::completeTemporaryKeyRequest(EncryptorScope scope, const cc7::json::JsonValue & json)
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
        auto payload = jwt::JwtReader::fromCompact(json["jwt"].asString())
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
            throw Exception(EC_InternalError, "ActivationID from response is no longer valid");
        }

        _time_service->completeTimeSynchronizationTask(cdata.timeSynchronization, 0.001 * response.serverTime);

        // Store all data
        ki.created = TimestampToTimeInterval(response.serverTime);
        ki.expires = TimestampToTimeInterval(response.expiration);
        ki.keyIdentifier = response.keyId;

        ki.publicKey = crypto::PublicKey::getInstance("P-256");
        ki.publicKey->importKeyFromBase64(response.publicKey, crypto::KEY_FORMAT_X963);

        // Reset information about pending request
        ki.creationData = nullptr;
        // Success
    } catch (...) {
        // Clear key info in case of failure
        clearDataForScope(scope);
        std::rethrow_exception(std::current_exception());
    }
}

void EciesEncryptorFactory::cancelPendingTemporaryKeyRequest(EncryptorScope scope)
{
    LOCK_GUARD();
    auto& ki = keyInfo(scope);
    if (ki.hasPendingRequest()) {
        clearDataForScope(scope);
    }
}

json::JsonValue EciesEncryptorFactory::GetTemporaryKeyRequest::toJson() const noexcept
{
    auto root = json::JsonValue::object();
    root.insert("applicationKey", json::JsonValue(applicationKey));
    root.insert("challenge", json::JsonValue(challenge));
    if (!activationId.empty()) {
        root.insert("activationId", json::JsonValue(activationId));
    }
    return root;
}

EciesEncryptorFactory::GetTemporaryKeyResponse EciesEncryptorFactory::GetTemporaryKeyResponse::fromJson(const cc7::json::JsonValue &json)
{
    return {
        json["applicationKey"].asString(),
        json.containsValueAtPath("activationId") ? json["activationId"].asString() : std::string(),
        json["challenge"].asString(),
        json["sub"].asString(),     // keyId
        json["publicKey"].asString(),
        json["exp_ms"].asInteger(), // expiration
        json["iat_ms"].asInteger()  // server time
    };
}


// MARK: - Private functions

std::string EciesEncryptorFactory::activationId() const noexcept
{
    if (_session_data->hasPersistentData() && _session_data->getProtocolVersion() == Version_V3) {
        return _session_data->persistentData().v3().activationId;
    }
    return std::string();
}

const EciesEncryptorFactory::TemporaryKeyData& EciesEncryptorFactory::keyInfo(EncryptorScope scope) const noexcept
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

EciesEncryptorFactory::TemporaryKeyData& EciesEncryptorFactory::keyInfo(EncryptorScope scope) noexcept
{
    switch (scope) {
        case EncryptorScope::APPLICATION: return _application_key_info;
        case EncryptorScope::ACTIVATION: return _activation_key_info;
    }
}

EciesEncryptorFactory::TemporaryKeyData& EciesEncryptorFactory::validKeyInfo(EncryptorScope scope)
{
    auto& ki = keyInfo(scope);
    if (ki.isExpired(_time_service->currentTime())) {
        ki.clear();
        throw Exception(EC_NotAllowed, "Temporary key is not valid or is expired");
    }
    if (ki.keyScope == EncryptorScope::ACTIVATION && !_session_data->hasPersistentData()) {
        ki.clear();
        throw Exception(EC_MissingActivation, "Temporary key cannot be accessed due to missing activation");
    }
    return ki;
}

void EciesEncryptorFactory::clearDataForScope(EncryptorScope scope)
{
    checkNotDestroyed();
    if (scope == EncryptorScope::APPLICATION) {
        _application_key_info.clear();
    }
    // Selecting APPLICATION scope means that we have to also clear activation's data.
    _activation_key_info.clear();
}


// MARK: - TemporaryKeyData

bool EciesEncryptorFactory::TemporaryKeyData::isValid() const noexcept
{
    return !(keyIdentifier.empty() || !publicKey || created < 0.0 || expires < 0.0);
}

bool EciesEncryptorFactory::TemporaryKeyData::isExpired(TimeInterval now) const noexcept
{
    if (isValid()) {
        return now >= expires - KEY_EXPIRATION_THRESHOLD;
    }
    return true;
}

bool EciesEncryptorFactory::TemporaryKeyData::hasPendingRequest() const noexcept
{
    return creationData != nullptr;
}

void EciesEncryptorFactory::TemporaryKeyData::clear() noexcept
{
    publicKey = nullptr;
    keyIdentifier.clear();
    created = -1;
    expires = -1;
    creationData = nullptr;
}

} // namespace v3
} // namespace powerAuth
