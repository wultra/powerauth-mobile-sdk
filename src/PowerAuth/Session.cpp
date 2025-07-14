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
#include "Context.h"
#include "request/RequestBuilder.h"
#include "v4/HybridKeyPair.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

Session::Session(ContextPtr context) :
    _lock(context->getSharedMutexPtr()),
    _context(context)
{
}

SessionPtr Session::createInstance(ConfigurationPtr configuration)
{
    auto context = Context::getInstance(configuration->algorithm(), configuration);
    return std::make_shared<Session>(context);
}

// MARK: - State

ProtocolVersion Session::getProtocolVersion() const noexcept
{
    LOCK_GUARD();
    return sessionData().getProtocolVersion();
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


void Session::loadState(const cc7::ByteRange &serialized_state)
{
    LOCK_GUARD();
    auto pv_before = sessionData().getProtocolVersion();
    sessionData().deserialize(serialized_state);
    if (pv_before != sessionData().getProtocolVersion()) {
        _context->updateAfterProtocolVersionChange();
    }
}

cc7::ByteArray Session::saveState()
{
    LOCK_GUARD();
    return sessionData().serialize();
}

void Session::resetState()
{
    LOCK_GUARD();
    sessionData().resetSessionData();
}

// MARK: - Activation

bool Session::canCreateActivation() const noexcept
{
    LOCK_GUARD();
    const auto& sd = sessionData();
    return !sd.hasRegistrationData() && !sd.hasPersistentData();
}

RequestPtr Session::createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    if (!canCreateActivation()) {
        throw Exception(EC_WrongActivationState, "Cannot create activation");
    }
    auto new_rd = RegistrationData::create(Version_V4);
    sessionData().setRegistrationData(new_rd);
    auto self = shared_from_this();
    return RequestBuilder(*_context, v4::Endpoint_ActivationCreate)
        .withJson(L1_data)
        .withPrepareCallback([self, L1_data, L2_data](const Request& request) -> cc7::json::JsonValue {
            return self->prepareRequestActivationData(L1_data, L2_data);
        })
        .withResponseCallback([self](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseActivationData(body);
        })
        .withCancelCallback([self]() {
            self->resetState();
        })
        .build();
}

cc7::json::JsonValue Session::prepareRequestActivationData(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    auto& rd = sessionData().registrationData().v4();
    
    // generate device public key-pairs
    rd.deviceKeyPair = _context->getSigningKeyPairFactoryPtr()->generateKeyPair();
    // prepare shared secret
    auto shared_secret = _context->sharedSecret().generateRequestCryptogram();
    
    rd.sharedSecretAlgorithm = _context->getSharedSecretPtr();
    rd.sharedSecretContext   = shared_secret.second;
    
    // Prepare L2 data
    L2_data["sharedSecretRequest"] = shared_secret.first.toJson();
    L2_data["devicePublicKeys"]    = v4::HybridKey_ToJson(rd.deviceKeyPair->getPublicKey(), _context->specification());
    
    // Encrypt L2 data
    rd.requestEncryptor = encryptorFactory().getClientEncryptor(EncryptorId::ACTIVATION_LAYER_2);
    auto L2_request_cryptogram = rd.requestEncryptor->encryptJsonRequest(L2_data);
    
    // Prepare L1 data
    L1_data["activationData"]      = L2_request_cryptogram.requestPayload;
    return L1_data;
}

ResponseObjectPtr Session::processResponseActivationData(const cc7::json::JsonValue& L1_data)
{
    LOCK_GUARD();
    auto& rd = sessionData().registrationData().v4();
    
    // Decrypt L2 data
    auto L2_data = rd.requestEncryptor->decryptJsonResponse({ L1_data["activationData"] });
    
    // Extract public keys and calculate shared secret
    auto server_public_key = v4::HybridKey_FromJson(L2_data["serverPublicKeys"], *_context->getSigningKeyPairFactoryPtr());
    auto shared_secret     = rd.sharedSecretAlgorithm->computeSharedSecret(rd.sharedSecretContext, SharedSecretResponse::fromJson(L2_data["sharedSecretResponse"]));
    
    // Extract other values
    auto activation_id = L2_data["activationId"].asString();
    auto ctr_data = L2_data["ctrData"].asBase64();
    if (activation_id.empty() || ctr_data.size() != v4::HASH_COUNTER_SIZE) {
        throw Exception(EC_InvalidData, "Invalid activation data");
    }
    // Keep values in RD
    rd.activationId             = activation_id;
    rd.authCodeCounterData      = ctr_data;
    rd.serverPublicKey          = server_public_key;
    rd.calculatedSharedSecret   = shared_secret;
    // Clear shared secret context and algorithm
    rd.sharedSecretContext = nullptr;
    rd.sharedSecretAlgorithm = nullptr;
    
    return nullptr;
}


RequestPtr Session::confirmActivation(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto& sd = sessionData();
    if (!sd.hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. There's no pending activation");
    }
    auto& rd = sd.registrationData().v4();
    if (rd.activationId.empty()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. Key-exchange is not completed yet");
    }
    auto request = cc7::json::JsonValue::object({
        { "enableBiometry", cc7::json::JsonValue(credentials->hasBiometryKEK()) }
    });
    auto auth = Credentials::knowledge(credentials->knowledgeKEK());
    
    auto self = shared_from_this();
    return RequestBuilder(*_context, v4::Endpoint_ActivationConfirm)
        .withJson(request)
        .withAuthentication(auth)
        .withResponseCallback([self, credentials](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseActivationConfirm(credentials);
        })
        .build();
}

ResponseObjectPtr Session::processResponseActivationConfirm(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto& rd = sessionData().registrationData().v4();
    
    if (rd.calculatedSharedSecret.empty()) {
        throw Exception(EC_InternalError, "Shared secret is not calculated");
    }

    auto secrets = keyProvider().unlockInitialSecretKeys(*credentials, rd.calculatedSharedSecret);
    // We don't need to use initial secrets at all. The operation is automatically done in the key provider,
    // which is responsible for the persistent data creation at the operation end.
    keyProvider().lockSecretKeys(secrets);
    
    if (!sessionData().hasPersistentData()) {
        throw Exception(EC_InternalError, "PersistentData not created after lock");
    }

    // No specific object is created at the end
    return nullptr;
}

bool Session::hasValidActivationData() const noexcept
{
    LOCK_GUARD();
    return sessionData().hasPersistentData();
}

std::string Session::activationId() const noexcept
{
    LOCK_GUARD();
    const auto& sd = sessionData();
    if (sd.hasPersistentData()) {
        return sd.persistentData().getActivationId();
    }
    return std::string();
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
