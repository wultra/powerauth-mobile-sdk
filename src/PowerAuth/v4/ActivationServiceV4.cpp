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

#include "ActivationServiceV4.h"
#include "HybridKeyPair.h"
#include "../request/RequestBuilder.h"
#include "../common/CommonFunctions.h"

namespace powerAuth {
namespace v4 {

// MARK: - Construction

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

ActivationServiceV4::ActivationServiceV4(const ContextPtr& context) :
    Service("ActivationServiceV4", context->getSharedMutexPtr()),
    _weak_context(context),
    _session_data(context->getSessionDataPtr())
{
}

ProtocolVersion ActivationServiceV4::protocolVersion() const noexcept
{
    return Version_V4;
}

IServicePtr ActivationServiceV4::asService()
{
    return shared_from_this();
}

ContextPtr ActivationServiceV4::lockContext()
{
    if (auto context = _weak_context.lock()) {
        return context;
    }
    throw Exception(EC_InternalError, "Parent Session object is destroyed");
}

// MARK: - Activation creation

RequestPtr ActivationServiceV4::createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto new_rd = RegistrationData::create(Version_V4);
    _session_data->setRegistrationData(new_rd);
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_ActivationCreate)
        .withPrepareCallback([self, L1_data, L2_data, context](const Request& request) -> cc7::json::JsonValue {
            return self->prepareRequestActivationData(*context, L1_data, L2_data);
        })
        .withResponseCallback([self, context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseActivationData(*context, body);
        })
        .withCancelCallback([self]() {
            self->resetState();
        })
        .build();
}

cc7::json::JsonValue ActivationServiceV4::prepareRequestActivationData(Context& context, cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    auto& rd = _session_data->registrationData().v4();
    
    // generate device public key-pairs
    rd.deviceKeyPair = context.getSigningKeyPairFactoryPtr()->generateKeyPair();
    // prepare shared secret
    auto shared_secret = context.sharedSecret().generateRequestCryptogram();
    
    rd.sharedSecretAlgorithm = context.getSharedSecretPtr();
    rd.sharedSecretContext   = shared_secret.second;
    
    // Prepare L2 data
    L2_data["sharedSecretRequest"] = shared_secret.first.toJson();
    L2_data["devicePublicKeys"]    = v4::HybridKey_ToJson(rd.deviceKeyPair->getPublicKey(), context.specification());
    
    // Encrypt L2 data  
    rd.requestEncryptor = context.encryptorFactory().getClientEncryptor(EncryptorId::ACTIVATION_LAYER_2);
    auto L2_request_cryptogram = rd.requestEncryptor->encryptJsonRequest(L2_data);
    
    // Prepare L1 data
    L1_data["activationData"]      = L2_request_cryptogram.requestPayload;
    return L1_data;
}

ResponseObjectPtr ActivationServiceV4::processResponseActivationData(Context& context, const cc7::json::JsonValue& L1_data)
{
    LOCK_GUARD();
    auto& rd = _session_data->registrationData().v4();
    
    // Decrypt L2 data
    auto L2_data = rd.requestEncryptor->decryptJsonResponse({ L1_data["activationData"] });
    
    // Extract public keys and calculate shared secret
    auto server_public_key = v4::HybridKey_FromJson(L2_data["serverPublicKeys"], *context.getSigningKeyPairFactoryPtr());
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
    
    return std::make_shared<ActivationResult>(calculateActivationFingerprint(), L1_data);
}

RequestPtr ActivationServiceV4::confirmActivation(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto request = cc7::json::JsonValue::object({
        { "enableBiometry", cc7::json::JsonValue(credentials->hasBiometryKEK()) }
    });
    auto auth = Credentials::knowledge(credentials->knowledgeKEK());
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_ActivationConfirm)
        .withJson(request)
        .withAuthentication(auth)
        .withResponseCallback([self, credentials, context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseActivationConfirm(*context, credentials);
        })
        .build();
}

ResponseObjectPtr ActivationServiceV4::processResponseActivationConfirm(Context& context, InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto& rd = _session_data->registrationData().v4();
    auto& keyProvider = context.keyProvider();
    
    if (rd.calculatedSharedSecret.empty()) {
        throw Exception(EC_InternalError, "Shared secret is not calculated");
    }

    auto secrets = keyProvider.unlockInitialSecretKeys(*credentials, rd.calculatedSharedSecret);
    // We don't need to use initial secrets at all. The operation is automatically done in the key provider,
    // which is responsible for the persistent data creation at the operation end.
    keyProvider.lockSecretKeys(secrets);
    
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_InternalError, "PersistentData not created after lock");
    }

    // No specific object is created at the end
    return nullptr;
}

std::string ActivationServiceV4::calculateActivationFingerprint()
{
    LOCK_GUARD();
    if (!_activation_fingerprint.empty()) {
        return _activation_fingerprint;
    }
    auto context = lockContext();
    auto& keyProvider = context->keyProvider();
    _activation_fingerprint = calculateActivationFingerprint(*context, keyProvider.devicePublicKey(), keyProvider.serverPublicKey());
    return _activation_fingerprint;
}

std::string ActivationServiceV4::calculateActivationFingerprint(Context& context,
                                                                const cc7::crypto::PublicKey& device_public_key,
                                                                const cc7::crypto::PublicKey& server_public_key) const
{
    auto spec = context.specification();
    if (spec->isLegacy()) {
        throw Exception(EC_InternalError, "V3 algorithm not supported");
    }
    auto activation_id = _session_data->getActivationId();
    const auto& algorithm = spec->algorithmName();
    cc7::ByteArray activation_data;
    if (spec->isHybrid()) {
        activation_data = cc7::ConcatByteRanges({
            cc7::MakeRange(algorithm),
            common::ExportKeyToNormalizedForm(HybridKey_GetKey1(device_public_key)),
            common::ExportKeyToNormalizedForm(HybridKey_GetKey2(device_public_key)),
            cc7::MakeRange(activation_id),
            common::ExportKeyToNormalizedForm(HybridKey_GetKey1(server_public_key)),
            common::ExportKeyToNormalizedForm(HybridKey_GetKey2(server_public_key))
        });
    } else {
        activation_data = cc7::ConcatByteRanges({
            cc7::MakeRange(algorithm),
            common::ExportKeyToNormalizedForm(device_public_key),
            cc7::MakeRange(activation_id),
            common::ExportKeyToNormalizedForm(server_public_key)
        });
    }
    auto hash = algorithms().v4.sha3_256().digest(activation_data);
    return common::CalculateHumanReadableCodeFromHash(hash, common::ACTIVATION_FINGERPRINT_LENGTH);
}

// MARK: - Status

void ActivationServiceV4::resetState()
{
    LOCK_GUARD();
    _session_data->resetSessionData();
    _activation_fingerprint.clear();
}

RequestPtr ActivationServiceV4::fetchActivationStatus()
{
    throw Exception(EC_InternalError, "TODO");
}

RequestPtr ActivationServiceV4::removeActivation(CredentialsPtr credentials)
{
    throw Exception(EC_InternalError, "TODO");
}

RequestPtr ActivationServiceV4::changePassword(PasswordPtr old_password, PasswordPtr new_password)
{
    throw Exception(EC_InternalError, "TODO");
}

// MARK: - Factors

RequestPtr ActivationServiceV4::addBiometricFactor(PasswordPtr password)
{
    throw Exception(EC_InternalError, "TODO");
}

RequestPtr ActivationServiceV4::removeBiometricFactor()
{
    throw Exception(EC_InternalError, "TODO");
}

} // namespace v4
} // namespace powerAuth
