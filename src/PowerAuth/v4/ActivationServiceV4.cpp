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
    
    // Store received User Info into Session Data
    auto user_info = L1_data.findValueAtPath("userInfo");
    _session_data->setUserInfo(user_info ? *user_info : cc7::json::JsonValue());
    
    return std::make_shared<ActivationResult>(calculateActivationFingerprint(), L1_data);
}

RequestPtr ActivationServiceV4::confirmActivation(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto request = cc7::json::JsonValue::object({
        { "enableBiometry", cc7::json::JsonValue(credentials->hasBiometryKEK()) }
    });
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_ActivationConfirm)
        .withJson(request)
        .withAuthentication(Credentials::knowledge(credentials->knowledgeKEK()))
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
            common::ExportKeyToNormalizedForm(HybridKey_GetKey1(device_public_key)),
            cc7::MakeRange(activation_id),
            common::ExportKeyToNormalizedForm(HybridKey_GetKey1(server_public_key))
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
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_ActivationStatus)
        .withResponseCallback([self, context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseActivationStatus(*context, body);
        })
        .build();
}

ResponseObjectPtr ActivationServiceV4::processResponseActivationStatus(Context &context, const cc7::json::JsonValue &response)
{
    LOCK_GUARD();
    // Extract values
    auto status_blob = response["activationStatus"].asBase64();
    auto custom_object = response.containsValueAtPath("customObject", cc7::json::JsonValue::Object) ? response["customObject"] : cc7::json::JsonValue::object();
    if (status_blob.size() < v4::STATUS_BLOB_SIZE + v4::STATUS_MAC_SIZE) {
        throw Exception(EC_InvalidData, "Binary status blob is too short");
    }
    // Verify status MAC
    auto status_blob_data = status_blob.byteRange().subRangeTo(v4::STATUS_BLOB_SIZE);
    auto status_blob_mac  = status_blob.byteRange().subRangeFrom(v4::STATUS_BLOB_SIZE);
        
    auto& keyProvider = context.keyProvider();
    auto secrets = keyProvider.unlockSecretKeys();
    auto verified = algorithms().v4.kmac256().verifyToken(secrets->keyMacStatus(), status_blob_data, status_blob_mac, {
        { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take(v4::STATUS_MAC_SIZE) },
        { cc7::crypto::MAC_PARAM_CUSTOM_STRING, cc7::crypto::Parameter::ref("PA4MAC-STATUS") }
    });
    cc7::ByteArray key_mac_ctr_data = secrets->keyMacCtrData();
    keyProvider.lockSecretKeys(secrets);
    if (!verified) {
        throw Exception(EC_InvalidData, "Activation status MAC is not valid");
    }
    
    // Parse binary data
    auto binary_data = ActivationStatus::parseStatusBlobV4(status_blob_data);
    ActivationState local_state;
    switch (binary_data.state) {
        case ActivationStatus::ServerState_PendingCommit:
            local_state = ActivationState::PendingCommit;
            break;
        case ActivationStatus::ServerState_Active:
            local_state = ActivationState::Active;
            break;
        case ActivationStatus::ServerState_Blocked:
            local_state = ActivationState::Blocked;
            break;
        case ActivationStatus::ServerState_Removed:
            local_state = ActivationState::Removed;
            break;
        default:
            throw Exception(EC_InvalidData, "Unsupported activation state in binary status blob");
    }

    // try synchronize counter
    auto counter_state = trySynchronizeCounter(binary_data, key_mac_ctr_data);
    if (counter_state == ActivationStatus::CounterState_Invalid) {
        // force state to deadlock
        local_state = ActivationState::Deadlock;
    }
    // Check counter synchronization
    return std::make_shared<ActivationStatus>(Version_V4, local_state, counter_state, binary_data, custom_object);
}

int ActivationServiceV4::calculateHashCounterDistance(cc7::ByteArray& local_ctr_data,
                                 const cc7::ByteRange& server_ctr_data_hash,
                                 const cc7::ByteRange& key_ctr_data,
                                 int max_iterations)
{
    const cc7::crypto::ParameterList params {
        { cc7::crypto::MAC_PARAM_CUSTOM_STRING, cc7::crypto::Parameter::ref("PA4MAC-CTR") },
        { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take((size_t)32) }
    };
    const auto& kmac = algorithms().v4.kmac256();
    const auto& hash = algorithms().v4.sha3_256();
    int iteration = 0;
    while (max_iterations > 0) {
        auto local_ctr_data_hash = kmac.token(key_ctr_data, local_ctr_data, params);
        if (local_ctr_data_hash == server_ctr_data_hash) {
            return iteration;
        }
        // next counter value
        local_ctr_data = hash.digest(local_ctr_data);
        ++iteration;
        --max_iterations;
    }
    return -1;
}

ActivationStatus::CounterState ActivationServiceV4::trySynchronizeCounter(const ActivationStatus::BinaryData& data, const cc7::ByteRange& key_ctr_data)
{
    auto has_pd = _session_data->hasPersistentData();
    const int look_ahead_window = data.lookAheadCount;
    auto local_ctr_byte = has_pd
                            ? _session_data->persistentData().v4().authCodeCounterByte
                            : _session_data->registrationData().v4().authCodeCounterByte;
    auto local_ctr_data = has_pd
                            ? _session_data->persistentData().v4().authCodeCounterData
                            : _session_data->registrationData().v4().authCodeCounterData;
    // Calculate hash counters distance
    auto hash_distance = calculateHashCounterDistance(local_ctr_data, data.counterHash, key_ctr_data, look_ahead_window);
    // Calculate byte counters distance
    auto byte_distance = common::CalculateDistanceBetweenByteCounters(local_ctr_byte, data.counterByte);
    if (hash_distance == 0 && byte_distance == 0) {
        // Everything's OK
        return ActivationStatus::CounterState_OK;
    }
    if (byte_distance > 0 && hash_distance == -1) {
        // Client's ahead. Determine for how much and decide the synchronization result.
        if (byte_distance > look_ahead_window) {
            // We cannot recover from this state. Client is too much ahead against the server.
            // The activation is technically blocked.
            return ActivationStatus::CounterState_Invalid;
        }
        if (byte_distance > look_ahead_window / 2) {
            // The local counter is more than half the allowed interval ahead to server.
            // It's recommended to calculate some signature soon.
            return ActivationStatus::CounterState_CalculateAuthCode;
        }
        // Counter will be synchronized automatically
        return ActivationStatus::CounterState_OK;
    }
    if (-byte_distance == hash_distance) {
        // hash distance is always greater than 0, but byte distance is negative in case that server's ahead.
        // We have last matched CTR_DATA value in local_ctr_data variable.
        if (has_pd) {
            auto& pd = _session_data->persistentData().v4();
            pd.authCodeCounterData = local_ctr_data;
            pd.authCodeCounterByte = data.counterByte;
            // Report that persistent data should be saved
            return ActivationStatus::CounterState_Updated;
        }
        // We're still in the middle of the registration process, do we don't need to
        // persist the data. Just update the counter.
        auto& rd = _session_data->registrationData().v4();
        rd.authCodeCounterData = local_ctr_data;
        rd.authCodeCounterByte = data.counterByte;
        return ActivationStatus::CounterState_OK;
    }
    // Looks like that counters cannot be synchronized and the activation is technically blocked.
    return ActivationStatus::CounterState_Invalid;
}

RequestPtr ActivationServiceV4::removeActivation(CredentialsPtr credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_ActivationRemove)
        .withAuthentication(credentials)
        .withResponseCallback([self](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            self->resetState();
            return nullptr;
        })
        .build();
}

// MARK: - Factors

RequestPtr ActivationServiceV4::changePassword(PasswordPtr old_password, PasswordPtr new_password)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto old_credentials = Credentials::knowledge(old_password->passwordData());
    auto new_credentials = Credentials::knowledge(new_password->passwordData());
    SharedSecretRequest ss_request;
    SharedSecretContextPtr ss_context;
    std::tie(ss_request, ss_context) = context->sharedSecret().generateRequestCryptogram();
    auto self = shared_from_this();
    return RequestBuilder(*context, Endpoint_PasswordChange)
        .withJson(ss_request.toJson())
        .withAuthentication(old_credentials)
        .withResponseCallback([self, context, ss_context, old_credentials, new_credentials](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseChangePassword(*context, ss_context, body, old_credentials, new_credentials);
        })
        .build();
}

ResponseObjectPtr ActivationServiceV4::processResponseChangePassword(Context &context,
                                                                     SharedSecretContextPtr ss_context,
                                                                     const cc7::json::JsonValue &response,
                                                                     CredentialsPtr old_credentials,
                                                                     CredentialsPtr new_credentials)
{
    LOCK_GUARD();
    auto ss_response = SharedSecretResponse::fromJson(response);
    auto new_knowledge_factor = context.sharedSecret().computeSharedSecret(ss_context, ss_response);
    auto& key_provider = context.keyProvider();
    
    auto secrets = key_provider.unlockSecretKeys(*old_credentials);
    secrets->updateKeyAuthenticationCodeKnowledge(new_knowledge_factor, new_credentials->knowledgeKEK());
    key_provider.lockSecretKeys(secrets);
    
    return nullptr;
}

RequestPtr ActivationServiceV4::addBiometricFactor(PasswordPtr password, const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    auto context = lockContext();
    SharedSecretRequest ss_request;
    SharedSecretContextPtr ss_context;
    std::tie(ss_request, ss_context) = context->sharedSecret().generateRequestCryptogram();
    auto self = shared_from_this();
    cc7::ByteArray new_kek = new_biometry_kek;
    return RequestBuilder(*context, Endpoint_BiometryAdd)
        .withJson(ss_request.toJson())
        .withAuthentication(Credentials::knowledge(password->passwordData()))
        .withResponseCallback([self, context, ss_context, new_kek](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseAddBiometricFactor(*context, ss_context, body, new_kek);
        })
        .build();
}

ResponseObjectPtr ActivationServiceV4::processResponseAddBiometricFactor(Context &context,
                                                                         SharedSecretContextPtr ss_context,
                                                                         const cc7::json::JsonValue &response,
                                                                         const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    auto ss_response = SharedSecretResponse::fromJson(response);
    auto new_biometry_factor = context.sharedSecret().computeSharedSecret(ss_context, ss_response);
    
    auto& key_provider = context.keyProvider();
    auto secrets = key_provider.unlockSecretKeys();
    secrets->updateKeyAuthenticationCodeBiometry(new_biometry_factor, new_biometry_kek);
    key_provider.lockSecretKeys(secrets);
    return nullptr;
}

RequestPtr ActivationServiceV4::removeBiometricFactor()
{
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_BiometryRemove)
        .withAuthentication(Credentials::possession())
        .withResponseCallback([self, context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            self->doRemoveBiometricFactor(*context);
            return nullptr;
        })
        .build();
}

void ActivationServiceV4::doRemoveBiometricFactor(Context& context)
{
    LOCK_GUARD();
    auto& key_provider = context.keyProvider();
    auto secrets = key_provider.unlockSecretKeys();
    secrets->removeKeyAuthenticationCodeBiometry();
    key_provider.lockSecretKeys(secrets);
}

// MARK: - User Info

RequestPtr ActivationServiceV4::fetchUserInfo()
{
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_UserInfo)
        .withResponseCallback([self, context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            context->sessionData().setUserInfo(body);
            return nullptr;
        })
        .build();
}

} // namespace v4
} // namespace powerAuth
