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

#include "ActivationServiceV3.h"
#include "../request/RequestBuilder.h"
#include "../common/CommonFunctions.h"
#include "./LegacyKDF.h"
#include "FunctionsV3.h"

namespace powerAuth {
namespace v3 {

// MARK: - Construction

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

ActivationServiceV3::ActivationServiceV3(const ContextPtr& context) :
    Service("ActivationServiceV3", context->getSharedMutexPtr()),
    _weak_context(context),
    _session_data(context->getSessionDataPtr())
{
}

ProtocolVersion ActivationServiceV3::protocolVersion() const noexcept
{
    return Version_V3;
}

IServicePtr ActivationServiceV3::asService()
{
    return shared_from_this();
}

ContextPtr ActivationServiceV3::lockContext()
{
    if (auto context = _weak_context.lock()) {
        return context;
    }
    throw Exception(EC_InternalError, "Parent Session object is destroyed");
}

// MARK: - Activation creation

RequestPtr ActivationServiceV3::createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto new_rd = RegistrationData::create(Version_V3);
    _session_data->setRegistrationData(new_rd);
    auto self = shared_from_this();
    return RequestBuilder(*context, v3::Endpoint_ActivationCreate)
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

cc7::json::JsonValue ActivationServiceV3::prepareRequestActivationData(Context& context, cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data)
{
    LOCK_GUARD();
    auto& rd = _session_data->registrationData().v3();
    
    // generate device public key-pairs
    rd.deviceKeyPair = context.getSigningKeyPairFactoryPtr()->generateKeyPair();
    
    // Prepare L2 data
    L2_data["devicePublicKey"] = cc7::json::JsonValue::base64(rd.deviceKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963));
    
    // Encrypt L2 data
    rd.requestEncryptor = context.encryptorFactory().getClientEncryptor(EncryptorId::ACTIVATION_LAYER_2);
    auto L2_request_cryptogram = rd.requestEncryptor->encryptJsonRequest(L2_data);
    
    // Prepare L1 data
    L1_data["activationData"] = L2_request_cryptogram.requestPayload;
    return L1_data;
}

ResponseObjectPtr ActivationServiceV3::processResponseActivationData(Context& context, const cc7::json::JsonValue& L1_data)
{
    LOCK_GUARD();
    auto& rd = _session_data->registrationData().v3();
    
    // Decrypt L2 data
    auto L2_data = rd.requestEncryptor->decryptJsonResponse({ L1_data["activationData"] });
    
    // Extract public key
    auto server_public_key = context.getSigningKeyPairFactoryPtr()->newPublicKey();
    server_public_key->importKey(L2_data["serverPublicKey"].asBase64(), cc7::crypto::KEY_FORMAT_X963);
    
    // Extract other values
    auto activation_id = L2_data["activationId"].asString();
    auto ctr_data = L2_data["ctrData"].asBase64();
    if (activation_id.empty() || ctr_data.size() != v3::HASH_COUNTER_SIZE) {
        throw Exception(EC_InvalidData, "Invalid activation data");
    }
    
    // Keep values in RD
    rd.activationId             = activation_id;
    rd.authCodeCounterData      = ctr_data;
    rd.serverPublicKey          = server_public_key;
    
    return std::make_shared<ActivationResult>(calculateActivationFingerprint(), L1_data);
}

std::string ActivationServiceV3::calculateActivationFingerprint()
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

std::string ActivationServiceV3::calculateActivationFingerprint(Context& context,
                                                                const cc7::crypto::PublicKey& device_public_key,
                                                                const cc7::crypto::PublicKey& server_public_key) const
{
    auto spec = context.specification();
    if (!spec->isLegacy()) {
        throw Exception(EC_InternalError, "Only V3 algorithm is supported");
    }
    
    cc7::ByteArray fingerprint_data = cc7::ConcatByteRanges({
        common::ExportKeyToNormalizedForm(device_public_key),
        cc7::MakeRange(_session_data->getActivationId()),
        common::ExportKeyToNormalizedForm(server_public_key)
    });
    
    auto hash = algorithms().v3.sha256().digest(fingerprint_data);
    return common::CalculateHumanReadableCodeFromHash(hash, v3::ACTIVATION_FINGERPRINT_SIZE);
}

RequestPtr ActivationServiceV3::confirmActivation(InitialCredentialsPtr credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto& keyProvider = context->keyProvider();
    
    auto secrets = keyProvider.unlockInitialSecretKeys(*credentials, cc7::ByteRange());
    // We don't need to use initial secrets at all. The operation is automatically done in the key provider,
    // which is responsible for the persistent data creation at the operation end.
    keyProvider.lockSecretKeys(secrets);
    
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_InternalError, "PersistentData not created after lock");
    }
    
    // No activation confirm endpoint is defined for V3
    return nullptr;
}

// MARK: - Status

void ActivationServiceV3::resetState()
{
    LOCK_GUARD();
    _session_data->resetSessionData();
}

RequestPtr ActivationServiceV3::fetchActivationStatus()
{
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    
    auto challenge = cc7::crypto::GetRandomData(v3::STATUS_BLOB_CHALLENGE_SIZE);
    return RequestBuilder(*context, v3::Endpoint_ActivationStatus)
        .withJson(cc7::json::JsonValue::object({
            {"activationId", cc7::json::JsonValue(_session_data->getActivationId())},
            {"challenge", cc7::json::JsonValue(challenge.base64())}
        }))
        .withCustomParameter(cc7::crypto::Parameter::copy(challenge))
        .withResponseCallback([self, context](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
            return self->processResponseActivationStatus(*context, request, response);
        })
        .build();
}

ResponseObjectPtr ActivationServiceV3::processResponseActivationStatus(Context& context, const Request& request, const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    
    // Extract values
    auto challenge = request.getCustomParameter().asByteRange();
    auto activation_id = response["activationId"].asString();
    if (activation_id != _session_data->getActivationId()) {
        throw Exception(EC_InvalidData, "Unexpected activation ID");
    }
    
    auto& keyProvider = context.keyProvider();
    auto secrets = keyProvider.unlockSecretKeys();
    auto status_blob = decryptActivationStatusBlob(response, challenge, secrets);
    if (status_blob.size() != v3::STATUS_BLOB_SIZE) {
        throw Exception(EC_InvalidData, "Invalid size of binary status blob");
    }

    auto custom_object = response.containsValueAtPath("customObject", cc7::json::JsonValue::Object) ? response["customObject"] : cc7::json::JsonValue::object();
    
    // Parse binary status blob
    auto binary_data = ActivationStatus::parseStatusBlobV3(status_blob);

    // Try synchronize counter
    auto counter_state = trySynchronizeCounter(binary_data, secrets->keyMacCtrData());
    
    keyProvider.lockSecretKeys(secrets);

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
    
    if (counter_state == ActivationStatus::CounterState_Invalid) {
        // force state to deadlock
        local_state = ActivationState::Deadlock;
    }
    
    // Check counter synchronization
    return std::make_shared<ActivationStatus>(Version_V3, local_state, counter_state, binary_data, custom_object);
}

cc7::ByteArray ActivationServiceV3::decryptActivationStatusBlob(const cc7::json::JsonValue& response, const cc7::ByteRange& challenge, const ISecretKeysPtr& secrets)
{
    auto nonce = response["nonce"].asBase64();
    if (nonce.size() != v3::STATUS_BLOB_NONCE_SIZE) {
        throw Exception(EC_InvalidData, "Invalid size of status blob nonce");
    }
    auto encrypted_status_blob = response["encryptedStatusBlob"].asBase64();
    
    auto status_iv_data = cc7::ConcatByteRanges({challenge, nonce});
    auto status_iv = algorithms().v3.kdfInternal().derive(secrets->legacyKeyTransportIV(), status_iv_data);

    return algorithms().v3.aes128cbcNoPad().decrypt(secrets->legacyKeyTransport(), status_iv, encrypted_status_blob);
}

ActivationStatus::CounterState ActivationServiceV3::trySynchronizeCounter(const ActivationStatus::BinaryData& data, const cc7::ByteRange& key_ctr_data)
{
    auto& pd = _session_data->persistentData().v3();
    auto local_ctr_data = pd.authCodeCounterData;
    const int look_ahead_window = data.lookAheadCount;
    
    // Calculate hash counters distance
    auto hash_distance = calculateHashCounterDistance(local_ctr_data, data.counterHash, key_ctr_data, look_ahead_window);
    // Calculate byte counters distance
     auto byte_distance = common::CalculateDistanceBetweenByteCounters(pd.authCodeCounterByte, data.counterByte);
    
    if (hash_distance == 0 && byte_distance == 0) {
        // Everything's OK.
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
        pd.authCodeCounterData = local_ctr_data;
        pd.authCodeCounterByte = data.counterByte;
        // Report that persistent data should be saved now.
        return ActivationStatus::CounterState_Updated;
    }
    
    // Looks like that counters cannot be synchronized and the activation is technically blocked.
    return ActivationStatus::CounterState_Invalid;
}

int ActivationServiceV3::calculateHashCounterDistance(cc7::ByteArray& local_ctr_data,
                                                      const cc7::ByteRange& server_ctr_data_hash,
                                                      const cc7::ByteRange& key_ctr_data,
                                                      int max_iterations)
{
    const auto& sha256 = algorithms().v3.sha256();
    
    int iteration = 0;
    while (max_iterations > 0) {
        auto local_ctr_data_hash = DeriveSecretKeyFromIndex(key_ctr_data, local_ctr_data);
        if (local_ctr_data_hash == server_ctr_data_hash) {
            return iteration;
        }
        
        local_ctr_data = ReduceSharedSecret(sha256.digest(local_ctr_data));
        ++iteration;
        --max_iterations;
    }
    return -1;
}

// MARK: - Remove

RequestPtr ActivationServiceV3::removeActivation(CredentialsPtr credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto self = shared_from_this();
    
    return RequestBuilder(*context, v3::Endpoint_ActivationRemove)
        .withAuthentication(credentials)
        .withResponseCallback([self](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            self->resetState();
            return nullptr;
        })
        .build();
}

// MARK: - Factors

RequestPtr ActivationServiceV3::changePassword(PasswordPtr old_password, PasswordPtr new_password)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto& key_provider = context->keyProvider();
    
    auto old_credentials = Credentials::knowledge(old_password->passwordData());
    auto new_credentials = Credentials::knowledge(new_password->passwordData());
    
    auto secrets = key_provider.unlockSecretKeys(*old_credentials);
    secrets->updateKeyAuthenticationCodeKnowledge(cc7::ByteRange(), new_credentials->knowledgeKEK());
    key_provider.lockSecretKeys(secrets);
    
    return nullptr;
}

RequestPtr ActivationServiceV3::addBiometricFactor(PasswordPtr password, const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    auto context = lockContext();
    
    auto credentials = Credentials::knowledge(password->passwordData());
    
    auto self = shared_from_this();
    cc7::ByteArray new_kek = new_biometry_kek;
    return RequestBuilder(*context, v3::Endpoint_VaultUnlock)
        .withJson(cc7::json::JsonValue::object({
            {"reason", cc7::json::JsonValue("ADD_BIOMETRY")}
        }))
        .withAuthentication(credentials)
        .withResponseCallback([self, context, new_kek](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
            self->doAddBiometricFactor(*context, response, new_kek);
            return nullptr;
        })
        .build();
}

void ActivationServiceV3::doAddBiometricFactor(Context& context, const cc7::json::JsonValue& response, const cc7::ByteRange& new_biometry_kek)
{
    auto& key_provider = context.keyProvider();
    
    auto secrets = key_provider.unlockVaultKey(VaultKeyType::KEK_DEVICE_PRIVATE, response["encryptedVaultEncryptionKey"].asBase64());
    secrets->updateKeyAuthenticationCodeBiometry(cc7::ByteRange(), new_biometry_kek);
    key_provider.lockSecretKeys(secrets);
}

RequestPtr ActivationServiceV3::removeBiometricFactor()
{
    LOCK_GUARD();
    auto context = lockContext();
    auto& key_provider = context->keyProvider();
    
    auto secrets = key_provider.unlockSecretKeys();
    secrets->removeKeyAuthenticationCodeBiometry();
    key_provider.lockSecretKeys(secrets);
    
    return nullptr;
}

} // namespace v3
} // namespace powerAuth
