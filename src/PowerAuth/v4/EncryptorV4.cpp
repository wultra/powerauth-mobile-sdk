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

#include "EncryptorV4.h"

#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>

#include "../crypto/PowerAuthAEAD.h"
#include "E2EEUtilsV4.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

static inline const cc7::crypto::AEAD& aeadAlg()
{
    return algorithms().v4.aead();
}

// MARK: - ClientEncryptor

ClientEncryptor::ClientEncryptor(EncryptorParametersPtr& parameters,
                                 EncryptorSecretsPtr& secrets,
                                 const ByteRange& nonce,
                                 const TimeServicePtr& time_service) :
    _parameters(std::move(parameters)),
    _secrets(std::move(secrets)),
    _nonce(nonce),
    _time_service(time_service),
    _time_sync_task(-1)
{
#if DEBUG
    // The following validations are enabled only for DEBUG build.
    if (!_parameters || !_secrets || !_time_service) {
        throw Exception(EC_InternalError, "ClientEncryptor V4: Missing required parameter");
    }
    if (_nonce.size() != crypto::PowerAuthAEAD::NONCE_SIZE*2) {
        throw Exception(EC_InternalError, "ClientEncryptor V4: Wrong request nonce size");
    }
    if (requestNonce() == responseNonce()) {
        throw Exception(EC_InternalError, "ClientEncryptor V4: Nonces must be different");
    }
#endif
}

bool ClientEncryptor::canEncryptRequest() const noexcept
{
    return _time_sync_task < 0;
}

bool ClientEncryptor::canDecryptResponse() const noexcept
{
    return _time_sync_task > 0;
}

EncryptedRequest ClientEncryptor::encryptRequest(const ByteRange &data)
{
    if (!canEncryptRequest()) {
        throw Exception(EC_NotAllowed, "Cannot encrypt request");
    }
    
    const auto& aead = aeadAlg();
    
    auto key = getKey();
    auto timestamp = _time_service->currentTimeMillis();
    auto aad = getAAD(timestamp);
    
    // Encrypt request
    auto ciphertext = aead.seal(*key, requestNonce(), aad, data);
    
    // Prepare request object
    auto object = json::JsonValue::object();
    object["temporaryKeyId"] = json::JsonValue(_parameters->temporaryKeyId);
    object["nonce"] = json::JsonValue(_nonce.base64());
    object["timestamp"] = json::JsonValue(timestamp);
    object["encryptedData"] = json::JsonValue(ciphertext.base64());
    
    // Prepare request header
    auto header = E2EE_BuildRequestHeader(*_parameters);
    
    // Start time synchronization, and flip encryptor to "decryptRequest" mode.
    _time_sync_task = _time_service->startTimeSynchronizationTask();
    
    // Return EncryptedRequest structure
    return { object, { header }};
}

ByteArray ClientEncryptor::decryptResponse(const EncryptedResponse &response)
{
    if (!canDecryptResponse()) {
        throw Exception(EC_NotAllowed, "Cannot decrypt response");
    }
    const auto& aead = aeadAlg();
    
    ByteArray ciphertext;
    Timestamp timestamp;
    try {
        timestamp = response.responsePayload["timestamp"].asInteger();
        ciphertext = Base64::decode(response.responsePayload["encryptedData"].asString());
        if (!ConstTimeEqual(responseNonce(), aead.extractNonce(ciphertext))) {
            throw Exception(EC_InvalidData, "Unexpected response nonce");
        }
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidData, "Invalid encrypted response");
    }
    // Complete time synchronization task
    _time_service->completeTimeSynchronizationTask(_time_sync_task, timestamp);
    // Flip decryptor to complete,
    _time_sync_task = 0.0;
    
    auto key = getKey();
    auto aad = getAAD(timestamp);
    return aead.open(*key, aad, ciphertext);
}

SymmetricKeyPtr ClientEncryptor::getKey() const
{
    auto key = SymmetricKey::getInstance("AES-256", _secrets->envelopeKey);
    key->setKeyContext(ConcatByteRanges({
        MakeRange(_parameters->protocolVersion),        // VERSION
        MakeRange(_parameters->sharedInfo1),            // SHARED_INFO_1
        _nonce                                          // NONCE
    }));
    return key;
}

ByteArray ClientEncryptor::getAAD(Timestamp timestamp) const
{
    auto associated_data = E2EE_BuildAssociatedData(*_parameters);
    return ConcatByteRanges({
        associated_data,                                // ASSOCIATED_DATA
        utils::ByteUtils_Join({
            MakeRange(ToBigEndian((U64)timestamp)),     // TIMESTAMP_BYTES
            _nonce,                                     // NONCE
            _secrets->sharedInfo2                       // SHARED_INFO_2
        })
    });
}

ByteRange ClientEncryptor::requestNonce() const
{
    return _nonce.byteRange().subRangeTo(crypto::PowerAuthAEAD::NONCE_SIZE);
}

ByteRange ClientEncryptor::responseNonce() const
{
    return _nonce.byteRange().subRangeFrom(crypto::PowerAuthAEAD::NONCE_SIZE);
}


// MARK: - ServerEncryptor

ServerEncryptor::ServerEncryptor(EncryptorParametersPtr& parameters,
                                 EncryptorSecretsPtr& secrets,
                                 const ITimeProviderPtr& time_provider) :
    _parameters(std::move(parameters)),
    _secrets(std::move(secrets)),
    _time_provider(time_provider)
{
#if DEBUG
    // The following validations are enabled only for DEBUG build.
    if (!_parameters || !_secrets || !_time_provider) {
        throw Exception(EC_InternalError, "ServerEncryptor V4: Missing required parameter");
    }
#endif
}

bool ServerEncryptor::canDecryptRequest() const noexcept
{
    return _nonce.empty() && !_response_processed;
}

bool ServerEncryptor::canEncryptResponse() const noexcept
{
    return !_nonce.empty() && !_response_processed;
}

ByteArray ServerEncryptor::decryptRequest(const EncryptedRequest &request)
{
    if (!canDecryptRequest()) {
        throw Exception(EC_NotAllowed, "Cannot decrypt request");
    }
    
    const auto& aead = aeadAlg();
    
    ByteArray nonce;
    ByteArray ciphertext;
    std::string temporary_key_id;
    Timestamp timestamp;
    try {
        temporary_key_id = request.requestPayload["temporaryKeyId"].asString();
        nonce = Base64::decode(request.requestPayload["nonce"].asString());
        ciphertext = Base64::decode(request.requestPayload["encryptedData"].asString());
        timestamp = request.requestPayload["timestamp"].asInteger();
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidData, "Wrong encrypted request data");
    }
    if (temporary_key_id != _parameters->temporaryKeyId) {
        throw Exception(EC_WrongParameter, "Wrong temporary key ID");
    }
    if (nonce.size() != 2 * crypto::PowerAuthAEAD::NONCE_SIZE) {
        throw Exception(EC_InvalidData, "Wrong nonce size");
    }
    _nonce = nonce;
    if (requestNonce() != aead.extractNonce(ciphertext)) {
        throw Exception(EC_InvalidData, "Wrong request nonce");
    }
    if (requestNonce() == responseNonce()) {
        throw Exception(EC_InvalidData, "Wrong response nonce");
    }
    
    auto key = getKey();
    auto aad = getAAD(timestamp);
    return aead.open(*key, aad, ciphertext);
}

EncryptedResponse ServerEncryptor::encryptResponse(const ByteRange &data)
{
    if (!canEncryptResponse()) {
        throw Exception(EC_NotAllowed, "Cannot encrypt response");
    }
    
    const auto& aead = aeadAlg();
    
    auto timestamp = _time_provider->getCurrentTimeMillis();
    
    auto key = getKey();
    auto aad = getAAD(timestamp);
    auto ciphertext = aead.seal(*key, responseNonce(), aad, data);
    
    _response_processed = true;
    
    // Prepare request object
    auto object = json::JsonValue::object();
    object["timestamp"] = json::JsonValue(timestamp);
    object["encryptedData"] = json::JsonValue(ciphertext.base64());
    
    return { object };
}

SymmetricKeyPtr ServerEncryptor::getKey() const
{
    auto key = SymmetricKey::getInstance("AES-256", _secrets->envelopeKey);
    key->setKeyContext(ConcatByteRanges({
        MakeRange(_parameters->protocolVersion),        // VERSION
        MakeRange(_parameters->sharedInfo1),            // SHARED_INFO_1
        _nonce                                          // NONCE
    }));
    return key;
}

ByteArray ServerEncryptor::getAAD(Timestamp timestamp) const
{
    auto associated_data = E2EE_BuildAssociatedData(*_parameters);
    return ConcatByteRanges({
        associated_data,                                // ASSOCIATED_DATA
        utils::ByteUtils_Join({
            MakeRange(ToBigEndian((U64)timestamp)),     // TIMESTAMP_BYTES
            _nonce,                                     // NONCE
            _secrets->sharedInfo2                       // SHARED_INFO_2
        })
    });
}

ByteRange ServerEncryptor::requestNonce() const
{
    return _nonce.byteRange().subRangeTo(crypto::PowerAuthAEAD::NONCE_SIZE);
}

ByteRange ServerEncryptor::responseNonce() const
{
    return _nonce.byteRange().subRangeFrom(crypto::PowerAuthAEAD::NONCE_SIZE);
}

} // namespace v4
} //namespace powerAuth
