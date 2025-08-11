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

#include "EciesEncryptor.h"
#include "FunctionsV3.h"
#include <PowerAuth/ByteUtils.h>
#include "../HttpHeaderHelper.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v3 {

// MARK: - Envelope key

class EciesEnvelopeKey {
public:
    
    // Default constructors & copy / move operators
    
    EciesEnvelopeKey() = default;
    
    /// Constructs a key with given bytes from |range|.
    EciesEnvelopeKey(const cc7::ByteRange & range) : _key(range) {}
    
    /// Assign a |range| of bytes to the key.
    EciesEnvelopeKey& operator=(const cc7::ByteRange & range)
    {
        _key.assign(range);
        return *this;
    }
    
    /// Returns key for encryption or decryption.
    const cc7::ByteRange encKey() const
    {
        return _key.subRange(EncKeyOffset, EncKeySize);
    }
    
    /// Returns key for HMAC calculation.
    const cc7::ByteRange macKey() const
    {
        return _key.subRange(MacKeyOffset, MacKeySize);
    }
    
    /// Returns key for IV derivation.
    const cc7::ByteRange ivKey() const
    {
        return _key.subRange(IvKeyOffset, IvKeySize);
    }
    
    /// Returns IV derived from IV key and provided nonce.
    cc7::ByteArray deriveIvForNonce(const cc7::ByteRange & nonce) const
    {
        return DeriveSecretKeyFromIndex(ivKey(), nonce);
    }
                
public:

    // Constants for sub-keys
    static const size_t EncKeyOffset = 0;
    static const size_t EncKeySize = 16;
    static const size_t MacKeyOffset = EncKeyOffset + EncKeySize;
    static const size_t MacKeySize = 16;
    static const size_t IvKeyOffset = MacKeyOffset + MacKeySize;
    static const size_t IvKeySize = 16;
            
    // Expected length of a whole envelope key.
    static const size_t EnvelopeKeySize = EncKeySize + MacKeySize + IvKeySize;
    
    // Other constants
    static const size_t NonceSize = 16;
    static const size_t IvSize = 16;

private:
    
    /// Envelope key's data
    cc7::ByteRange _key;
};


// MARK: - Common Encrypt & Decrypt

static json::JsonValue _Encrypt(const EciesEnvelopeKey & ek,
                     const ByteRange & info2,
                     const ByteRange & data,
                     const ByteRange & iv)
{
    if (iv.size() != EciesEnvelopeKey::IvSize) {
        throw Exception(EC_InternalError, "Wrong IV size");
    }
    auto body = algorithms().v3.aes128cbc().encrypt(ek.encKey(), iv, data);
    auto body_size = body.size();
    body.append(info2);
    auto mac = algorithms().v3.hmacWithSha256().token(ek.macKey(), body);
    body.resize(body_size);
    
    auto cryptogram = json::JsonValue::object();
    cryptogram["encryptedData"] = json::JsonValue::base64(body);
    cryptogram["mac"] = json::JsonValue::base64(mac);
    return cryptogram;
}

static ByteArray _Decrypt(const EciesEnvelopeKey & ek,
                          const ByteRange & info2,
                          const ByteRange & encrypted_data,
                          const ByteRange & mac,
                          const ByteRange & iv)
{
    if (iv.size() != EciesEnvelopeKey::IvSize) {
        throw Exception(EC_InternalError, "Wrong IV size");
    }
    ByteArray data_for_mac = encrypted_data;
    data_for_mac.append(info2);
    auto our_mac = algorithms().v3.hmacWithSha256().token(ek.macKey(), data_for_mac);
    // Verify calculated mac
    if (!ConstTimeEqual(our_mac, mac)) {
        throw Exception(EC_Cryptography, "MAC doesn't match");
    }
    return algorithms().v3.aes128cbc().decrypt(ek.encKey(), iv, encrypted_data);
}

// MARK: - EciesClientEncryptor

EciesClientEncryptor::EciesClientEncryptor(EncryptorParametersPtr& parameters,
                                           EncryptorSecretsPtr& secrets,
                                           const TimeServicePtr& time_service) :
    _parameters(std::move(parameters)),
    _secrets(std::move(secrets)),
    _time_service(time_service),
    // In ECIES, each reques/response key is different, so we don't need to use
    // nonce generator to generate sequence of unique nonces.
    _request_nonce(GetRandomData(EciesEnvelopeKey::NonceSize)),
    _time_sync_task(-1)
{
}

EciesClientEncryptor::EciesClientEncryptor(EncryptorParametersPtr& parameters,
                                           EncryptorSecretsPtr& secrets,
                                           const cc7::ByteRange& nonce,
                                           const TimeServicePtr& time_service) :
    _parameters(std::move(parameters)),
    _secrets(std::move(secrets)),
    _time_service(time_service),
    _fail_on_nosync_time(true),
    _request_nonce(nonce),
    _time_sync_task(-1)
{
}

bool EciesClientEncryptor::canEncryptRequest() const noexcept
{
    return _time_sync_task < 0;
}

bool EciesClientEncryptor::canDecryptResponse() const noexcept
{
return _time_sync_task > 0;
}


EncryptedRequest EciesClientEncryptor::encryptRequest(const ByteRange &data)
{
    if (!canEncryptRequest()) {
        throw Exception(EC_NotAllowed, "Cannot encrypt request");
    }
    if (!_time_service->isTimeSynchronized() && _fail_on_nosync_time) {
        throw Exception(EC_TimeNotSynchronized, "Encryption required time synchronized with server");
    }

    auto timestamp = _time_service->currentTimeMillis();
    auto key = EciesEnvelopeKey(_secrets->envelopeKey);
    auto aad = getAAD(timestamp, _request_nonce, _secrets->ephemeralKey);
    auto iv = key.deriveIvForNonce(_request_nonce);
    
    // Encrypt request
    auto cryptogram = _Encrypt(key, aad, data, iv);
    
    cryptogram["nonce"] = json::JsonValue::base64(_request_nonce);
    cryptogram["timestamp"] = json::JsonValue::integer(timestamp);
    cryptogram["temporaryKeyId"] = json::JsonValue::string(_parameters->temporaryKeyId);
    cryptogram["ephemeralPublicKey"] = json::JsonValue::base64(_secrets->ephemeralKey);
    
    // Prepare request header
    auto header = HttpHeaderHelper::buildEncryptionRequestHeader(*_parameters);
    
    // Start time synchronization, and flip encryptor to "decryptRequest" mode.
    _time_sync_task = _time_service->startTimeSynchronizationTask();
    
    // Return EncryptedRequest structure
    return { cryptogram, { header }};
}

ByteArray EciesClientEncryptor::decryptResponse(const EncryptedResponse &response)
{
    if (!canDecryptResponse()) {
        throw Exception(EC_NotAllowed, "Cannot decrypt response");
    }
    
    ByteArray ciphertext, nonce, mac;
    Timestamp timestamp;
    try {
        ciphertext = response.responsePayload["encryptedData"].asBase64();
        nonce = response.responsePayload["nonce"].asBase64();
        mac = response.responsePayload["mac"].asBase64();
        timestamp = response.responsePayload["timestamp"].asInteger();
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidResponse, "Invalid encrypted response");
    }
    if (ConstTimeEqual(_request_nonce, nonce)) {
        throw Exception(EC_InvalidResponse, "Request and response nonces are equal");
    }
    
    auto key = EciesEnvelopeKey(_secrets->envelopeKey);
    auto aad = getAAD(timestamp, nonce, ByteRange());
    auto iv = key.deriveIvForNonce(nonce);
    
    auto plaintext = _Decrypt(key, aad, ciphertext, mac, iv);

    // Complete time synchronization task
    _time_service->completeTimeSynchronizationTask(_time_sync_task, timestamp);
    // Flip decryptor to complete,
    _time_sync_task = 0.0;

    return plaintext;
}

void EciesClientEncryptor::disableFailWhenTimeIsNotSynchronized()
{
#if DEBUG
    _fail_on_nosync_time = false;
#else
    throw Exception(EC_InternalError, "Not implemented");
#endif
}

ByteArray EciesClientEncryptor::getAAD(Timestamp timestamp, const ByteRange & nonce, const ByteRange& ephemeral_key) const
{
    auto timestamp_be = ToBigEndian((U64)timestamp);
    return utils::ByteUtils_ConcatWithSizes({
        _secrets->sharedInfo2,
        nonce,
        MakeRange(timestamp_be),
        ephemeral_key,
        _parameters->buildAssociatedData()
    });
}

} // namespace v3
} // namespace powerAuth
