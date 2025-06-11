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

#include "PowerAuthAEAD.h"
#include "PowerAuthKDF.h"
#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace crypto {

const std::string PowerAuthAEAD::ALG_NAME      = "PA4AEAD";
const std::string PowerAuthAEAD::MAC_CUSTOM    = "PA4MAC-AEAD";
const std::string PowerAuthAEAD::KEY_ENC_LABEL = "aead/enc";
const std::string PowerAuthAEAD::KEY_MAC_LABEL = "aead/mac";

const size_t PowerAuthAEAD::NONCE_SIZE = 12;
const size_t PowerAuthAEAD::TAG_SIZE   = 32;

const ParameterList PowerAuthAEAD::MAC_PARAMS {
    { MAC_PARAM_CUSTOM_STRING, Parameter::ref(MAC_CUSTOM) },
    { MAC_PARAM_DIGEST_LENGTH, Parameter::take(TAG_SIZE) }
};

PowerAuthAEAD::PowerAuthAEAD(const std::shared_ptr<PowerAuthKDF> & kdf, const cc7::crypto::CipherPtr & cipher, const cc7::crypto::MACPtr & mac) :
    _kdf(kdf),
    _cipher(cipher),
    _mac(mac)
{
}

// AEAD

cc7::ByteArray PowerAuthAEAD::seal(const cc7::ByteRange &key, const cc7::ByteRange &input_nonce, const cc7::ByteRange &associated_data, const cc7::ByteRange &plaintext, const cc7::crypto::ParameterList &params) const
{
    ByteArray nonce = input_nonce;
    ByteRange key_context;
    NonceGeneratorPtr nonce_generator;
    auto param_ctx = params.beginParameterProcessing();
    if (!params.getBytes(PARAM_KEY_CONTEXT, param_ctx, key_context)) {
        throw std::invalid_argument("PARAM_KEY_CONTEXT is missing");
    }
    if (params.getTypedObject<NonceGenerator>(AEAD_NONCE_GENERATOR, param_ctx, nonce_generator)) {
        nonce = nonce_generator->getNonce();
    }
    params.endParameterProcessing(param_ctx);
    
    if (nonce.size() != NONCE_SIZE) {
        throw std::invalid_argument("Wrong nonce size");
    }
    
    auto key_enc = _kdf->derive(key, KEY_ENC_LABEL, key_context);
    auto key_mac = _kdf->derive(key, KEY_MAC_LABEL, key_context);
    
    auto iv = ConcatByteRanges({ nonce, ByteRange::zero(4) });
    auto encrypted = _cipher->encrypt(key_enc, iv, plaintext);
    auto auth_data = ConcatByteRanges({ nonce, associated_data, encrypted });
    auto tag = _mac->token(key_mac, auth_data, MAC_PARAMS);
    
    return ConcatByteRanges({ nonce, tag, encrypted });
}

cc7::ByteArray PowerAuthAEAD::open(const cc7::ByteRange &key, const cc7::ByteRange &associated_data, const cc7::ByteRange &ciphertext, const cc7::crypto::ParameterList &params) const
{
    if (ciphertext.size() < NONCE_SIZE + TAG_SIZE) {
        throw std::invalid_argument("ciphertext is too short");
    }
    ByteRange key_context;
    auto ctx = params.beginParameterProcessing();
    if (!params.getBytes(PARAM_KEY_CONTEXT, ctx, key_context)) {
        throw std::invalid_argument("PARAM_KEY_CONTEXT is missing");
    }
    params.endParameterProcessing(ctx);

    auto nonce     = ciphertext.subRangeTo(NONCE_SIZE);
    auto tag       = ciphertext.subRange(NONCE_SIZE, TAG_SIZE);
    auto encrypted = ciphertext.subRangeFrom(NONCE_SIZE + TAG_SIZE);
    auto auth_data = ConcatByteRanges({ nonce, associated_data, encrypted });
    
    auto key_mac = _kdf->derive(key, KEY_MAC_LABEL, key_context);
    
    if (!_mac->verifyToken(key_mac, auth_data, tag, MAC_PARAMS)) {
        throw cc7::crypto::CryptoException("MAC is wrong");
    }
    
    auto key_enc = _kdf->derive(key, KEY_ENC_LABEL, key_context);
    auto iv = ConcatByteRanges({ nonce, ByteRange::zero(4) });
    
    return _cipher->decrypt(key_enc, iv, encrypted);
}

cc7::ByteArray PowerAuthAEAD::extractNonce(const ByteRange &ciphertext) const
{
    if (ciphertext.size() < NONCE_SIZE + TAG_SIZE) {
        throw std::invalid_argument("ciphertext is too short");
    }
    return ciphertext.subRangeTo(NONCE_SIZE);
}

// Algorithm
const std::string & PowerAuthAEAD::getAlgorithmName() const
{
    return ALG_NAME;
}

void PowerAuthAEAD::setParameter(int param_id, const cc7::crypto::Parameter & value)
{
    throw std::invalid_argument("Unsupported parameter");
}

cc7::crypto::Parameter PowerAuthAEAD::getParameter(int param_id) const
{
    throw std::invalid_argument("Unsupported parameter");
}


} // namespace crypto
} // namespace powerAuth
