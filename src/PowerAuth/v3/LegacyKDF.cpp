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

#include "LegacyKDF.h"
#include <cc7/Endian.h>
#include "../model/Constants.h"

namespace powerAuth {
namespace v3 {

LegacyKDF::LegacyKDF(const cc7::crypto::CipherPtr& aes128cbcNoPad) :
    _aes(aes128cbcNoPad)
{
#ifdef DEBUG
    if (_aes->getAlgorithmName() != "AES-128-CBC" ||
        _aes->getParameter(cc7::crypto::CIPHER_PARAM_USE_PADDING).asBool()) {
            throw Exception(EC_InternalError, "Invalid LegacyKDF setup");
    }
#endif
}

cc7::ByteArray LegacyKDF::derive(const cc7::ByteRange &key, uint64_t index) const
{
    cc7::ByteArray data(8, 0);
    index = cc7::ToBigEndian(index);
    data.append(cc7::MakeRange(index));
    return _aes->encrypt(key, common::ZERO16_IV, data);
}

LegacyKDFInternal::LegacyKDFInternal(const cc7::crypto::MACPtr& hmacSha256) :
    _mac(hmacSha256)
{
#ifdef DEBUG
    if (_mac->getAlgorithmName() != "HMAC-SHA-256" ||
        _mac->getParameter(cc7::crypto::MAC_PARAM_DIGEST_LENGTH).asSize() != 32) {
        throw Exception(EC_InternalError, "Invalid LegacyKDFInternal setup");
    }
#endif
}

cc7::ByteArray LegacyKDFInternal::derive(const cc7::ByteRange& key, cc7::ByteRange& index) const
{
    auto result = _mac->token(key, index);
    // xor the result and shrink to 16B
    for (size_t i = 0; i < 16; i++) {
        result[i] = result[i] ^ result[i + 16];
    }
    result.resize(v3::FACTOR_KEY_SIZE);
    return result;

}

} // namespace v3
} // namespace powerAuth
