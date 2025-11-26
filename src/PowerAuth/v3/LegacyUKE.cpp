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

#include "LegacyUKE.h"
#include "../model/Constants.h"

namespace powerAuth {
namespace v3 {


LegacyUKE::LegacyUKE(const cc7::crypto::CipherPtr& aes128cbcNoPad) :
    _aes(aes128cbcNoPad)
{
#ifdef DEBUG
    if (_aes->getAlgorithmName() != "AES-128-CBC" ||
        _aes->getParameter(cc7::crypto::CIPHER_PARAM_USE_PADDING).asBool()) {
            throw Exception(EC_InternalError, "Invalid LegacyUKE setup");
    }
#endif
}
    
cc7::ByteArray LegacyUKE::wrap(const cc7::ByteRange& kek, const cc7::ByteRange& factor_key) const
{
    if (kek.size() != v3::FACTOR_KEY_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid size of factor kek");
    }
    if (factor_key.size() != v3::FACTOR_KEY_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid size of factor key");
    }
    return _aes->encrypt(kek, common::ZERO16_IV, factor_key);
}

cc7::ByteArray LegacyUKE::unwrap(const cc7::ByteRange& kek, const cc7::ByteRange& wrapped_key) const
{
    if (kek.size() != v3::FACTOR_KEY_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid size of factor kek");
    }
    if (wrapped_key.size() != v3::FACTOR_KEY_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid size of wrapped factor key");
    }
    return _aes->decrypt(kek, common::ZERO16_IV, wrapped_key);
}

} // namespace v3
} // namespace powerAuth
