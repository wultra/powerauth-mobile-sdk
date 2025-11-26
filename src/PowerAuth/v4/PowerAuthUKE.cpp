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

#include "PowerAuthUKE.h"
#include <cc7/crypto/Random.h>

namespace powerAuth {
namespace v4 {

PowerAuthUKE::PowerAuthUKE(const cc7::crypto::CipherPtr& aes_ctr) :
    _aes_ctr(aes_ctr != nullptr ? aes_ctr : cc7::crypto::Cipher::getInstance("AES-256-CTR"))
{
#ifdef DEBUG
    if (_aes_ctr->getAlgorithmName() != "AES-256-CTR") {
        throw Exception(EC_InternalError, "Invalid UKE algorithm");
    }
#endif
}

cc7::ByteArray PowerAuthUKE::wrap(const cc7::ByteRange& kek, const cc7::ByteRange& secret_key) const
{
    if (secret_key.size() != KEY_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid secret key size");
    }
    auto iv = cc7::crypto::GetRandomData(IV_SIZE);
    auto encrypted = _aes_ctr->encrypt(kek, iv, secret_key);
    return cc7::ConcatByteRanges({ iv, encrypted });
}

cc7::ByteArray PowerAuthUKE::unwrap(const cc7::ByteRange& kek, const cc7::ByteRange& wrapped_key) const
{
    if (wrapped_key.size() != KEY_SIZE + IV_SIZE) {
        throw Exception(EC_WrongParameter, "Invalid wrapped key size");
    }
    auto iv = wrapped_key.subRangeTo(IV_SIZE);
    auto encrypted = wrapped_key.subRangeFrom(IV_SIZE);
    return _aes_ctr->decrypt(kek, iv, encrypted);
}

} // namespace v4
} // namespace powerAuth
