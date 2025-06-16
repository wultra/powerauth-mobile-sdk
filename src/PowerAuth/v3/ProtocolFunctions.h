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

#pragma once

#include <PowerAuth/Types.h>
#include <PowerAuth/Algorithms.h>
#include "../model/Constants.h"

namespace powerAuth {
namespace v3 {

cc7::ByteArray ReduceSharedSecret(const cc7::ByteRange & secret)
{
    size_t s = secret.size();
    if (s != SHARED_SECRET_KEY_SIZE) {
        throw Exception(EC_InternalError, "Shared secret has unexpected size.");
    }
    s = s / 2;
    cc7::ByteArray reduced(s, 0);
    for (size_t i = 0; i < secret.size() / 2; i++) {
        reduced[i] = secret[i] ^ secret[i + SHARED_SECRET_KEY_SIZE/2];
    }
    return reduced;
}

/**
 Returns ByteArray( {0,0,0,0,0,0,0,0} + BigEndian(n) )
 */
static inline cc7::ByteArray _U64ToData(cc7::U64 n)
{
    cc7::ByteArray data(8, 0);
    n = cc7::ToBigEndian(n);
    data.append(cc7::MakeRange(n));
    CC7_ASSERT(data.size() == 16, "Wrong key size after index append");
    return data;
}

cc7::ByteArray DeriveSecretKey(const cc7::ByteRange & secret, cc7::U64 index)
{
#if DEBUG
    if (secret.size() != v3::FACTOR_KEY_SIZE) {
        throw Exception(EC_InternalError, "Wrong secret length");
    }
#endif
    cc7::ByteArray key = _U64ToData(index);
    return algorithms().v3.aes128cbcNoPad().encrypt(secret, common::ZERO16_IV, key);
}

cc7::ByteArray DeriveSecretKeyFromPassword(const cc7::ByteRange & password, const cc7::ByteRange & salt, cc7::U32 iterations)
{
    const auto params = cc7::crypto::ParameterList {
        { cc7::crypto::KDF_PARAM_ITERATIONS,    cc7::crypto::Parameter::take(static_cast<size_t>(iterations)) },
        { cc7::crypto::KDF_PARAM_SALT,          cc7::crypto::Parameter::ref(salt) },
    };
    return algorithms().v3.pbkdf2WithSha1().deriveKeyBytes(password, params);
}

cc7::ByteArray DeriveSecretKeyFromIndex(const cc7::ByteRange & masterKey, const cc7::ByteRange & index)
{
    if (masterKey.size() == v3::FACTOR_KEY_SIZE && index.size() >= v3::FACTOR_KEY_SIZE) {
        // Calculate HMAC SHA256 without cropping the result
        auto result = algorithms().v3.hmacWithSha256().token(masterKey, index);
        if (result.size() != 32) {
            throw Exception(EC_Cryptography, "Wrong HMAC-SHA256 result size");
        }
        // Everything looks fine, just xor the final array.
        for (size_t i = 0; i < 16; i++) {
            result[i] = result[i] ^ result[i + 16];
        }
        result.resize(v3::FACTOR_KEY_SIZE);
        return result;
    }
    throw Exception(EC_InternalError, "Provided masterKey or index has wrong size.");
}

} // namespace v3
} // namespace powerAuth
