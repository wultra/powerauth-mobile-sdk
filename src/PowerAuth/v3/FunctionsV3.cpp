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

#include "FunctionsV3.h"
#include "../model/Constants.h"
#include "../common/CommonFunctions.h"

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

static std::vector<cc7::ByteArray> CalculateAuthenticationCodeComponents(const std::vector<cc7::ByteRange>& factor_keys,
                                                                        const cc7::ByteRange& counter,
                                                                        const cc7::ByteRange& data)
{
    const auto& hmacSha256 = algorithms().v3.hmacWithSha256();
    
    std::vector<cc7::ByteArray> components;
    components.reserve(factor_keys.size());
    
    for (auto i = 0; i < factor_keys.size(); ++i) {
        auto key_derived = hmacSha256.token(factor_keys[i], counter);
        for (auto j = 0; j < i; ++j) {
            auto key_derived_current = hmacSha256.token(factor_keys[j + 1], counter);
            key_derived = hmacSha256.token(key_derived_current, key_derived);
        }
        components.push_back(hmacSha256.token(key_derived, data).byteRange().subRangeFrom(16));
    }
    
    return components;
}

cc7::ByteArray CalculateOnlineAuthenticationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                                const cc7::ByteRange& counter,
                                                const cc7::ByteRange& data)
{
    auto components = CalculateAuthenticationCodeComponents(factor_keys, counter, data);
        
    cc7::ByteArray auth_code;
    auth_code.reserve(components.size() * v3::AUTH_CODE_COMPONENT_LENGTH);
    for (const auto& c : components) {
        auth_code.append(c);
    }
    return auth_code;
}

std::string CalculateOfflineAuthenticationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                              const cc7::ByteRange& counter,
                                              const cc7::ByteRange& data,
                                              size_t component_size)
{
    auto components = CalculateAuthenticationCodeComponents(factor_keys, counter, data);
    
    std::string result;
    result.reserve((component_size + 1) * components.size() - 1);
    for (const auto& c : components) {
        auto code = common::CalculateHumanReadableCodeFromHash(c, component_size);
        if (result.empty()) {
            result.assign(code);
        } else {
            result.append("-");
            result.append(code);
        }
    }
    
    return result;
}

} // namespace v3
} // namespace powerAuth
