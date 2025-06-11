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

#include <PowerAuth/Authentication.h>
#include "model/Constants.h"

namespace powerAuth {

Authentication Authentication::possession(const cc7::ByteRange& possesion_kek) noexcept
{
    return Authentication(AuthFactors::POSSESSION, possesion_kek, cc7::ByteRange(), cc7::ByteRange());
}

Authentication Authentication::knowledge(const cc7::ByteRange& possesion_kek, const cc7::ByteRange& password) noexcept
{
    return Authentication(AuthFactors::POSSESSION_KNOWLEDGE, possesion_kek, password, cc7::ByteRange());
}

Authentication Authentication::knowledge(const cc7::ByteRange& possesion_kek, const Password& password) noexcept
{
    return Authentication(AuthFactors::POSSESSION_KNOWLEDGE, possesion_kek, password.passwordData(), cc7::ByteRange());
}

Authentication Authentication::biometry(const cc7::ByteRange& possesion_kek, const cc7::ByteRange& biometry_kek) noexcept
{
    return Authentication(AuthFactors::POSSESSION_BIOMETRY, possesion_kek, cc7::ByteRange(), biometry_kek);
}

Authentication::Authentication(AuthFactors factors,
                               const cc7::ByteRange& possession,
                               const cc7::ByteRange& knowledge,
                               const cc7::ByteRange& biometry) noexcept :
    _factors(factors),
    _possession(possession),
    _knowledge(knowledge),
    _biometry(biometry)
{
}

const cc7::ByteArray& Authentication::possessionKEK() const noexcept
{
    return _possession;
}

const cc7::ByteArray& Authentication::knowledgeKEK() const
{
    if (_factors != AuthFactors::POSSESSION_KNOWLEDGE) {
        throw Exception(EC_InternalError, "Knowledge factor is not configured");
    }
    return _knowledge;
}

const cc7::ByteArray& Authentication::biometryKEK() const
{
    if (_factors != AuthFactors::POSSESSION_BIOMETRY) {
        throw Exception(EC_InternalError, "Biometry factor is not configured");
    }
    return _biometry;
}

AuthFactors Authentication::factors() const noexcept
{
    return _factors;
}

std::string Authentication::factorsString() const noexcept
{
    switch (_factors) {
        case AuthFactors::POSSESSION: return std::string("possession");
        case AuthFactors::POSSESSION_KNOWLEDGE: return std::string("possession_knowledge");
        case AuthFactors::POSSESSION_BIOMETRY: return std::string("possession_biometry");
    }
}

void Authentication::validate(ProtocolVersion v) const
{
    
    size_t key_size;
    switch (v) {
        case Version_V4: key_size = v4::FACTOR_KEY_SIZE; break;
        case Version_V3: key_size = v3::FACTOR_KEY_SIZE; break;
        default:
            throw Exception(EC_InternalError, "Unsupported protocol version");
    }
    bool valid = false;
    switch (_factors) {
        case AuthFactors::POSSESSION:
            valid = _possession.size() == key_size;
            break;
        case AuthFactors::POSSESSION_KNOWLEDGE:
            valid = _possession.size() == key_size &&
                    _knowledge.size() >= common::MINIMAL_PASSWORD_LENGTH;
            break;
        case AuthFactors::POSSESSION_BIOMETRY:
            valid = _possession.size() == key_size &&
                    _biometry.size() == key_size;
            break;
    }
    if (!valid) {
        throw Exception(EC_WrongParameter, "Invalid Authentication keys provided");
    }
}

} // namespace powerAuth
