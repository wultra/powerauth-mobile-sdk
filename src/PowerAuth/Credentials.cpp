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

#include <PowerAuth/Credentials.h>
#include "model/Constants.h"

namespace powerAuth {

// MARK: - Support functions

static size_t _FactorKeySizeForProtocol(ProtocolVersion v)
{
    switch (v) {
        case Version_V4: return v4::FACTOR_KEY_SIZE;
        case Version_V3: return v3::FACTOR_KEY_SIZE;
        default:
            throw Exception(EC_InternalError, "Unsupported protocol version");
    }
}

// MARK: - Credentials

CredentialsPtr Credentials::possession() noexcept
{
    return std::shared_ptr<Credentials>(new Credentials(AuthFactors::POSSESSION, cc7::ByteRange(), cc7::ByteRange()));
}

CredentialsPtr Credentials::knowledge(const cc7::ByteRange& password) noexcept
{
    return std::shared_ptr<Credentials>(new Credentials(AuthFactors::POSSESSION_KNOWLEDGE, password, cc7::ByteRange()));
}

CredentialsPtr Credentials::biometry(const cc7::ByteRange& biometry_kek) noexcept
{
    return std::shared_ptr<Credentials>(new Credentials(AuthFactors::POSSESSION_BIOMETRY, cc7::ByteRange(), biometry_kek));
}

Credentials::Credentials(AuthFactors factors,
                         const cc7::ByteRange& knowledge,
                         const cc7::ByteRange& biometry) noexcept :
    _factors(factors),
    _knowledge(knowledge),
    _biometry(biometry)
{
}

const cc7::ByteArray& Credentials::knowledgeKEK() const
{
    if (_factors != AuthFactors::POSSESSION_KNOWLEDGE) {
        throw Exception(EC_InternalError, "Knowledge factor is not configured");
    }
    return _knowledge;
}

const cc7::ByteArray& Credentials::biometryKEK() const
{
    if (_factors != AuthFactors::POSSESSION_BIOMETRY) {
        throw Exception(EC_InternalError, "Biometry factor is not configured");
    }
    return _biometry;
}

AuthFactors Credentials::factors() const noexcept
{
    return _factors;
}

std::string Credentials::factorsString() const noexcept
{
    switch (_factors) {
        case AuthFactors::POSSESSION: return std::string("possession");
        case AuthFactors::POSSESSION_KNOWLEDGE: return std::string("possession_knowledge");
        case AuthFactors::POSSESSION_BIOMETRY: return std::string("possession_biometry");
    }
}

void Credentials::validate(ProtocolVersion v) const
{
    
    auto key_size = _FactorKeySizeForProtocol(v);
    auto valid = false;
    switch (_factors) {
        case AuthFactors::POSSESSION:
            valid = true;
            break;
        case AuthFactors::POSSESSION_KNOWLEDGE:
            valid = _knowledge.size() >= common::MINIMAL_PASSWORD_LENGTH;
            break;
        case AuthFactors::POSSESSION_BIOMETRY:
            valid = _biometry.size() == key_size;
            break;
    }
    if (!valid) {
        throw Exception(EC_WrongParameter, "Invalid credentials provided");
    }
}

// MARK: - InitialCredentials

InitialCredentialsPtr InitialCredentials::credentials(const cc7::ByteRange &password,
                                                      const cc7::ByteRange &biometry_kek) noexcept
{
    return std::shared_ptr<InitialCredentials>(new InitialCredentials(password, biometry_kek));
}

InitialCredentials::InitialCredentials(const cc7::ByteRange& password,
                                       const cc7::ByteRange& biometry_kek) noexcept :
    _knowledge(password),
    _biometry(biometry_kek)
{
}

const cc7::ByteArray& InitialCredentials::knowledgeKEK() const noexcept
{
    return _knowledge;
}

const cc7::ByteArray& InitialCredentials::biometryKEK() const noexcept
{
    return _biometry;
}

bool InitialCredentials::hasBiometryKEK() const noexcept
{
    return !_biometry.empty();
}

void InitialCredentials::validate(ProtocolVersion version) const
{
    auto key_size = _FactorKeySizeForProtocol(version);
    auto valid = _knowledge.size() >= common::MINIMAL_PASSWORD_LENGTH &&
                 (_biometry.empty() || _biometry.size() == key_size);
    if (!valid) {
        throw Exception(EC_WrongParameter, "Invalid initial credentials provided");
    }
}

} // namespace powerAuth
