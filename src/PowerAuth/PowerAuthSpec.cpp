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

#include <PowerAuth/PowerAuthSpec.h>

#include "v4/HybridKeyPair.h"
#include "v4/HybridSignature.h"

namespace powerAuth {

const PowerAuthSpec PowerAuthSpec::spec_LEGACY_P256 {
    PowerAuthSpec::LEGACY_P256,
    Version_V3,
    "LEGACY",
    nullptr,
    { "ECDSA-SHA-256", "" },
    { "P-256", "" }
};

const PowerAuthSpec PowerAuthSpec::spec_EC_P384 {
    PowerAuthSpec::EC_P384,
    Version_V4,
    "EC_P384",
    SharedSecret::specForAlgorithm(SharedSecret::EC_P384),
    { "ECDSA-SHA3-384", "" },
    { "P-384", "" }
};

const PowerAuthSpec PowerAuthSpec::spec_EC_P384_ML_L3 {
    PowerAuthSpec::EC_P384_ML_L3,
    Version_V4,
    "EC_P384_ML_L3",
    SharedSecret::specForAlgorithm(SharedSecret::EC_P384_ML_L3),
    { "ECDSA-SHA3-384", "ML-DSA-65" },
    { "P-384", "ML-DSA-65" }
};

ConstPowerAuthSpecPtr PowerAuthSpec::specForAlgorithm(Algorithm algorithm) noexcept
{
    switch (algorithm) {
        case EC_P384:       return &spec_EC_P384;
        case EC_P384_ML_L3: return &spec_EC_P384_ML_L3;
        case LEGACY_P256:   return &spec_LEGACY_P256;
        default: return nullptr;
    }
}

ConstPowerAuthSpecPtr PowerAuthSpec::specForAlgorithmId(cc7::byte algorithm) noexcept
{
    return specForAlgorithm(static_cast<Algorithm>(algorithm));
}

PowerAuthSpec::PowerAuthSpec(Algorithm algorithm,
                             ProtocolVersion version,
                             const std::string& name,
                             SharedSecretSpecPtr sharedSecret,
                             AlgorithmPair signature_algorithms,
                             AlgorithmPair signing_key_pair_algorithms) :
    _algorithm(algorithm),
    _protocol_version(version),
    _name(name),
    _shared_secret(sharedSecret),
    _signature_algorithms(signature_algorithms),
    _signing_key_pair_algorithms(signing_key_pair_algorithms)
{
}

bool PowerAuthSpec::isLegacy() const noexcept
{
    return _protocol_version < Version_V4;
}

bool PowerAuthSpec::isHybrid() const noexcept
{
    if (isLegacy()) {
        return false;
    }
    return !_signature_algorithms.second.empty();;
}

bool PowerAuthSpec::isActivationSupported() const noexcept
{
    // The current implementation disables only legacy protocol (so V3), but this may
    // be changed in the future. For example, if we discontinue some V4 algorithms, then
    return !isLegacy();
}

PowerAuthSpec::Algorithm PowerAuthSpec::algorithm() const noexcept
{
    return _algorithm;
}

ProtocolVersion PowerAuthSpec::protocolVersion() const noexcept
{
    return _protocol_version;
}

cc7::byte PowerAuthSpec::algorithmId() const noexcept
{
    return static_cast<cc7::byte>(_algorithm);
}

const std::string& PowerAuthSpec::algorithmName() const noexcept
{
    return _name;
}

SharedSecret::Algorithm PowerAuthSpec::sharedSecret() const
{
    if (!_shared_secret) {
        throw Exception(EC_InternalError, "SharedSecret is not available");
    }
    return _shared_secret->identifier;
}

const PowerAuthSpec::AlgorithmPair& PowerAuthSpec::getSignatureAlgorithms() const noexcept
{
    return _signature_algorithms;
}

const PowerAuthSpec::AlgorithmPair& PowerAuthSpec::getSigningKeyPairAlgorithms() const noexcept
{
    return _signing_key_pair_algorithms;
}

const cc7::crypto::KeyPairFactoryPtr PowerAuthSpec::getSigningKeyPairFactory() const
{
    if (_protocol_version == Version_V4) {
        return v4::HybridKeyPairFactory::getInstance(_signing_key_pair_algorithms.first,
                                                     _signing_key_pair_algorithms.second);
    }
    return cc7::crypto::KeyPairFactory::getInstance(_signing_key_pair_algorithms.first);
}

} // namespace powerAuth
