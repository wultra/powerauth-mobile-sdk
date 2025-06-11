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

#include "crypto/HybridKeyPair.h"
#include "crypto/HybridSignature.h"

namespace powerAuth {

const PowerAuthSpec PowerAuthSpec::spec_LEGACY_P256 {
    PowerAuthSpec::LEGACY_P256,
    Version_V3,
    "LEGACY",
    nullptr
};

const PowerAuthSpec PowerAuthSpec::spec_EC_P384 {
    PowerAuthSpec::EC_P384,
    Version_V4,
    "EC_P384",
    SharedSecret::specForAlgorithm(SharedSecret::EC_P384)
};

const PowerAuthSpec PowerAuthSpec::spec_EC_P384_ML_L3 {
    PowerAuthSpec::EC_P384_ML_L3,
    Version_V4,
    "EC_P384_ML_L3",
    SharedSecret::specForAlgorithm(SharedSecret::EC_P384_ML_L3)
};

PowerAuthSpecPtr PowerAuthSpec::specForAlgorithm(Algorithm algorithm)
{
    switch (algorithm) {
        case EC_P384:       return &spec_EC_P384;
        case EC_P384_ML_L3: return &spec_EC_P384_ML_L3;
        case LEGACY_P256:   return &spec_LEGACY_P256;
        default:            return nullptr;
    }
}

PowerAuthSpecPtr PowerAuthSpec::specForAlgorithmId(cc7::byte algorithm)
{
    return specForAlgorithm(static_cast<Algorithm>(algorithm));
}

PowerAuthSpec::PowerAuthSpec(Algorithm algorithm,
                             ProtocolVersion version,
                             const std::string& name,
                             SharedSecretSpecPtr sharedSecret) :
    _algorithm(algorithm),
    _protocol_version(version),
    _name(name),
    _shared_secret(sharedSecret)
{
}

bool PowerAuthSpec::isLegacy() const noexcept
{
    return _protocol_version < Version_V4;
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

} // namespace powerAuth
