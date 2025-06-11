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

#include <PowerAuth/SharedSecret.h>
#include <PowerAuth/Algorithms.h>

namespace powerAuth {

class PowerAuthSpec
{
public:
    
    enum Algorithm
    {
        /// Legacy protocol V3.3
        /// - Signatures: ECDSA with P256,
        /// - SharedSecret: ECDH with P256
        LEGACY_P256 = 0,
        /// Protocol V4.0
        /// - Signatures: ECDSA with P384,
        /// - SharedSecret: ECDHE with P384
        EC_P384,
        /// Protocol V4.0
        /// - Signatures: ECDSA with P384 + ML-DSA-65
        /// - SharedSecret: ECDHE with P384 + ML-KEM-768
        EC_P384_ML_L3
    };
        
    bool isLegacy() const noexcept;
    bool isActivationSupported() const noexcept;

    ProtocolVersion protocolVersion() const noexcept;
    Algorithm algorithm() const noexcept;
    cc7::byte algorithmId() const noexcept;
    const std::string& algorithmName() const noexcept;

    SharedSecret::Algorithm sharedSecret() const;
        
    static PowerAuthSpec const * const specForAlgorithm(Algorithm algorithm);
    static PowerAuthSpec const * const specForAlgorithmId(cc7::byte algorithm);
    
private:
    
    PowerAuthSpec(Algorithm algorithm,
                  ProtocolVersion version,
                  const std::string& name,
                  SharedSecretSpecPtr sharedSecret);
    
    Algorithm _algorithm;
    ProtocolVersion _protocol_version;
    std::string _name;
    SharedSecretSpecPtr _shared_secret;
    
    static const PowerAuthSpec spec_LEGACY_P256;
    static const PowerAuthSpec spec_EC_P384;
    static const PowerAuthSpec spec_EC_P384_ML_L3;
};

typedef PowerAuthSpec const * const PowerAuthSpecPtr;

} // namespace powerAuth
