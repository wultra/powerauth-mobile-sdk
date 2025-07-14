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
#include <cc7/jwt/JwtKey.h>

namespace powerAuth {

/// The `PowerAuthSpec` class contains algorithms specification
/// for selected PowerAuth algorithm.
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
    
    /// Type defining two algorithm identifiers. If hybrid scheme is used,
    /// then `first` and `second` contains valid identifiers. For non-hybrid schemes,
    /// only `first` is set.
    typedef std::pair<std::string, std::string> AlgorithmPair;
    
    /// Returns `true` if this is legacy protocol.
    bool isLegacy() const noexcept;
    
    /// Returns `true` if uses hybrid signatures and shared secret.
    bool isHybrid() const noexcept;
    
    /// Returns `true` if activation process is supported for this algorithm.
    bool isActivationSupported() const noexcept;

    /// Returns protocol version for this specification.
    ProtocolVersion protocolVersion() const noexcept;
    
    /// Returns PowerAuth algorithm for this specification.
    Algorithm algorithm() const noexcept;
    
    /// Returns byte identifier for this specification.
    cc7::byte algorithmId() const noexcept;
    
    /// Returns string representation of algorithm for this specification.
    const std::string& algorithmName() const noexcept;

    /// Returns shared secret algorithm for this specification. If this is legacy specification,
    /// then throws exception.
    SharedSecret::Algorithm sharedSecret() const;
    
    /// Get algorithm(s) for digital signature calculation.
    const AlgorithmPair& getSignatureAlgorithms() const noexcept;
    
    /// Get algorithm(s) for constructing key-pairs.
    const AlgorithmPair& getSigningKeyPairAlgorithms() const noexcept;
    
    /// Get new KeyPairFactory instance that allows you to construct key-pair for signature
    /// calculation or verification.
    const cc7::crypto::KeyPairFactoryPtr getSigningKeyPairFactory() const;
        
    /// Look for specification by algorithm enumeration.
    /// - Parameter algorithm: Algorithm to look for.
    /// - Returns: Pointer to specification or `nullptr` if no such algorithm exists.
    static PowerAuthSpec const * const specForAlgorithm(Algorithm algorithm) noexcept;
    /// Look for specification by byte representing algorithm identifier.
    /// - Parameter algorithm: Algorithm to look for.
    /// - Returns: Pointer to specification or `nullptr` if no such algorithm exists.
    static PowerAuthSpec const * const specForAlgorithmId(cc7::byte algorithm) noexcept;
    
private:
    
    PowerAuthSpec(Algorithm algorithm,
                  ProtocolVersion version,
                  const std::string& name,
                  SharedSecretSpecPtr sharedSecret,
                  AlgorithmPair signature_algorithms,
                  AlgorithmPair signing_key_pair_algorithms);
    
    Algorithm _algorithm;
    ProtocolVersion _protocol_version;
    std::string _name;
    SharedSecretSpecPtr _shared_secret;
    AlgorithmPair _signature_algorithms;
    AlgorithmPair _signing_key_pair_algorithms;
    
    static const PowerAuthSpec spec_LEGACY_P256;
    static const PowerAuthSpec spec_EC_P384;
    static const PowerAuthSpec spec_EC_P384_ML_L3;
};

typedef PowerAuthSpec const * PowerAuthSpecPtr;
typedef PowerAuthSpec const * const ConstPowerAuthSpecPtr;

} // namespace powerAuth
