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
        /// - SharedSecret: DHKEM(P384, HKDF-SHA384)
        EC_P384,
        /// Protocol V4.0
        /// - Signatures: ECDSA with P384 + ML-DSA-65
        /// - SharedSecret: DHKEM(P384, HKDF-SHA384) + ML-KEM-768
        EC_P384_ML_L3,
        /// Protocol V4.0
        /// - Signatures: ECDSA with P384 + ML-DSA-87
        /// - SharedSecret: DHKEM(P384, HKDF-SHA384) + ML-KEM-1024
        EC_P384_ML_L5,
        
        // Experimental (not exposed to ObjC / Java)
        
        /// Protocol V4.0
        /// - Signatures: ML-DSA-65
        /// - SharedSecret: ML-KEM-768
        ML_L3,
        /// Protocol V4.0
        /// - Signatures: ML-DSA-87
        /// - SharedSecret: ML-KEM-1024
        ML_L5
    };
    
    /// Master key identifier used in binary configuration.
    enum MasterKeyId
    {
        /// V3: Legacy key using P-256.
        KEY_ID_P256     = 0x01,
        /// V4: P-384 key.
        KEY_ID_P384     = 0x02,
        /// V4: ML-DSA-65 key.
        KEY_ID_MLDSA65  = 0x03,
        /// V4: ML-DSA-87 key.
        KEY_ID_MLDSA87  = 0x04,
        
        /// No key specified.
        KEY_ID_NONE     = 0x00,
    };
    
    /// Master key specification, contains combination of key identifier
    /// and the serialization format.
    struct MasterKeySpec
    {
        /// Configuration's key identifier.
        MasterKeyId keyId;
        /// Key serialization format used in configuration.
        cc7::crypto::KeyFormat keyFormat;
    };

    /// Type defining two algorithm identifiers. If hybrid scheme is used,
    /// then `first` and `second` contains valid identifiers. For non-hybrid schemes,
    /// only `first` is set.
    typedef std::pair<std::string, std::string> AlgorithmPair;
    
    /// Type defines two master key specifications. If hybrid scheme is used,
    /// then `first` and `second` contains valid specification. For non-hybrid schemes,
    /// `second` has key identifier set to `KEY_ID_NONE`.
    typedef std::pair<MasterKeySpec, MasterKeySpec> MasterKeySpecPair;
    
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

    /// Get master key specifications for proper loading the key from the configuration.
    const MasterKeySpecPair& getMasterKeySpecs() const noexcept;
    
    /// Get algorithm(s) for digital signature calculation or verification.
    const AlgorithmPair& getSignatureAlgorithms() const noexcept;
    
    /// Get algorithm(s) for JWS digital signature calculation or verification.
    const AlgorithmPair& getJwsSignatureAlgorithms() const noexcept;
    
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
    /// Look for specification by string representing algorithm's name.
    /// - Parameter algorithm: Algorithm to look for.
    /// - Returns: Pointer to specification or `nullptr` if no such algorithm exists.
    static PowerAuthSpec const * const specForAlgorithmName(const std::string& algorithm) noexcept;
    
private:
    
    PowerAuthSpec(Algorithm algorithm,
                  ProtocolVersion version,
                  const std::string& name,
                  MasterKeySpecPair key_specs,
                  AlgorithmPair signature_algorithms,
                  AlgorithmPair jws_algorithms,
                  AlgorithmPair signing_key_pair_algorithms);
    
    Algorithm _algorithm;
    ProtocolVersion _protocol_version;
    std::string _name;
    MasterKeySpecPair _key_specs;
    AlgorithmPair _signature_algorithms;
    AlgorithmPair _jws_signature_algorithms;
    AlgorithmPair _signing_key_pair_algorithms;
    
    static const PowerAuthSpec spec_LEGACY_P256;
    static const PowerAuthSpec spec_EC_P384;
    static const PowerAuthSpec spec_EC_P384_ML_L3;
    static const PowerAuthSpec spec_EC_P384_ML_L5;
    static const PowerAuthSpec spec_ML_L3;
    static const PowerAuthSpec spec_ML_L5;
};

typedef PowerAuthSpec const * PowerAuthSpecPtr;
typedef PowerAuthSpec const * const ConstPowerAuthSpecPtr;

} // namespace powerAuth
