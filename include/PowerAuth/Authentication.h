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
#include <PowerAuth/Password.h>

namespace powerAuth {

/// The `Authentication` class contains key encryption keys (KEKs) for all used factors for authentication. The following combination of factors
/// are supported:
/// - `POSSESSION` - authentication with possession only factor will be performed.
/// - `POSSESSION_KNOWLEDGE` - authentication with combination of knowledge and possession factors will be performed.
/// - `POSSESSION_BIOMETRY` - authentication with combination of knowledge and biometry factors will be performed.
///
class Authentication
{
public:
    // Copy & Move constructors
    Authentication(const Authentication& other) = default;
    Authentication(Authentication&& other) = default;
    
    // Copy & Move assign operators
    Authentication& operator=(const Authentication&) = default;
    Authentication& operator=(Authentication&&) = default;

    // Public object construction
    
    /// Construct authentication object for authentication with possession-only factor.
    /// - Parameter possesion_kek: KEK for possession factor key.
    /// - Returns: Authentication object configured for authentication with possession-only factors.
    static Authentication possession(const cc7::ByteRange& possesion_kek) noexcept;
    
    /// Construct authentication object for authentication with possession and knowledge factor.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key.
    ///   - password: KEK for knowledge factor key (e.g. user's passphrase).
    /// - Returns: Authentication object configured for authentication with possession and knowledge factors.
    static Authentication knowledge(const cc7::ByteRange& possesion_kek, const cc7::ByteRange& password) noexcept;
    
    /// Construct authentication object for authentication with possession and knowledge factor.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key.
    ///   - password: Password object that contains KEK for knowledge factor key.
    /// - Returns: Authentication object configured for authentication with possession and knowledge factors.
    static Authentication knowledge(const cc7::ByteRange& possesion_kek, const Password& password) noexcept;
    
    /// Construct authentication object for authentication with possession and knowledge factor.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key.
    ///   - biometry_kek: KEK for biometry factor key.
    /// - Returns: Authentication object configured for authentication with possession and biometry factors.
    static Authentication biometry(const cc7::ByteRange& possesion_kek, const cc7::ByteRange& biometry_kek) noexcept;
    
    /// Return KEK for possession factor key.
    const cc7::ByteArray& possessionKEK() const noexcept;
    
    /// Return KEK for knowledge factor key.
    /// - Throws: `PowerAuthException` with `EC_InternalError` code if knowledge factor is not configured.
    const cc7::ByteArray& knowledgeKEK() const;
    
    /// Return KEK for biometry factor key.
    /// - Throws: `PowerAuthException` with `EC_InternalError` code if biometry factor is not configured.
    const cc7::ByteArray& biometryKEK() const;

    /// Return factors involved in authentication with this object.
    AuthFactors factors() const noexcept;
    
    /// Returns string representation of factors involved in authentication with this object.
    std::string factorsString() const noexcept;
    
    /// Validate authentication object for given version of protocol.
    /// - Parameter version: Version of protocol.
    /// - Throws:
    ///   - `PowerAuthException` with `EC_InternalError` code if unsupported version is used.
    ///   - `PowerAuthException` with `EC_WrongParameter` code if keys with wrong size provided.
    void validate(ProtocolVersion version) const;
        
private:
    Authentication(AuthFactors factors,
                   const cc7::ByteRange& possession,
                   const cc7::ByteRange& knowledge,
                   const cc7::ByteRange& biometry) noexcept;
    
    AuthFactors _factors;
    cc7::ByteArray _possession;
    cc7::ByteArray _knowledge;
    cc7::ByteArray _biometry;
};

} // namespace powerAuth
