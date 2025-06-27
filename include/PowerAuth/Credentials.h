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

/// The `Credentials` class contains key encryption keys (KEKs) for all used factors for authentication. The following combination of factors
/// are supported:
/// - `POSSESSION` - authentication with possession only factor will be performed.
/// - `POSSESSION_KNOWLEDGE` - authentication with combination of knowledge and possession factors will be performed.
/// - `POSSESSION_BIOMETRY` - authentication with combination of knowledge and biometry factors will be performed.
class Credentials
{
public:
    
    /// Construct credentials object for authentication with possession-only factor.
    /// - Parameter possesion_kek: KEK for possession factor key.
    /// - Returns: Credentials object configured for authentication with possession-only factors.
    static std::shared_ptr<Credentials> possession() noexcept;
    
    /// Construct credentials object for authentication with possession and knowledge factor.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key.
    ///   - password: KEK for knowledge factor key (e.g. user's password).
    /// - Returns: Credentials object configured for authentication with possession and knowledge factors.
    static std::shared_ptr<Credentials> knowledge(const cc7::ByteRange& password) noexcept;
        
    /// Construct credentials object for authentication with possession and knowledge factor.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key.
    ///   - biometry_kek: KEK for biometry factor key.
    /// - Returns: Credentials object configured for activation persistence with selected factors.
    static std::shared_ptr<Credentials> biometry(const cc7::ByteRange& biometry_kek) noexcept;
        
    /// Return KEK for knowledge factor key. Note that knowledge factor is still represented as plaintext password and
    /// needs to be transformed to actual KEK with appropriate password KDF function.
    /// - Throws: `PowerAuthException` with `EC_InternalError` code if knowledge factor is not configured.
    const cc7::ByteArray& knowledgeKEK() const;
    
    /// Return KEK for biometry factor key.
    /// - Throws: `PowerAuthException` with `EC_InternalError` code if biometry factor is not configured.
    const cc7::ByteArray& biometryKEK() const;

    /// Return factors involved in authentication with this object.
    AuthFactors factors() const noexcept;
    
    /// Returns string representation of factors involved in authentication with this object.
    std::string factorsString() const noexcept;
    
    /// Validate credentials object for given version of protocol.
    /// - Parameter version: Version of protocol.
    /// - Throws:
    ///   - `PowerAuthException` with `EC_InternalError` code if unsupported version is used.
    ///   - `PowerAuthException` with `EC_WrongParameter` code if keys with wrong size provided.
    void validate(ProtocolVersion version) const;
        
private:
    Credentials(AuthFactors factors,
                const cc7::ByteRange& knowledge,
                const cc7::ByteRange& biometry) noexcept;
    
    const AuthFactors _factors;
    const cc7::ByteArray _knowledge;
    const cc7::ByteArray _biometry;
};

CC7_SHARED_PTR(Credentials)

/// The `InitialCredentials` class contains initial key encryption keys (KEKs) for all used factors for future authentication.
class InitialCredentials
{
public:
    /// Construct credentials object for initial configuration of authentication factors.
    /// - Parameters:
    ///   - possesion_kek: KEK for possession factor key. This key is mandatory.
    ///   - password: KEK for knowledge factor key (e.g. user's password). This key is mandatory.
    ///   - biometry_kek: KEK for biometry factor key. This key is optional.
    /// - Returns: Credentuals object configured for authentication with possession and knowledge factors.
    static std::shared_ptr<InitialCredentials> credentials(const cc7::ByteRange& password,
                                                           const cc7::ByteRange& biometry_kek = cc7::ByteRange()) noexcept;
        
    /// Return KEK for knowledge factor key. Note that knowledge factor is still represented as plaintext password and
    /// needs to be transformed to actual KEK with appropriate password KDF function.
    /// - Throws: `PowerAuthException` with `EC_InternalError` code if knowledge factor is not configured.
    const cc7::ByteArray& knowledgeKEK() const noexcept;
    
    /// Return KEK for biometry factor key. If factor is not set, then the returned range is empty.
    const cc7::ByteArray& biometryKEK() const noexcept;
    
    /// Return `true` if biometry KEK is configured.
    bool hasBiometryKEK() const noexcept;
    
    /// Validate credentials object for given version of protocol.
    /// - Parameter version: Version of protocol.
    /// - Throws:
    ///   - `PowerAuthException` with `EC_InternalError` code if unsupported version is used.
    ///   - `PowerAuthException` with `EC_WrongParameter` code if keys with wrong size provided.
    void validate(ProtocolVersion version) const;
    
private:
    InitialCredentials(const cc7::ByteRange& password_kek,
                       const cc7::ByteRange& biometry_kek) noexcept;
    
    const cc7::ByteArray _knowledge;
    const cc7::ByteArray _biometry;
};

CC7_SHARED_PTR(InitialCredentials)

} // namespace powerAuth
