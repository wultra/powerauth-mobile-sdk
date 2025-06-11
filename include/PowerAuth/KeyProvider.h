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
#include <PowerAuth/Authentication.h>
#include <cc7/crypto/Crypto.h>

namespace powerAuth {

/// The `IPublicKeys` class defines interface that provide access to
/// the various public keys.
class IPublicKeys : public cc7::BaseObject
{
public:
    virtual ~IPublicKeys() = default;
    
    /// Return protocol version supported by the instance of the object.
    virtual ProtocolVersion protocolVersion() const = 0;
    
    /// Return master server public key.
    /// - Throws: `PowerAuthException` in case the key cannot be constructed.
    virtual const cc7::crypto::PublicKey& masterServerPublicKey() = 0;
    
    /// Return server public key.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    virtual const cc7::crypto::PublicKey& serverPublicKey() = 0;
    
    /// Return device's public key.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    virtual const cc7::crypto::PublicKey& devicePublicKey() = 0;
};


typedef std::shared_ptr<IPublicKeys> IPublicKeysPtr;

/// The `ISecretKeys` class defines interface that provide access to the various secret keys.
///
/// All methods throws the following exceptions:
///
/// - `PowerAuthException` with `EC_NotAllowed` if the key is not available at the time.
class ISecretKeys : public cc7::BaseObject
{
public:
    /// Return protocol version supported by the instance of the object.
    virtual ProtocolVersion protocolVersion() const = 0;
    
    // Authentication
    virtual const cc7::ByteRange& keyAuthenticationCodePossession() = 0;
    virtual const cc7::ByteRange& keyAuthenticationCodeKnowledge() = 0;
    virtual const cc7::ByteRange& keyAuthenticationCodeBiometry() = 0;
    
    virtual void updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_knowledge_key) = 0;
    virtual void updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_biometry_key) = 0;
    
    virtual const cc7::ByteRange& kdkAuthenticationCode() = 0;
    
    // Encryption
    virtual const cc7::ByteRange& kdkEncryption() = 0;
    
    // Vault
    virtual const cc7::ByteRange& kdkVault() = 0;
    virtual const cc7::ByteRange& kdkAppVaultKnowledge() = 0;
    virtual const cc7::ByteRange& kdkAppVault2FA() = 0;
    
    // Utility
    virtual const cc7::ByteRange& kdkUtility() = 0;
    virtual const cc7::ByteRange& keyMacCtrData() = 0;
    virtual const cc7::ByteRange& keyMacStatus() = 0;
    virtual const cc7::ByteRange& keyMacGetAppTempKey() = 0;
    virtual const cc7::ByteRange& keyMacGetActTempKey() = 0;
    virtual const cc7::ByteRange& keyMacPersonalizedData() = 0;
    virtual const cc7::ByteRange& keyE2EESharedInfo2() = 0;
    virtual const cc7::ByteRange& kdkAppUtility() = 0;
    
    // Other
    virtual const cc7::ByteRange& keyActivationSecret() = 0;
    virtual const cc7::crypto::PrivateKey& devicePrivateKey() = 0;
    
    // Legacy
    virtual const cc7::ByteRange& legacyKeyTransport() = 0;
    virtual const cc7::ByteRange& legacyKeyTransportIV() = 0;
    virtual const cc7::ByteRange& legacyKeyTransportCTR() = 0;
};


// Note that unique_ptr<> is better choice for ISecretKeys than shared_ptr<>. We don't want
// to spread pointer to ISecretKeys over the code. You can only move the reference.

typedef std::unique_ptr<ISecretKeys> ISecretKeysPtr;

class IKeyProvider : public cc7::BaseObject
{
public:
    
    /// Returns reference to object implementing `IPublicKeys` interface.
    virtual IPublicKeys& publicKeys() = 0;
    
    /// Acquire interface providing secret keys. The provided authentication object determine what keys
    /// will be available in the returned structure. If the secret keys are no longer required for
    /// performed cryptographic operation, then you must call `returnSecretKeys()` and take the object
    /// back to the `KeyProvider`.
    ///
    /// - Parameter auth: Authentication object that determine level of available keys.
    /// - Parameter read_only: If true, then returned structure will not allow updating stored keys.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already borrowed.
    virtual ISecretKeysPtr borrowSecretKeys(const Authentication& auth, bool read_only = true) = 0;
    
    /// Return previously borrowed `ISecretKeys` interface. You must call this method at the end of work
    /// with the secret keys.
    /// - Parameter secret_keys: Pointer to previously borrowed secret keys.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_NotAllowed` if no secret keys are borrowed.
    virtual void returnSecretKeys(ISecretKeysPtr & secret_keys) = 0;
};

} // namespace powerAuth
