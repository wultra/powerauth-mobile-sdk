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

#include <PowerAuth/MemoryCleanupListener.h>
#include <PowerAuth/Credentials.h>
#include <cc7/crypto/Crypto.h>

namespace powerAuth {

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
    virtual cc7::ByteRange keyAuthenticationCodePossession() = 0;
    virtual cc7::ByteRange keyAuthenticationCodeKnowledge() = 0;
    virtual cc7::ByteRange keyAuthenticationCodeBiometry() = 0;

    virtual void updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_key,
                                                      const cc7::ByteRange& new_kek) = 0;
    virtual void updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_key,
                                                     const cc7::ByteRange& new_kek) = 0;
    virtual void removeKeyAuthenticationCodeBiometry() = 0;

    // Encryption
    virtual cc7::ByteRange keyDeviceSpecific() = 0;
    virtual cc7::ByteRange keyLocalData() = 0;
    // Vault
    virtual cc7::ByteRange kekDevicePrivate() = 0;
    virtual cc7::ByteRange kdkAppVaultKnowledge() = 0;
    virtual cc7::ByteRange kdkAppVault2FA() = 0;
    
    // Utility
    virtual cc7::ByteRange keyMacCtrData() = 0;
    virtual cc7::ByteRange keyMacStatus() = 0;
    virtual cc7::ByteRange keyMacGetAppTempKey() = 0;
    virtual cc7::ByteRange keyMacGetActTempKey() = 0;
    virtual cc7::ByteRange keyMacPersonalizedData() = 0;
    virtual cc7::ByteRange keyE2EESharedInfo2() = 0;
    virtual cc7::ByteRange kdkAppUtility() = 0;
    
    // Other
    virtual const cc7::crypto::PrivateKey& devicePrivateKey() = 0;
    
    // Legacy
    virtual cc7::ByteRange legacyKeyVault() = 0;
    virtual cc7::ByteRange legacyKeyTransport() = 0;
    virtual cc7::ByteRange legacyKeyTransportIV() = 0;
    virtual cc7::ByteRange legacyKeyTransportCTR() = 0;
};


// Note that unique_ptr<> is better choice for ISecretKeys than shared_ptr<>. The goal is to
// limit the lifetime of the object as much as possible.

typedef std::unique_ptr<ISecretKeys> ISecretKeysPtr;

/// The `VaultKeyType` enumeration defines types of vault keys available.
enum class VaultKeyType
{
    /// Key encryption key for accessing device private key.
    /// This key is defined in protocol version 4.0.
    KEK_DEVICE_PRIVATE,
    /// Application specific key derivation key, available after user authenticate
    /// on the server with possession and knowledge factors.
    /// /// This key is defined in protocol version 4.0.
    KDK_APP_VAULT_KNOWLEDGE,
    /// Application specific key derivation key, available after user authenticate
    /// on the server with with possession and knowledge, or possession and biometry
    /// factors.
    /// /// This key is defined in protocol version 4.0.
    KDK_APP_VAULT_2FA,
    /// Legacy vault key for accessing device private key and factor keys in protocol
    /// version 3.0.
    ///
    /// The legacy vault key was replaced with other vault key types in protocol 4.0.
    LEGACY,
};

/// The `IKeyProvider` abstract class defines interface for retrieving keys for various
/// cryptographic operations.
class IKeyProvider : public MemoryCleanupListener
{
public:
    
    using MemoryCleanupListener::clearSensitiveData;
    using MemoryCleanupListener::restoreSensitiveData;
    
    /// Return protocol version supported by the instance of the object.
    virtual ProtocolVersion protocolVersion() const noexcept = 0;
    
    /// Return master server public key.
    /// - Returns: Smart pointer with master server public key.
    /// - Throws: `PowerAuthException` in case the key cannot be constructed.
    virtual cc7::crypto::ConstPublicKeyPtr getMasterServerPublicKeyPtr() = 0;
    
    /// Return device's public key.
    /// - Returns: Smart pointer with device public key.
    /// - Note: Be aware that method may fail also when the secret keys are unlocked.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    virtual cc7::crypto::ConstPublicKeyPtr getDevicePublicKeyPtr() = 0;
    
    /// Return server public key.
    /// - Returns: Smart pointer with server public key.
    /// - Note: Be aware that method may fail also when the secret keys are unlocked.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    virtual cc7::crypto::ConstPublicKeyPtr getServerPublicKeyPtr() = 0;
    
    /// Return master server public key.
    /// - Returns: Reference to master server public key.
    /// - Throws: `PowerAuthException` in case the key cannot be constructed.
    const cc7::crypto::PublicKey& masterServerPublicKey();
    
    /// Return device's public key.
    /// - Returns: Reference to device public key.
    /// - Note: Be aware that method may fail also when the secret keys are unlocked.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    const cc7::crypto::PublicKey& devicePublicKey();
    
    /// Return server public key.
    /// - Returns: Reference to server public key.
    /// - Note: Be aware that method may fail also when the secret keys are unlocked.
    /// - Throws: `PowerAuthException` in case the key is not available or cannot be constructed.
    const cc7::crypto::PublicKey& serverPublicKey();
    
    
    /// Clears activation related keys.
    virtual void clearActivationKeys() noexcept = 0;
    
    /// Acquire interface providing secret keys. In this call, only secret keys independent on activation
    /// are unlocked. If the secret keys are no longer required for performed cryptographic operation, then
    /// you must call `lockSecretKeys()` and give the object back to the `KeyProvider`.
    ///
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.
    virtual ISecretKeysPtr unlockSecretKeys() = 0;

    /// Acquire interface providing initial secret keys during an activation process. If the secret keys
    /// are no longer required for performed cryptographic operation, then you must call `lockSecretKeys()`
    /// and give the object back to the `KeyProvider`.
    ///
    /// - Parameter credentials: Initial credentials.
    /// - Parameter shared_secret: Shared secret agreed with the server.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.
    virtual ISecretKeysPtr unlockInitialSecretKeys(const InitialCredentials& credentials, const cc7::ByteArray& shared_secret) = 0;
        
    /// Acquire interface providing secret keys. The provided authentication object determine what keys
    /// will be available in the returned structure. If the secret keys are no longer required for
    /// performed cryptographic operation, then you must call `lockSecretKeys()` and give the object
    /// back to the `KeyProvider`.
    ///
    /// - Parameter credentials: Authentication object that determine level of available keys.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.
    virtual ISecretKeysPtr unlockSecretKeys(const Credentials& auth) = 0;
    
    /// Acquire interface providing secret keys and vault key. The provided authentication object
    /// determine what keys will be available in the returned structure. If the secret keys are no
    /// longer required for performed cryptographic operation, then you must call `lockSecretKeys()`
    /// and give the object back to the `KeyProvider`.
    ///
    /// - Parameter credentials: Authentication object that determine level of available keys.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.

    virtual ISecretKeysPtr unlockVaultAndSecretKeys(const Credentials& credentials,
                                                    VaultKeyType vault_key_type,
                                                    const cc7::ByteRange& vault_key) = 0;
    
    /// Return previously acquired `ISecretKeys` interface. You must call this method at the end of work
    /// with the secret keys.
    /// - Parameter secret_keys: Pointer to previously acquired secret keys.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_NotAllowed` if no keys interface previously acquired.
    virtual void lockSecretKeys(ISecretKeysPtr & secret_keys) = 0;
};

CC7_SHARED_PTR(IKeyProvider)

} // namespace powerAuth
