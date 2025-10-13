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

#include <PowerAuth/Credentials.h>
#include <PowerAuth/Service.h>
#include <cc7/crypto/Crypto.h>

namespace powerAuth {

/// The `ISecretKeys` class defines interface that provide access to the various secret keys.
/// Each method providing key returns `ByteRange` and therefore the lifetime of range is limited
/// by the lifetime of this object.
/// 
/// The interface provides methods for getting keys for both, V3 and V4 versions, but the actual
/// interface implementations support only specific protocol version. If this is important, then
/// call `protocolVersion()` to determine the actual protocol supported.
/// 
/// All methods throws the following exceptions:
///  
/// - `PowerAuthException` with `EC_NotAllowed` if the key is not available at the time.
class ISecretKeys : public cc7::BaseObject
{
public:
    
    /// Return protocol version supported by the instance of the object.
    virtual ProtocolVersion protocolVersion() const noexcept = 0;
    
    
    // Authentication
    
    /// Get possession factor key for authentication code calculation.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4:`KEY_AUTHENTICATION_CODE_POSSESSION`
    /// - V3:`KEY_SIGNATURE_POSSESSION`
    virtual cc7::ByteRange keyAuthenticationCodePossession() = 0;
    /// Get knowledge factor key for authentication code calculation.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_AUTHENTICATION_CODE_KNOWLEDGE`
    /// - V3: `KEY_SIGNATURE_KNOWLEDGE`
    virtual cc7::ByteRange keyAuthenticationCodeKnowledge() = 0;
    /// Get biometry factor key for authentication code calculation.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_AUTHENTICATION_CODE_BIOMETRY`
    /// - V3: `KEY_SIGNATURE_BIOMETRY`
    virtual cc7::ByteRange keyAuthenticationCodeBiometry() = 0;

    /// Update knowledge factor keys.
    ///
    /// Be aware that the secret keys object has to be created with credentials
    /// with the knowledge KEK set to old, verified password. This is the typical
    /// "change password" sequence:
    ///
    /// ```cpp
    /// auto old_credentials = Credentials::knowledge(old_password);
    /// auto secrets = keyProvider->unlockSecretKeys(*credentials);
    /// if (secrets->protocolVersion() == Version_V3) {
    ///    // V3 doesn't use new factor key
    ///    secrets->updateKeyAuthenticationCodeKnowledge(cc7::ByteRange(), new_password);
    /// } else {
    ///    // V4 require new factor key. The key is deduced with using "shared secret" protocol.
    ///    secrets->updateKeyAuthenticationCodeKnowledge(new_factor_key, new_password);
    /// }
    /// keyProvider->lockSecretKeys(secrets);
    /// ```
    ///
    /// Protocol versions: V3, V4
    ///
    /// Updated keys:
    /// - V4: `KEY_AUTHENTICATION_CODE_KNOWLEDGE`, `KEK_AUTHENTICATION_CODE_KNOWLEDGE`, `CKEY_AUTHENTICATION_CODE_KNOWLEDGE`
    /// - V3: key protecting `KEY_SIGNATURE_KNOWLEDGE`, `CKEY_SIGNATURE_KNOWLEDGE`
    ///
    /// - Parameters:
    ///   - new_key: New knowledge factor key. The parameter is mandatory for V4 and ignored in V3 protocol.
    ///   - new_kek: New password protecting knowledge factor key. The parameter is mandatory for V4 and V3 protocols.
    virtual void updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_key,
                                                      const cc7::ByteRange& new_kek) = 0;
    /// Update biometry factor keys.
    ///
    /// Be aware that biometry key update differs between protocol versions:
    /// - For V4, we receive `new_key` from the server.
    /// - For V3, we have to deduce `new_key` from shared secret, so `kekDevicePrivate()` must be available.
    ///
    /// Here's example of processing:
    /// ```cpp
    /// if (keyProvider->protocolVersion() == Version_V3) {
    ///    // V3 must deduce biometric factor key from the shared secret.
    ///    auto secrets = keyProvider->unlockVaultKey(VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
    ///    secrets->updateKeyAuthenticationCodeBiometry(ByteRange(), new_kek);
    ///    keyProvider->lockSecretKeys(secrets);
    /// } else {
    ///    // V4 require new factor key. The key is deduced with using "shared secret" protocol.
    ///    auto secrets = keyProvider->unlockSecretKeys();
    ///    secrets->updateKeyAuthenticationCodeBiometry(new_key, new_kek);
    ///    keyProvider->lockSecretKeys(secrets);
    /// }
    /// ```
    ///
    /// Protocol versions: V3, V4
    ///
    /// Updated keys:
    /// - V4: `KEY_AUTHENTICATION_CODE_BIOMETRY`, `KEK_AUTHENTICATION_CODE_BIOMETRY`, `CKEY_AUTHENTICATION_CODE_BIOMETRY`
    /// - V3: key protecting `KEY_SIGNATURE_BIOMETRY`, `CKEY_SIGNATURE_BIOMETRY`
    ///
    /// - Parameters:
    ///   - new_key: New biometry factor key. The parameter is mandatory for V4 and ignored in V3 protocol.
    ///   - new_kek: New key encryption key protecting the knowledge factor key. The parameter is mandatory for V4 and V3 protocols.
    virtual void updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_key,
                                                     const cc7::ByteRange& new_kek) = 0;
    
    /// Remove the biometry factor key and KEK protecting the key.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Updated keys: `KEY_AUTHENTICATION_CODE_BIOMETRY`, `KEK_AUTHENTICATION_CODE_BIOMETRY`
    virtual void removeKeyAuthenticationCodeBiometry() = 0;

    // Encryption
    
    /// Get the key derived from the device specific data.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KEK_DEVICE_PRIVATE`
    virtual cc7::ByteRange keyDeviceSpecific() = 0;
    
    /// Get key for local data encryption.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_LOCAL_DATA`
    /// - V3: Name not specified, but key is identical to KEK protecting knowledge factor key.
    virtual cc7::ByteRange keyLocalData() = 0;
    
    
    // Vault
    
    /// Get the key encrypting device private key.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEK_DEVICE_PRIVATE`
    /// - V3: `KEY_ENCRYPTION_VAULT`
    virtual cc7::ByteRange kekDevicePrivate() = 0;
    
    /// Get the key encrypting application specific data after successful authentication
    /// with the knowledge factor.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KDK_APP_VAULT_KNOWLEDGE`
    virtual cc7::ByteRange kdkAppVaultKnowledge() = 0;
    
    /// Get the key encrypting application specific data after successful authentication
    /// with knowledge or biometry factor.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KDK_APP_VAULT_2FA`
    virtual cc7::ByteRange kdkAppVault2FA() = 0;
    
    
    // Utility
    
    /// Get the key for computing MAC from hash based counter.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_MAC_CTR_DATA`
    /// - V3: `KEY_TRANSPORT_CTR`
    virtual cc7::ByteRange keyMacCtrData() = 0;
    
    /// Get the key for computing MAC from activation status blob.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KEY_MAC_STATUS`.
    virtual cc7::ByteRange keyMacStatus() = 0;
    
    /// Get the key for signing payload in getting temporary key request in application scope.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_MAC_GET_APP_TEMP_KEY`.
    /// - V3: name not defined
    virtual cc7::ByteRange keyMacGetAppTempKey() = 0;
    
    /// Get the key for signing payload in getting temporary key request in activation scope.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_MAC_GET_ACT_TEMP_KEY`.
    /// - V3: name not defined
    virtual cc7::ByteRange keyMacGetActTempKey() = 0;
    
    /// Get the key for validate MAC for personalized data, typically displayed as QR code.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KEY_MAC_PERSONALIZED_DATA`.
    virtual cc7::ByteRange keyMacPersonalizedData() = 0;
    
    /// Get the key for `SHARED_INFO_2` calculation for End-To-End Encryption.
    ///
    /// Protocol versions: V3, V4
    ///
    /// Key name:
    /// - V4: `KEY_MAC_PERSONALIZED_DATA`
    /// - V3: name not defined
    virtual cc7::ByteRange keyE2EESharedInfo2() = 0;
    
    /// Get the key derivation key for application specific purposes.
    ///
    /// Protocol versions: V4
    ///
    /// Key name: `KDK_APP_UTILITY`.
    virtual cc7::ByteRange kdkAppUtility() = 0;
    
    
    // Other
    
    /// Get the pointer to device private key.
    ///
    /// - Warning: The returned key is sealed.
    ///
    /// Protocol version V3, V4
    ///
    /// Key name: `KEY_DEVICE_PRIVATE`
    virtual const cc7::crypto::PrivateKeyPtr& getDevicePrivateKeyPtr() = 0;
    
    /// Get the device private key.
    ///
    /// - Warning: The returned key is sealed.
    ///
    /// Protocol version V3, V4
    ///
    /// Key name: `KEY_DEVICE_PRIVATE`
    const cc7::crypto::PrivateKey& devicePrivateKey();
    
    // Legacy
    
    /// Get the legacy transport key.
    ///
    /// Protocol version: V3
    ///
    /// Key name: `KEY_TRANSPORT`
    virtual cc7::ByteRange legacyKeyTransport() = 0;
    
    /// Get the legacy key for computing IV for activation status blob encryption.
    ///
    /// Protocol version: V3
    ///
    /// Key name: `KEY_TRANSPORT_IV`
    virtual cc7::ByteRange legacyKeyTransportIV() = 0;
};


// Note that unique_ptr<> is better choice for ISecretKeys than shared_ptr<>. The goal is to
// limit the lifetime of the object as much as possible.

typedef std::unique_ptr<ISecretKeys> ISecretKeysPtr;

/// The `VaultKeyType` enumeration defines types of vault keys available.
enum class VaultKeyType
{
    /// Key encryption key for accessing device private key.
    ///
    /// This key is defined in protocol version 4 and is equal to `KEY_ENCRYPTION_VAULT`
    /// for protocol version 3.
    KEK_DEVICE_PRIVATE,
    /// Application specific key derivation key, available after user authenticate
    /// on the server with possession and knowledge factors.
    ///
    /// This key is defined in protocol version 4.0.
    KDK_APP_VAULT_KNOWLEDGE,
    /// Application specific key derivation key, available after user authenticate
    /// on the server with with possession and knowledge, or possession and biometry
    /// factors.
    /// 
    /// This key is defined in protocol version 4.0.
    KDK_APP_VAULT_2FA
};

/// The `IKeyProvider` abstract class defines interface for retrieving keys for various
/// cryptographic operations.
class IKeyProvider
{
public:
    /// Return instance of this `IKeyProvider` implementing `IService` interface.
    /// This means that class implementing the key provider interface must be also a service.
    virtual IServicePtr asService() = 0;
    
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
    
    /// Acquire interface providing secret keys for computing signature with requested factors.
    /// The method should fail for `POSSESSION_BIOMETRY` factors or if implementation supports V3 protocol.
    /// The method is useful for computing authentication code during the pending registration process.
    ///
    /// - Parameter factors: Prepare keys for factors.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.
    virtual ISecretKeysPtr unlockSecretKeysForFactors(AuthFactors factors) = 0;

    /// Acquire interface providing vault key. If the secret keys are no longer required for performed
    /// cryptographic operation, then you must call `lockSecretKeys()` and give the object back
    /// to the `KeyProvider`.
    ///
    /// - Parameter vault_key_type: Type of vault key to unlock.
    /// - Parameter vault_key: Vault key data received from the server.
    /// - Returns: Unique pointer to `ISecretKeys` interface.
    /// - Throws:
    ///     - `PowerAuthException` with code `EC_MissingActivation` if there's no activation available.
    ///     - `PowerAuthException` with code `EC_NotAllowed` if secret keys are already acquired.
    virtual ISecretKeysPtr unlockVaultKey(VaultKeyType vault_key_type,
                                          const cc7::ByteRange& vault_key) = 0;
    
    /// Acquire interface providing secret keys and vault key. The provided authentication object
    /// determine what keys will be available in the returned structure. If the secret keys are no
    /// longer required for performed cryptographic operation, then you must call `lockSecretKeys()`
    /// and give the object back to the `KeyProvider`.
    ///
    /// - Parameter credentials: Authentication object that determine level of available keys.
    /// - Parameter vault_key_type: Type of vault key to unlock.
    /// - Parameter vault_key: Vault key data received from the server.
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
