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

#include <PowerAuth/Service.h>
#include <PowerAuth/Request.h>
#include <PowerAuth/KeyProvider.h>

namespace powerAuth {

/// Enum defining the reason why a vault key is acquired from the server.
enum class UnlockVaultKeyReason
{
    /// The key is acquired for signing with a private key stored on the device.
    SIGN_WITH_DEVICE_PRIVATE_KEY,
    /// The key is acquired for application purposes, such as requesting an encryption key.
    FETCH_ENCRYPTION_KEY,
    /// The key is acquired for adding a biometric factor in protocol version 3 (legacy).
    LEGACY_ADD_BIOMETRY
};

/// The `VaultService` class provides access to the vault key.
class VaultService :
    public ServiceWithContext,
    public std::enable_shared_from_this<VaultService>
{
public:
    /// Construct service with context and the target protocol version.
    /// - Parameters:
    ///   - context: Context pointer.
    ///   - protocol_version: Protocol version/
    VaultService(const std::shared_ptr<Context>& context,
                 ProtocolVersion protocol_version);
    
    /// Callback called when vault key is properly acquired from the server. The callback gets initialized instance of
    /// key provider and properly initialized `ISecretKeys` interface.
    using Callback = std::function<ResponseObjectPtr(IKeyProvider& key_provider, ISecretKeys& secret_keys)>;

    /// Returns protocol version used in this service.
    ProtocolVersion protocolVersion() const noexcept;
    
    /// Get vault key from the server and create `ISecretKeys` interface with initialized chain of keys, containing the vault key.
    /// - Parameters:
    ///   - credentials: Credentials used for authentication on the server.
    ///   - vault_key_type: Vault key type to acquire.
    ///   - unlock_reason: Reason of accessing the vault key.
    ///   - callback: Callback called when vault key is properly acquired from the server.
    /// - Returns: HTTP request object.
    RequestPtr unlockVaultKey(const CredentialsPtr& credentials, VaultKeyType vault_key_type, UnlockVaultKeyReason unlock_reason, Callback callback) const;
    
    /// Fetch encryption key from the server and set `DataResponse` in request's response.
    /// - Parameters:
    ///   - credentials: Credentials used for authentication on the server.
    ///   - key_id: Encryption key identifier.
    ///   - index: Derivation index for legacy key.
    /// - Returns: HTTP request object.
    RequestPtr fetchVaultEncryptionKey(const CredentialsPtr& credentials, SecureVaultKeyId key_id, cc7::U64 index) const;
    
    /// Derive existing vault encryption key into another key.
    /// - Parameters:
    ///   - key: Key material to derive.
    ///   - index: Derivation index.
    ///   - key_size: Size of derived key in bytes. Minimum is 16 bytes.
    ///   - key_id: Identifier of current vault key.
    /// - Returns: Derived key.
    static cc7::ByteArray deriveVaultEncryptionKey(const cc7::ByteRange& key, cc7::U64 index, cc7::U64 key_size, SecureVaultKeyId key_id);
    
    /// Create instance of service for given protocol version.
    /// - Parameters:
    ///   - context: Context object.
    ///   - protocol_version: Protocol version.
    /// - Returns: Smart pointer with new service instance configured for requested protocol version.
    static std::shared_ptr<VaultService> getInstance(const std::shared_ptr<Context>& context, ProtocolVersion protocol_version) noexcept;
    
    /// Convert value of `UnlockVaultKeyReason` enumeration into the string representation.
    /// - Parameter reason: Reason to convert.
    /// - Returns: String representation of reason.
    static std::string unlockVaultKeyReasonToString(UnlockVaultKeyReason reason);
    
    /// Convert value of `VaultKeyType` enumeration into the string representation.
    /// - Parameter key_type: Key type to convert.
    /// - Returns: String representation of key type.
    static std::string vaultKeyTypeToString(VaultKeyType key_type);
    
private:

    /// Process response containing vault encryption key, received from the server.
    /// - Parameters:
    ///   - context: Reference to `Context`.
    ///   - vault_key_type: Type of vault key received.
    ///   - raw_encryption_key: Raw encryption key data received from the server.
    ///   - callback: Completion callback.
    /// - Returns: Response object returned from the callback.
    ResponseObjectPtr processVaultKeyResponse(Context& context, VaultKeyType vault_key_type, const cc7::ByteRange& raw_encryption_key, const Callback& callback) const;
    
    /// Process response from fetching encryption key.
    /// - Parameters:
    ///   - context: Context object.
    ///   - secret_keys: `ISecretKeys` instance.
    ///   - key_id: Vault key identifier.
    ///   - index: Derivation index for legacy key.
    /// - Returns: `DataResponse` object.
    ResponseObjectPtr processVaultEncryptionKeyResponse(Context& context, ISecretKeys& secret_keys, SecureVaultKeyId key_id, cc7::U64 index) const;
    
    const IKeyProviderPtr _key_provider;
    const ProtocolVersion _protocol_version;
};

CC7_SHARED_PTR(VaultService)

} // namespace powerAuth

