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

#import <PowerAuth2/PowerAuthMacros.h>

@class PowerAuthCoreData;

/// The `PowerAuthVaultKeyId` enumeration defines the types of vault keys
/// supported in the PowerAuth Mobile SDK.
typedef NS_ENUM(int, PowerAuthVaultEncryptionKeyId) {
    /// This type of vault key can be provided after successful 2FA authentication
    /// on the server.
    PowerAuthVaultEncryptionKeyId_KnowledgeOrBiometry,
    /// This type of vault key can be provided after authentication with the user's password.
    PowerAuthVaultEncryptionKeyId_Knowledge,
    /// This is a legacy key available only when PowerAuthSDK is still running on a legacy
    /// protocol version. The key can be provided after authentication with the user's password.
    PowerAuthVaultEncryptionKeyId_Legacy,
};

/// The `PowerAuthVaultEncryptionKey` class represents a vault encryption key
/// available for application use. The key is typically obtained as part of
/// the activation process, allowing the application to encrypt sensitive data
/// during activation. It can later be retrieved from the server after successful
/// authentication.
///
/// It is not recommended to persist this key on the device.
@interface PowerAuthVaultEncryptionKey : NSObject

/// Default initialization is unavailable.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Indicates whether this key is a base key.
/// If `YES`, the key should not be used directly — derive another key from it instead.
@property (nonatomic, readonly) BOOL baseKey;

/// Identifier of the vault encryption key stored in this object.
@property (nonatomic, readonly) PowerAuthVaultEncryptionKeyId keyId;

/// Derivation index used for key construction.
@property (nonatomic, readonly) UInt64 derivationIndex;

/// Vault encryption key data.
@property (nonatomic, readonly, strong, nonnull) PowerAuthCoreData *key;

/// Derives another key from this key, allowing creation of a chain of
/// separated keys.
/// If this is a legacy key, the function returns an error.
///
/// - Parameters:
///   - index: Derivation index.
///   - error: Pointer to an error object that is set in case of failure.
/// - Returns: A derived key, or `nil` if the operation fails.
- (nullable PowerAuthVaultEncryptionKey*) deriveKeyWithIndex:(UInt64)index
                                                       error:(NSError*_Nullable*_Nullable)error;

@end
