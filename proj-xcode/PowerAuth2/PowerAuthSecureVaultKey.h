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

#import <PowerAuth2/PowerAuthSecureData.h>

@class PowerAuthCoreData;

/// The `PowerAuthVaultKeyId` enumeration defines the types of vault keys
/// supported in the PowerAuth Mobile SDK.
typedef NS_ENUM(int, PowerAuthSecureVaultKeyId) {
    /// This type of vault key can be provided after successful 2FA authentication
    /// on the server.
    PowerAuthSecureVaultKeyId_KnowledgeOrBiometry = 1,
    /// This type of vault key can be provided after authentication with the user's password.
    PowerAuthSecureVaultKeyId_Knowledge = 2,
};

/// The `PowerAuthSecureVaultKey` class represents a vault encryption key
/// available for application use. The key is typically obtained as part of
/// the activation process, allowing the application to encrypt sensitive data
/// during activation. It can later be retrieved from the server after successful
/// authentication.
@interface PowerAuthSecureVaultKey : NSObject

/// Default initialization is unavailable.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Identifier of the vault encryption key stored in this object.
@property (nonatomic, readonly) PowerAuthSecureVaultKeyId keyId;

/// Derives another key from this key, allowing creation of a chain of
/// separated keys.
///
/// - Parameters:
///   - index: Derivation index.
///   - keySize: Size of derived key in bytes. Minimum is 16 bytes.
///   - error: Pointer to an error object that is set in case of failure.
/// - Returns: A derived key, or `nil` if the operation fails.
- (nullable PowerAuthSecureData*) deriveKeyWithIndex:(UInt64)index
                                             keySize:(UInt64)keySize
                                               error:(NSError*_Nullable*_Nullable)error
                                NS_SWIFT_NAME(deriveKey(withIndex:keySize:));

/// Compare two vault encryption keys.
/// - Parameter other: Other key to compare.
/// - Returns: `YES` if both keys are equal.
- (BOOL) isEqualToVaultEncryptionKey:(nullable PowerAuthSecureVaultKey*)other;

@end
