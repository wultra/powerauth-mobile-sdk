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

@import PowerAuthCore;

/// The `PowerAuthVaultKeyId` enumeration defines the types of vault keys
/// supported in the PowerAuth Mobile SDK.
typedef NS_ENUM(int, PowerAuthVaultKeyId) {
    /// This type of vault key can be provided after successful 2FA authentication
    /// on the server.
    PowerAuthVaultKeyId_2FA,
    /// This type of vault key can be provided after authentication with the user's password.
    PowerAuthVaultKeyId_Knowledge,
    /// This is a legacy key available only when PowerAuthSDK is running on a legacy
    /// protocol. The key can be provided after authentication with the user's password.
    PowerAuthVaultKeyId_Legacy,
};

/// The `PowerAuthVaultKey` object contains a vault key available for application
/// purposes. The key is typically provided as a result of the activation process,
/// allowing the application to encrypt sensitive data during activation. The key can
/// later be obtained from the server after authentication.
///
/// It is not recommended to persist the key on the device.
@interface PowerAuthVaultEncryptionKey : NSObject

/// Default construction is unavailable.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains the vault key data.
@property (nonatomic, readonly, strong, nonnull) PowerAuthCoreData * vaultKey;

/// Contains identifier of vault key stored in the object.
@property (nonatomic, readonly) PowerAuthVaultKeyId keyId;

/// Contains the derivation index used for key construction.
@property (nonatomic, readonly) UInt64 derivationIndex;

/// Derives another key from this key to create a chain of separated keys.
/// If this is a legacy key, the function returns an error.
///
/// - Parameters:
///   - index: Derivation index.
///   - error: Pointer where the error is set in case of failure.
/// - Returns: A derived key or `nil` in case of failure.
- (nullable PowerAuthVaultEncryptionKey*) deriveKeyWithIndex:(UInt64)index
                                             error:(NSError*_Nullable*_Nullable)error;

@end
