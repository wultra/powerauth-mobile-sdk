/*
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreData.h>
#import <PowerAuthCore/PowerAuthCoreOtpUtil.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>


/// The `PowerAuthCoreProtocolVersion` enum defines PowerAuth protocol versions.
typedef NS_ENUM(int, PowerAuthCoreProtocolVersion) {
    /// Protocol version is not specified, or cannot be determined.
    PowerAuthCoreProtocolVersion_NA = 0,
    /// Protocol version 2. This version is discontinued and is no longer supported in SDK.
    PowerAuthCoreProtocolVersion_V2 = 2,
    /// Protocol version 3. This is the legacy version of the protocol, supported in SDK.
    PowerAuthCoreProtocolVersion_V3 = 3,
    /// Protocol version 4. This is the latest version of protocol supported in SDK.
    PowerAuthCoreProtocolVersion_V4 = 4,
};

/// The `PowerAuthCoreHttpHeader` object represents HTTP header with its name and value.
@interface PowerAuthCoreHttpHeader : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Contains HTTP header name
@property (nonatomic, strong, readonly, nonnull) NSString * headerName;
/// Contains HTTP header value
@property (nonatomic, strong, readonly, nonnull) NSString * headerValue;

@end

/// The `PowerAuthDevicePublicKeyFormat` enumeration defines the output format
/// of exported the device public key.
typedef NS_ENUM(int, PowerAuthCoreDevicePublicKeyFormat) {
    /// SPKI (X.509) encoded DER format.
    PowerAuthCoreDevicePublicKeyFormat_SPKI,
    /// RAW key format. The output format depends on the key type:
    /// - For "EC" based keys, the output data is ASN.1 encoded, as specified in ANSI X9.63.
    /// - For "ML-DSA" based keys, the output data is the result of OpenSSL `EVP_PKEY_get_raw_public_key()`
    ///   function.
    PowerAuthCoreDevicePublicKeyFormat_RAW,
};

/// The `PowerAuthCoreSignatureKeyType` enumeration defines types of keys
/// used for sign or verify operations.
typedef NS_ENUM(int, PowerAuthCoreSignatureKeyType) {
    /// Elliptic Curve based key.
    PowerAuthCoreSignatureKeyType_EC,
    /// ML-DSA based key.
    PowerAuthCoreSignatureKeyType_ML_DSA,
};

/// The `PowerAuthCoreDevicePublicKeyData` object contains containing exported
/// device public key.
@interface PowerAuthCoreDevicePublicKeyData : NSObject

/// Default construction is unavailable
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Type of public key.
@property (nonatomic, readonly) PowerAuthCoreSignatureKeyType keyType;
/// Contains information about key algorithm ("P-256", "P-384", "ML-DSA-65", etc.)
@property (nonatomic, strong, readonly, nonnull) NSString * keyAlgorithm;
/// Public key data.
@property (nonatomic, strong, readonly, nonnull) NSData * keyData;

@end

/// The `PowerAuthCoreSignatureKeyId` enumeration defines keys available for
/// signature calculation or verification.
///
/// Note that some keys are available only for signing or only for verification.
/// The operation may end with exception if you use a wrong key identifier.
typedef NS_ENUM(int, PowerAuthCoreSignatureKeyId) {
    /// Use all available "master" keys for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_P256_PUBLIC` for protocol V3
    /// - `KEY_MASTER_ECDSA_P384_PUBLIC`, `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_MASTER = 0x00,

    /// Use only the "EC"-based "master" key for signature verification.
    /// Depending on availability, the following will be used:
    /// - `KEY_MASTER_P256_PUBLIC` for protocol V3
    /// - `KEY_MASTER_ECDSA_P384_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_MASTER_EC,

    /// Use only the "ML-DSA"-based "master" key for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_MASTER_ML_DSA,

    /// Use all available "server" keys for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_SERVER_P256_PUBLIC` for protocol V3
    /// - `KEY_SERVER_ECDSA_P384_PUBLIC`, `KEY_SERVER_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_SERVER = 0x10,
    /// Use only the "EC"-based "server" key for signature verification.
    /// Depending on availability, the following will be used:
    /// - `KEY_SERVER_P256_PUBLIC` for protocol V3
    /// - `KEY_SERVER_ECDSA_P384_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_SERVER_EC,
    /// Use only the "ML-DSA"-based "server" key for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_SERVER_ML_DSA,
    
    /// Use all available "device" keys for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_P256_PRIVATE` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PRIVATE`, `KEY_DEVICE_MLDSA65_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_P256_PUBLIC` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PUBLIC`, `KEY_DEVICE_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_DEVICE = 0x20,
    /// Use only the "EC"-based "server" key for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_P256_PRIVATE` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_P256_PUBLIC` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_DEVICE_EC,
    /// Use only the "ML-DSA"-based "server" key for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_MLDSA65_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_MLDSA65_PUBLIC` for protocol V4
    PowerAuthCoreSignatureKeyId_DEVICE_ML_DSA,
    
    /// Use "KMAC"-based symmetric key for signature verification. The following key will be used:
    /// - `KEY_MAC_PERSONALIZED_DATA` for protocol V4
    /// Note that the key is not supported in JWS routines.
    PowerAuthCoreSignatureKeyId_MAC_PERSONALIZED = 0x30,
};

/// The `PowerAuthCoreVaultEncryptionKeyId` enumeration defines the types of vault keys
/// supported in the PowerAuth Mobile SDK.
typedef NS_ENUM(int, PowerAuthCoreSecureVaultKeyId) {
    /// This type of vault key can be provided after successful 2FA authentication
    /// on the server.
    PowerAuthCoreSecureVaultKeyId_2FA = 1,
    /// This type of vault key can be provided after authentication with the user's password.
    PowerAuthCoreSecureVaultKeyId_Knowledge = 2,
    /// This is a legacy key available only when PowerAuthSDK is running on a legacy
    /// protocol. The key can be provided after authentication with the user's password.
    PowerAuthCoreSecureVaultKeyId_Legacy = 3,
};

/// The `PowerAuthCoreEncryptorScope` enumeration defines how `PowerAuthCoreEncryptor` encryptor
/// is configured.
typedef NS_ENUM(int, PowerAuthCoreEncryptorScope) {
    /// No encryptor is specified in core request.
    PowerAuthCoreEncryptorScope_None = 0,
    /// An application scope means that encryptor can be constructed also when
    /// the session has no valid activation.
    PowerAuthCoreEncryptorScope_Application = 1,
    /// An activation scope means that the encryptor can be constructed only when
    /// the session has a valid activation.
    PowerAuthCoreEncryptorScope_Activation = 2,
};
