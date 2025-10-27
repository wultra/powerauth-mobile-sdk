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

/// The `PowerAuthCoreSignatureKeyId` enumeration defines keys available for
/// signature calculation or verification.
///
/// The following key categories are available:
///
/// - **"master"** keys are used to verify data signed on the server.
///   These keys can be used with or without an activation present in `PowerAuthSDK`.
///
/// - **"server"** keys are personalized keys uniquely associated with an activation.
///   You can use these keys to verify data signed on the server.
///
/// - **"device"** keys are unique keys stored locally on the device and associated with an activation.
///   You can use these keys to sign data and to verify previously signed data.
///
/// If the `PowerAuthAlgorithm` specified in `PowerAuthConfiguration` includes more than one algorithm,
/// you can choose a specific key type or use all keys for the operation.
/// Note that currently, only the API for JWS signatures supports hybrid signatures.
typedef NS_ENUM(int, PowerAuthSignatureKeyId) {
    /// Use all available "master" keys for signature verification.
    PowerAuthSignatureKeyId_Master = 0x00,
    /// Use only the EC-based "master" key for ECDSA signature verification.
    PowerAuthSignatureKeyId_Master_EC,
    /// Use only the ML-DSA-based "master" key for ML-DSA signature verification.
    PowerAuthSignatureKeyId_Master_ML_DSA,
    /// Use all available "server" keys for signature verification.
    PowerAuthSignatureKeyId_Server = 0x10,
    /// Use only the EC-based "server" key for ECDSA signature verification.
    PowerAuthSignatureKeyId_Server_EC,
    /// Use only the ML-DSA-based "server" key for ML-DSA signature verification.
    PowerAuthSignatureKeyId_Server_ML_DSA,
    /// Use all available "device" keys for signature computation or verification.
    PowerAuthSignatureKeyId_Device = 0x20,
    /// Use only the EC-based "device" key for ECDSA signature computation or verification.
    PowerAuthSignatureKeyId_Device_EC,
    /// Use only the ML-DSA-based "device" key for ML-DSA signature computation or verification.
    PowerAuthSignatureKeyId_Device_ML_DSA,
    /// Use the KMAC-based symmetric key for MAC verification.
    /// This key is available only when an activation is present.
    PowerAuthSignatureKeyId_MacPersonalized = 0x30,
};

/// The `PowerAuthSignatureKeyType` enumeration defines the types of keys
/// used for signing or verifying operations.
typedef NS_ENUM(int, PowerAuthSignatureKeyType) {
    /// Elliptic Curve–based key.
    PowerAuthSignatureKeyType_EC,
    /// ML-DSA–based key.
    PowerAuthSignatureKeyType_ML_DSA,
};

/// The `PowerAuthDevicePublicKeyFormat` enumeration defines the output format
/// used when exporting the device public key.
typedef NS_ENUM(int, PowerAuthDevicePublicKeyFormat) {
    /// DER key format, which corresponds to the SPKI or X.509 structure.
    PowerAuthDevicePublicKeyFormat_Der,
    /// RAW key format. The actual output depends on the key type:
    /// - For EC-based keys, the output data is ASN.1 encoded, as specified in ANSI X9.63.
    /// - For ML-DSA-based keys, the output data is obtained using the OpenSSL
    ///   `EVP_PKEY_get_raw_public_key()` function.
    PowerAuthDevicePublicKeyFormat_Raw,
};

/// The `PowerAuthDevicePublicKeyData` class represents exported
/// device public key data.
@interface PowerAuthDevicePublicKeyData : NSObject

/// Default initialization is unavailable.
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Type of the public key.
@property (nonatomic, readonly) PowerAuthSignatureKeyType keyType;

/// Information about the key algorithm (e.g., "P-256", "P-384", "ML-DSA-65", etc.).
@property (nonatomic, strong, readonly, nonnull) NSString * keyAlgorithm;

/// Public key data.
@property (nonatomic, strong, readonly, nonnull) NSData * keyData;

@end
