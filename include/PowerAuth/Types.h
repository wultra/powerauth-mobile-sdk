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

#pragma once

#include <cc7/ByteArray.h>
#include <cc7/BaseObject.h>
#include <cc7/json/Json.h>
#include <PowerAuth/Exception.h>

namespace powerAuth {

// MARK: - Support objects -

/// Type definition for mutex shared between multiple objects. The mutex
/// implementation must support recursive locking.
typedef std::recursive_mutex SharedMutex;

CC7_SHARED_PTR(SharedMutex)


/// The ProtocolVersion enum defines PowerAuth protocol version.
enum ProtocolVersion
{
    /// Constant defining that version is not available. The enumeration
    /// has meaning in several APIs, where unknown or "no version"
    /// state can be returned as a regular result.
    Version_NA = 0,
    /// Constant defining Protocol Version 2.
    Version_V2 = 2,
    /// Constant defining Protocol Version 3.
    Version_V3 = 3,
    /// Constant defining Protocol Version 4.
    Version_V4 = 4,
    
    // Special constant for "latest" version
    Version_Latest = Version_V3
};

/**
 Returns textual representation for given protocol version. For example, for `Version_V3` returns "3.3".
 You can use `Version_NA` to get the latest supported version.
 */
extern const std::string& ProtocolVersion_GetHttpHeaderVersion(ProtocolVersion protocol_version);


/// Type for millisecond precise timestamp.
typedef int64_t Timestamp;

/// Type for seconds precise timestamp represented as floating point precision value.
typedef double TimeInterval;

/// The `HttpHeader` structure contains information for HTTP header construction.
struct HttpHeader
{
    /// Header's name.
    std::string headerName;
    /// Header's value.
    std::string headerValue;
};

/// List of headers.
typedef std::vector<HttpHeader> HttpHeaderList;

/// Data for constructing authentication header.
struct AuthenticationHeaderData
{
    /// Protocol version.
    ProtocolVersion version;
    /// PowerAuth application key.
    std::string applicationKey;
    /// Activation identifier.
    std::string activationIdentifier;
    /// Factors used in authentication code.
    std::string authenticationFactors;
    /// Nonce.
    std::string nonce;
    /// Authentication code.
    std::string authenticationCode;
};

/// Data for constructing token header.
struct TokenHeaderData
{
    /// Protocol version.
    ProtocolVersion version;
    /// Token identifier
    std::string tokenIdentifier;
    /// Nonce
    std::string nonce;
    /// Timestamp
    std::string timestamp;
    /// Token digest
    std::string tokenDigest;
};

/// Defines types of keys used for sign or verify operations.
enum class SignatureKeyType
{
    /// Elliptic Curve based key.
    EC,
    /// ML-DSA based key.
    ML_DSA,
};

/// Defines keys available for signature calculation or verification.
/// Note that some keys are available only for signing or only for verification.
/// The operation may end with exception if you use a wrong key identifier.
enum class SignatureKeyId
{
    /// Use all available "master" keys for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_P256_PUBLIC` for protocol V3
    /// - `KEY_MASTER_ECDSA_P384_PUBLIC`, `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    KEY_MASTER = 0x00,

    /// Use only the "EC"-based "master" key for signature verification.
    /// Depending on availability, the following will be used:
    /// - `KEY_MASTER_P256_PUBLIC` for protocol V3
    /// - `KEY_MASTER_ECDSA_P384_PUBLIC` for protocol V4
    KEY_MASTER_EC,

    /// Use only the "ML-DSA"-based "master" key for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    KEY_MASTER_ML_DSA,

    /// Use all available "server" keys for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_SERVER_P256_PUBLIC` for protocol V3
    /// - `KEY_SERVER_ECDSA_P384_PUBLIC`, `KEY_SERVER_MLDSA65_PUBLIC` for protocol V4
    KEY_SERVER = 0x10,
    /// Use only the "EC"-based "server" key for signature verification.
    /// Depending on availability, the following will be used:
    /// - `KEY_SERVER_P256_PUBLIC` for protocol V3
    /// - `KEY_SERVER_ECDSA_P384_PUBLIC` for protocol V4
    KEY_SERVER_EC,
    /// Use only the "ML-DSA"-based "server" key for signature verification.
    /// Depending on key availability, the following will be used:
    /// - `KEY_MASTER_MLDSA65_PUBLIC` for protocol V4
    KEY_SERVER_ML_DSA,
    
    /// Use all available "device" keys for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_P256_PRIVATE` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PRIVATE`, `KEY_DEVICE_MLDSA65_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_P256_PUBLIC` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PUBLIC`, `KEY_DEVICE_MLDSA65_PUBLIC` for protocol V4
    KEY_DEVICE = 0x20,
    /// Use only the "EC"-based "server" key for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_P256_PRIVATE` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_P256_PUBLIC` for protocol V3
    /// - `KEY_DEVICE_ECDSA_P384_PUBLIC` for protocol V4
    KEY_DEVICE_EC,
    /// Use only the "ML-DSA"-based "server" key for signature computation or verification.
    /// Depending on key availability, the following will be used for signing:
    /// - `KEY_DEVICE_MLDSA65_PRIVATE` for protocol V4
    /// For the signature verification, the following will be used:
    /// - `KEY_DEVICE_MLDSA65_PUBLIC` for protocol V4
    KEY_DEVICE_ML_DSA,
    
    /// Use "KMAC"-based symmetric key for signature verification. The following key will be used:
    /// - `KEY_MAC_PERSONALIZED_DATA` for protocol V4
    /// Note that the key is not supported in JWS routines.
    KEY_MAC_PERSONALIZED = 0x30
};


/// Structure containing exported device public key.
struct DevicePublicKeyData
{
    /// Type of public key.
    const SignatureKeyType keyType;
    /// Contains information about key algorithm ("P-256", "P-384", "ML-DSA-65", etc.)
    const std::string keyAlgorithm;
    /// Public key data.
    const cc7::ByteArray keyData;
};

// Encryption

/// The `EncryptorScope` enumeration defines scope of the encryptor.
enum class EncryptorScope
{
    /// Application scoped encryptor. This type of encryptor can be used before
    /// the activation is created. It's cryptographically bound to PowerAuth application's
    /// secret.
    APPLICATION = 1,
    /// Activation scoped encryptor. This type of encryptor is cryptographically bound to
    /// user's activation. So, it's available only while the Session has a valid activation data.
    ACTIVATION  = 2
};

/// The `EncryptorId` enumeration defines encryptors used in the PowerAuth protocol.
enum class EncryptorId
{
    /// No encryptor is used. The constant is used in situations when you have to specify
    /// that no encryptor is involved. For example, in endpoint specification.
    /// This value should not be used in API functions that require actual encryptors.
    NONE,
    /// General purpose encryptor for application scope. This encryptor is exposed to public API
    /// and the mobile application can use it for its own purposes.
    APPLICATION_SCOPE_GENERIC,
    /// General purpose encryptor for activation scope. This encryptor is exposed to public API
    /// and the mobile application can use it for its own purposes.
    ACTIVATION_SCOPE_GENERIC,
    /// Application scoped encryptor for encrypting "Layer 2" activation data.
    ACTIVATION_LAYER_2,
    /// Activation scoped encryptor for encrypting the vault key.
    VAULT_UNLOCK,
    /// Activation scoped encryptor for creating a PowerAuth token.
    CREATE_TOKEN,
    /// Activation scoped encryptor for changing a password.
    PASSWORD_CHANGE,
    /// Activation scoped encryptor for adding biometric factor.
    BIOMETRY_ADD,
    /// Application scoped encryptor for starting the upgrade to protocol V4+.
    UPGRADE_START
};

// Vault key

/// The `VaultKeyId` enumeration defines vault key identifiers.
enum class SecureVaultKeyId
{
    /// This type of vault key can be provided after successful 2FA authentication
    /// on the server.
    ANY_2FA = 1,
    /// This type of vault key can be provided after authentication with the user's password.
    KNOWLEDGE = 2,
    /// This is a legacy key available only when PowerAuthSDK is running on a legacy
    /// protocol. The key can be provided after authentication with the user's password.
    LEGACY = 3
};

// Authentication

/// Authentication factor for authentication code calculation.
enum class AuthFactors
{
    /// The authentication code will contain only the component with the possession factor.
    POSSESSION,
    /// The authentication code will contain components with the possession and the knowledge factors.
    POSSESSION_KNOWLEDGE,
    /// The authentication code will contain components with the possession and the biometry factors.
    POSSESSION_BIOMETRY
};

// Forward declarations for internal objects

class Context;
class SessionData;

} // namespace powerAuth
