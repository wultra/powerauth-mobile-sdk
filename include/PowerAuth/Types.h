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
    /// Application scoped encryptor for starting the upgrade to protocol V4+.
    UPGRADE_START
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



// TODO: missing documentation, unfinished API

struct AuthenticationHeaderData
{
    std::string version;
    std::string activationId;
    std::string authorizationCode;
    std::string authorizationFactors;
    std::string nonce;
};

struct EncryptionHeaderData
{
    std::string version;
    std::string activationId;
};

struct TokenHeaderData
{
    std::string version;
    std::string tokenId;
    std::string tokenDigest;
    std::string nonce;
    Timestamp timestamp = 0;
};


} // namespace powerAuth
