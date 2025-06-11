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
#include <PowerAuth/Exception.h>

namespace powerAuth {

// MARK: - Support objects -

typedef std::recursive_mutex SharedMutex;
typedef std::shared_ptr<std::recursive_mutex> SharedMutexPtr;


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



// MARK: - New "Engine" types

/// Type for millisecond precise timestamp.
typedef int64_t Timestamp;

/// Type for seconds precise timestamp represented as floating point precision value.
typedef double TimeInterval;

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

struct HttpHeader
{
    std::string headerName;
    std::string headerValue;
};

// Authentication

enum class AuthFactors
{
    POSSESSION,
    POSSESSION_KNOWLEDGE,
    POSSESSION_BIOMETRY
};

} // namespace powerAuth
