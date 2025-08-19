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
#include <PowerAuth/Credentials.h>
#include <PowerAuth/Request.h>
#include <map>

namespace powerAuth {

/// Data for calculating HTTP authorization header.
struct OnlineAuthenticationData
{
    /// Request's URI identifier.
    std::string_view uriIdentifier;
    /// Request's HTTP method
    std::string_view httpMethod;
    /// Indicate that authentication in this endpoint is allowed during pending activation registration.
    bool allowedInPendingRegistration = false;
    /// Indicate that authentication in this endpoint is allowed during protocol upgrade.
    bool allowedInUpgrade = false;
};

/// Data for calculating offline authorization code.
struct OfflineAuthenticationData
{
    /// Request's URI identifier.
    std::string_view uriIdentifier;
    /// Offline nonce.
    std::string_view offlineNonce;
    /// Length of output authorization code.
    size_t authorizationCodeLength = 8;
};

/// Reason send to request verifying user's credentials on the server.
enum class VerifyCredentialsReason
{
    /// Request is issued for password validation purpose.
    VALIDATE_PASSWORD,
    /// Request is issued for confirm password.
    CONFIRM_NEW_PASSWORD,
    /// Request is issued for authorization code's counter synchronization.
    COUNTER_SYNCHRONIZATION
};

/// The `IAuthenticationService` calculates authentication headers for online HTTP requests and authentication
/// codes for offline authentication.
class IAuthenticationService
{
public:
    virtual ~IAuthenticationService() = default;
    
    /// Return instance of this object implementing `IService` interface.
    virtual IServicePtr asService() = 0;
    
    /// Calculate authentication header for online HTTP request.
    /// - Parameters:
    ///   - credentials: User's credentials.
    ///   - auth_data: Data for constructing authentication header.
    ///   - body: HTTP request body.
    /// - Returns: HttpHeader structure.
    virtual HttpHeader calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                                           const OnlineAuthenticationData& auth_data,
                                                           const cc7::ByteRange& body) = 0;
    
    /// Calculate human readable header for offline authorization.
    /// - Parameters:
    ///   - credentials: User's credentials.
    ///   - auth_data: Data for constructing authentication code.
    ///   - body: Data to authenticate.
    /// - Returns: Human readable offline code.
    virtual std::string calculateOfflineAuthenticationCode(const Credentials& credentials,
                                                           const OfflineAuthenticationData& auth_data,
                                                           const cc7::ByteRange& data) = 0;
    
    /// Create HTTP request that verifies user's credentials.
    /// - Parameters:
    ///   - credentials: User's credentials.
    ///   - object: Additional request object.
    /// - Returns: HTTP request object.
    virtual RequestPtr verifyCredentials(const CredentialsPtr& credentials,
                                         const cc7::json::JsonValue& object) = 0;
    
    // Non virtual methods

    /// Normalize parameters for non-POST HTTP request. The result of this function can be used in
    /// `calculateOnlineAuthenticationHeader()` or `calculateOfflineAuthenticationCode()` method.
    ///
    /// - Parameter map: Map with parameters.
    /// - Returns: Normalized data.
    cc7::ByteArray normalizeGetRequestParameters(std::map<std::string, std::string>& map) const;
    
    /// Verify user's credentials on the server.
    /// - Parameters:
    ///   - credentials: Credentials to verify.
    ///   - reason: Reason of verification.
    /// - Returns: HTTP request object.
    RequestPtr verifyCredentialsWithReason(const CredentialsPtr& credentials, VerifyCredentialsReason reason);
    
    /// Verify user's password on the server.
    /// - Parameters:
    ///   - credentials: Credentials to verify.
    ///   - reason: Reason of verification.
    /// - Returns: HTTP request object.
    RequestPtr verifyPassword(const Password& password);
};

CC7_SHARED_PTR(IAuthenticationService)

} // namespace powerAuth
