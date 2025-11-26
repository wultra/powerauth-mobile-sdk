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
#include <PowerAuth/Credentials.h>

namespace powerAuth {

/// The `TokenAuthenticationData` contains information required for token header
/// construction.
struct TokenAuthenticationData
{
    /// Token identifier.
    std::string_view tokenIdentifier;
    /// Token secret bytes
    cc7::ByteRange tokenSecret;
};

/// The `GetAccessTokenResponse` object contains response data from endpoint
/// creating access token.
class GetAccessTokenResponse : public ResponseObject
{
public:
    /// Get factors used for authentication on the server.
    AuthFactors getFactors() const noexcept;
    /// Get token's identifier.
    const std::string& getIdentifier() const noexcept;
    /// Get token's secret.
    const cc7::ByteArray& getSecret() const noexcept;
    
    /// Construct object with all required parameters.
    /// - Parameters:
    ///   - factors: Factors used for token creation.
    ///   - identifier: Token's identifier.
    ///   - secret: Token's secret.
    GetAccessTokenResponse(AuthFactors factors,
                           const std::string_view& identifier,
                           const cc7::ByteRange& secret);
    
private:
    const AuthFactors _factors;
    const std::string _identifier;
    const cc7::ByteArray _secret;
};

CC7_SHARED_PTR(GetAccessTokenResponse)

/// The `ITokenService` calculates token headers for HTTP requests. The service also allows
/// you to acquire token from the server.
class ITokenService
{
public:
    virtual ~ITokenService() = default;
    
    /// Return instance of this object implementing `IService` interface.
    virtual IServicePtr asService() = 0;
    
    /// Calculate token authentication header with given token data.
    /// - Parameters:
    ///   - token_data: Data for constructing token header.
    /// - Returns: HTTP header structure.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual HttpHeader calculateTokenHeader(const TokenAuthenticationData& token_data) = 0;
    
    /// Get access token from the server. In case of success, the request contains `GetAccessTokenResponse`
    /// in response object property.
    /// - Parameters:
    ///   - credentials: Credentials for authentication on the server.
    /// - Returns: Request object.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr createAccessToken(const CredentialsPtr& credentials) = 0;
    
    /// Remove access token from the server.
    /// - Parameters:
    ///   - token_identifier: Token's identifier.
    /// - Returns: Request object.
    /// - Throws:
    ///   - `Exception` in case of failure.
    virtual RequestPtr removeAccessToken(const std::string_view& token_identifier) = 0;
};

CC7_SHARED_PTR(ITokenService)

} // namespace powerAuth
