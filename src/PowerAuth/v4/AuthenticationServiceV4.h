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

#include <PowerAuth/AuthenticationService.h>
#include <PowerAuth/Configuration.h>
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class AuthenticationServiceV4 :
    public Service,
    public IAuthenticationService,
    public std::enable_shared_from_this<AuthenticationServiceV4>
{
public:
    AuthenticationServiceV4(const ContextPtr& context);

    IServicePtr asService() override;
    
    HttpHeader calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                                   const OnlineAuthenticationData& auth_data,
                                                   const cc7::ByteRange& body) override;
    
    std::string calculateOfflineAuthenticationCode(const Credentials& credentials,
                                                   const OfflineAuthenticationData& auth_data,
                                                   const cc7::ByteRange& data) override;
    
    RequestPtr verifyCredentials(const CredentialsPtr& credentials, const cc7::json::JsonValue& body) override;

private:
    
    const ContextWeakPtr _weak_context;
    const ConfigurationPtr _configuration;
    const SessionDataPtr _session_data;
    const IKeyProviderPtr _key_provider;
    
    /// Prepare factor keys for authentication code calculation.
    /// - Parameters:
    ///   - secrets: Secret keys.
    ///   - factors: Factor keys to use.
    /// - Returns: Vector with secret keys.
    std::vector<cc7::ByteRange> prepareFactorKeys(ISecretKeys& secrets, AuthFactors factors);
    
    void moveCounterForward(cc7::ByteArray& hash_counter, cc7::byte& byte_counter);
};

} // namespace v4
} // namespace powerAuth

