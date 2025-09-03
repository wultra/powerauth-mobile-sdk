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

#include <PowerAuth/TokenService.h>
#include <cc7/crypto/NonceGenerator.h>
#include "../Context.h"

namespace powerAuth {
namespace v3 {

class TokenServiceV3 :
    public ITokenService,
    public Service,
    public std::enable_shared_from_this<TokenServiceV3>
{
public:
    TokenServiceV3(const ContextPtr& context);
    
    // ITokenService
    
    IServicePtr asService() override;
    HttpHeader calculateTokenHeader(const TokenAuthenticationData &token_data) override;
    RequestPtr createAccessToken(const CredentialsPtr &credentials) override;
    RequestPtr removeAccessToken(const std::string_view &token_identifier) override;
    
private:
    ResponseObjectPtr processCreateAccessTokenResponse(AuthFactors factors, const cc7::json::JsonValue& response);
    
    ContextPtr lockContext();

    SessionDataPtr _session_data;
    TimeServicePtr _time_service;
    ContextWeakPtr _weak_context;
    cc7::crypto::NonceGeneratorPtr _nonce_generator;
};

} // namespace v3
} // namespace powerAuth
