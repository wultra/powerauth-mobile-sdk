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

#include "TokenServiceV3.h"
#include "../HttpHeaderHelper.h"
#include "../request/RequestBuilder.h"

namespace powerAuth {
namespace v3 {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

TokenServiceV3::TokenServiceV3(const ContextPtr& context) :
    ServiceWithContext("TokenServiceV3", context),
    _session_data(context->getSessionDataPtr()),
    _time_service(context->getTimeServicePtr()),
    _nonce_generator(cc7::crypto::DefaultNonceGenerator::getInstance(16))
{
}

IServicePtr TokenServiceV3::asService()
{
    return shared_from_this();
}

void TokenServiceV3::clearActivationData()
{
    Service::clearActivationData();
    LOCK_GUARD();
    _nonce_generator->resetSavedState();
}

HttpHeader TokenServiceV3::calculateTokenHeader(const TokenAuthenticationData &token_data)
{
    LOCK_GUARD();
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Access token header cannot be calculated due to missing activation");
    }
    
    if (!_time_service->isTimeSynchronized()) {
        CC7_LOG("WARNING: Time is not synchronized. The token header may be rejected on the server.");
    }
    
    auto nonce = _nonce_generator->getNonce();
    auto current_time_ms = std::to_string(_time_service->currentTimeMillis());
    auto data = cc7::ConcatByteRanges({
        nonce,
        cc7::MakeRange(common::AMP),
        cc7::MakeRange(current_time_ms),
        cc7::MakeRange(common::AMP),
        cc7::MakeRange(v3::PA_VERSION_STRING)
    });
    
    return HttpHeaderHelper::buildTokenHeader({
        Version_V3,
        std::string(token_data.tokenIdentifier),
        nonce.base64(),
        current_time_ms,
        algorithms().v3.hmacWithSha256().token(token_data.tokenSecret, data).base64()
    });
}

RequestPtr TokenServiceV3::createAccessToken(const CredentialsPtr &credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto factors = credentials->factors();
    auto self = shared_from_this();
    
    return RequestBuilder(*context, v3::Endpoint_TokenCreate)
        .withAuthentication(credentials)
        .withResponseCallback([self, factors](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
            return self->processCreateAccessTokenResponse(factors, response);
        })
        .build();
}

ResponseObjectPtr TokenServiceV3::processCreateAccessTokenResponse(AuthFactors factors, const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Create access token response cannot be processed due to missing activation");
    }
    
    auto token_id = response["tokenId"].asString();
    auto token_secret = response["tokenSecret"].asBase64();
    if (token_secret.size() < v3::TOKEN_SECRET_SIZE || token_id.empty()) {
        throw Exception(EC_InvalidResponse, "Invalid token data received");
    }
    
    return std::make_shared<GetAccessTokenResponse>(factors, token_id, token_secret);
}

RequestPtr TokenServiceV3::removeAccessToken(const std::string_view &token_identifier)
{
    LOCK_GUARD();
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Access token cannot be removed due to missing activation");
    }
    
    return RequestBuilder(*lockContext(), v3::Endpoint_TokenRemove)
        .withAuthentication(Credentials::possession())
        .withJson(cc7::json::JsonValue::object({
            { "tokenId", cc7::json::JsonValue(token_identifier) }
        }))
        .build();
}

} // namespace v3
} // namespace powerAuth
