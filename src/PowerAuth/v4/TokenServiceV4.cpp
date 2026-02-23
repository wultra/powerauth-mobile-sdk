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

#include "TokenServiceV4.h"
#include "../HttpHeaderHelper.h"
#include "../request/RequestBuilder.h"


namespace powerAuth {
namespace v4 {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

TokenServiceV4::TokenServiceV4(const ContextPtr& context) :
    ServiceWithContext("TokenServiceV4", context),
    _session_data(context->getSessionDataPtr()),
    _time_service(context->getTimeServicePtr()),
    _nonce_generator(cc7::crypto::DefaultNonceGenerator::getInstance(16))
{
}

IServicePtr TokenServiceV4::asService()
{
    return shared_from_this();
}

void TokenServiceV4::clearActivationData()
{
    Service::clearActivationData();
    LOCK_GUARD();
    _nonce_generator->resetSavedState();
}

HttpHeader TokenServiceV4::calculateTokenHeader(const TokenAuthenticationData &token_data)
{
    LOCK_GUARD();
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
    
    if (!_time_service->isTimeSynchronized()) {
        CC7_LOG("WARNING: Time is not synchronized. The token header may be rejected on the server.");
    }
    
    auto nonce = _nonce_generator->getNonce();
    auto current_time_ms = std::to_string(_time_service->currentTimeMillis());
    
    TokenHeaderData header_data {
        Version_V4,
        std::string(token_data.tokenIdentifier),
        nonce.base64(),
        current_time_ms
    };
    
    auto data = cc7::ConcatByteRanges({
        nonce,
        cc7::MakeRange(common::AMP),
        cc7::MakeRange(current_time_ms),
        cc7::MakeRange(common::AMP),
        cc7::MakeRange(v4::PA_VERSION_STRING)
    });
    header_data.tokenDigest = algorithms().v4.kmac256()
        .token(token_data.tokenSecret, data, {
            { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take(v4::TOKEN_DIGEST_SIZE) },
            { cc7::crypto::MAC_PARAM_CUSTOM_STRING, cc7::crypto::Parameter::ref("PA4DIGEST") }
        })
        .base64();
    return HttpHeaderHelper::buildTokenHeader(header_data);
}

RequestPtr TokenServiceV4::createAccessToken(const CredentialsPtr &credentials)
{
    LOCK_GUARD();
    auto context = lockContext();
    auto factors = credentials->factors();
    auto self = shared_from_this();
    return RequestBuilder(*context, v4::Endpoint_TokenCreate)
        .withAuthentication(credentials)
        .withResponseCallback([self, factors](const Request& request, const cc7::json::JsonValue& response) -> ResponseObjectPtr {
            return self->processCreateAccessTokenResponse(factors, response);
        })
        .build();
}

ResponseObjectPtr TokenServiceV4::processCreateAccessTokenResponse(AuthFactors factors, const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    // Validate state one more time
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Activation is no longer valid");
    }
    
    // Build response object
    auto token_id     = response["tokenId"].asString();
    auto token_secret = response["tokenSecret"].asBase64();
    if (token_secret.size() < v4::TOKEN_SECRET_SIZE || token_id.empty()) {
        throw Exception(EC_InvalidResponse, "Invalid token data received");
    }
    return std::make_shared<GetAccessTokenResponse>(factors, token_id, token_secret);
}

RequestPtr TokenServiceV4::removeAccessToken(const std::string_view &token_identifier)
{
    LOCK_GUARD();
    if (!_session_data->hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
    return RequestBuilder(*lockContext(), v4::Endpoint_TokenRemove)
        .withAuthentication(Credentials::possession())
        .withJson(cc7::json::JsonValue::object({
            { "tokenId", cc7::json::JsonValue(token_identifier) }
        }))
        .build();
}

} // namespace v4
} // namespace powerAuth
