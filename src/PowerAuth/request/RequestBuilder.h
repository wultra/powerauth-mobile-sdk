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

#include <PowerAuth/Request.h>
#include <PowerAuth/Credentials.h>
#include "EndpointSpec.h"

namespace powerAuth {

class Context;
class Credentials;

class RequestBuilder
{
public:
    RequestBuilder(Context& context, const EndpointSpec& endpoint);
    
    RequestBuilder& withJson(const cc7::json::JsonValue& json_payload);
    RequestBuilder& withBody(const cc7::ByteRange& body);
    RequestBuilder& withHeaders(const std::vector<HttpHeader>& headers);
    RequestBuilder& withAuthentication(const CredentialsPtr& authentication);
    
    RequestBuilder& withResponseCallback(ResponseCallback callback);
    RequestBuilder& withCancelCallback(CancelCallback callback);
    
    RequestPtr build();
    
private:
    Context& _context;
    RequestPtr _request;
    bool _has_body;
};

} // namespace powerAuth
