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

class Credentials;

/// The `RequestBuilder` class creates `Request` object instances.
///
/// - Warning: The builder object should be instantiated only on stack.
class RequestBuilder
{
public:
    
    /// Construct builder with context and endpoint specification.
    ///
    /// - Parameters:
    ///   - context: Context object. The builder doesn't keep smart reference
    ///              to the context, so the builder must not live longer that
    ///              the context object itself.
    ///   - endpoint: Endpoint specification.
    RequestBuilder(Context& context, const EndpointSpec& endpoint);
    
    /// Add JSON request body.
    /// - Parameter json_payload: JSON request body.
    /// - Throws: `Exception` in case the body is already set.
    RequestBuilder& withJson(const cc7::json::JsonValue& json_payload);
    
    /// Add request body bytes.
    /// - Parameter body: Request body bytes.
    /// - Throws: `Exception` in case the body is already set.
    RequestBuilder& withBody(const cc7::ByteRange& body);
    
    /// Add request headers to the request.
    /// - Parameter headers: Headers to add to the request.
    RequestBuilder& withHeaders(const HttpHeaderList& headers);
    
    /// Add credentials in case the request is authenticated.
    /// - Parameter authentication: Credentials for authentication.
    RequestBuilder& withAuthentication(const CredentialsPtr& authentication);
    
    /// Add request body preparation callback.
    /// - Parameter callback: Preparation callback.
    /// - Throws: `Exception` in case the body is already set.
    RequestBuilder& withPrepareCallback(PrepareRequestCallback callback);
    
    /// Add response processing callback.
    /// - Parameter callback: Response processing callback.
    RequestBuilder& withResponseCallback(ResponseCallback callback);
    
    /// Add cancel callback.
    /// - Parameter callback: Response processing callback.
    RequestBuilder& withCancelCallback(CancelCallback callback);
    
    /// Build the request.
    RequestPtr build();
    
private:
    Context& _context;
    RequestPtr _request;
    bool _has_body;
};

} // namespace powerAuth
