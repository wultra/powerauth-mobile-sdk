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

#include "RequestBuilder.h"
#include "../Context.h"

namespace powerAuth {

RequestBuilder::RequestBuilder(Context& context, const EndpointSpec& endpoint) :
    _context(context),
    _request(std::unique_ptr<Request>(new Request(context.getSharedMutexPtr(), endpoint))),
    _has_body(false)
{
}

RequestBuilder& RequestBuilder::withJson(const cc7::json::JsonValue& json_payload)
{
    if (_has_body) {
        throw Exception(EC_WrongParameter, "Body is already set");
    }
    _request->_request_json = json_payload;
    _has_body = true;
    return *this;
}

RequestBuilder& RequestBuilder::withBody(const cc7::ByteRange& body)
{
    if (_has_body) {
        throw Exception(EC_WrongParameter, "Body is already set");
    }
    _request->_request_body = body;
    _has_body = true;
    return *this;
}

RequestBuilder& RequestBuilder::withHeaders(const HttpHeaderList &headers)
{
    _request->_request_headers.insert(_request->_request_headers.end(), headers.begin(), headers.end());
    return *this;
}

RequestBuilder& RequestBuilder::withAuthentication(const CredentialsPtr &authentication)
{
    if (!_request->_endpoint.isAuthenticated()) {
        throw Exception(EC_WrongParameter, "Endpoint is not authenticated");
    }
    _request->_authentication = authentication;
    return *this;
}

RequestBuilder& RequestBuilder::withAuthenticator(const IAuthenticationServicePtr& authenticator)
{
    if (!_request->_endpoint.isAuthenticated()) {
        throw Exception(EC_WrongParameter, "Endpoint is not authenticated");
    }
    _request->_authenticator = authenticator;
    return *this;
}

RequestBuilder& RequestBuilder::withPrepareCallback(PrepareRequestCallback callback)
{
    if (_has_body) {
        throw Exception(EC_WrongParameter, "Body is already set");
    }
    _request->_on_prepare = callback;
    _has_body = true;
    return *this;
}

RequestBuilder& RequestBuilder::withResponseCallback(ResponseCallback callback)
{
    _request->_on_response = callback;
    return *this;
}

RequestBuilder& RequestBuilder::withCancelCallback(CancelCallback callback)
{
    _request->_on_cancel = callback;
    return *this;
}

RequestBuilder& RequestBuilder::withCustomParameter(const cc7::crypto::Parameter &parameter)
{
    _request->_custom_parameter = parameter;
    return *this;
}

RequestPtr RequestBuilder::build()
{
    if (!_has_body) {
        _request->_request_json = cc7::json::JsonValue::object();
    }
    if (_request->isAuthenticated()) {
        if (_request->_authentication == nullptr) {
            throw Exception(EC_InternalError, "Authentication object is missing");
        }
        
        if (!_request->_authenticator) {
            _request->_authenticator = _context.getAuthenticationServicePtr();
        }
    }
    if (_request->_endpoint.isEncrypted()) {
        _request->_encryptor_factory = _context.getEncryptorFactoryPtr();
    }
    return std::move(_request);
}

} // namespace powerAuth
