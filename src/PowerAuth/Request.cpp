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

#include <PowerAuth/Request.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/AuthHeaderCalculator.h>

#include "request/EndpointSpec.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex)

Request::Request(const SharedMutexPtr& mutex, const EndpointSpec& endpoint) :
    _mutex(mutex),
    _endpoint(endpoint),
    _state(WAITING)
{
}

Request::~Request()
{
    cancelImpl(true);
}

const std::string& Request::getRelativePath() const noexcept
{
    return _endpoint.relativePath;
}

const std::string& Request::getHttpMethod() const noexcept
{
    return _endpoint.method;
}

bool Request::requireSynchronizedTime() const noexcept
{
    return _endpoint.requireSynchronizedTime();
}

bool Request::requireSerialQueue() const noexcept
{
    return _endpoint.requireSerialQueue();
}

bool Request::isAllowedInUpgrade() const noexcept
{
    return _endpoint.isAllowedInUpgrade();
}

bool Request::isEncrypted() const noexcept
{
    return _endpoint.isEncrypted();
}

bool Request::isAuthenticated() const noexcept
{
    return _endpoint.isAuthenticated();
}

EncryptorScope Request::encryptorScope() const
{
    return EncryptorSpec::specForId(_endpoint.encryptorId)->scope;
}


bool Request::isCompleted() const noexcept
{
    LOCK_GUARD();
    return _state == PROCESSED;
}

bool Request::isCanceled() const noexcept
{
    LOCK_GUARD();
    return _state == CANCELED;
}

bool Request::isFailed() const noexcept
{
    LOCK_GUARD();
    return _state == FAILED;
}

bool Request::isDone() const noexcept
{
    LOCK_GUARD();
    return _state >= PROCESSED;
}

void Request::cancel()
{
    LOCK_GUARD();
    cancelImpl(false);
}

void Request::cancelImpl(bool destruct)
{
    if (_state < PROCESSED) {
        return;
    }
    _state = CANCELED;
    // Execute cancel handler in safe way.
    try {
        if (_on_cancel) {
            _on_cancel();
        }
        cleanup();
    } catch (...) {
        cleanup();
        if (destruct) {
            CC7_LOG("Internal cancel processing in request failed");
        } else {
            Exception::reThrowWrapped(EC_Canceled, "Internal cancel processing in request failed");
        }
    }
}

const cc7::ByteArray& Request::getRequestBody() const
{
    LOCK_GUARD();
    if (_state != PENDING) {
        throw Exception(EC_NotAllowed, "Request body is not available");
    }
    return _request_body;
}

const HttpHeaderList& Request::getRequestHeaders() const
{
    LOCK_GUARD();
    if (_state != PENDING) {
        throw Exception(EC_NotAllowed, "Request headers are not available");
    }
    return _request_headers;
}

const cc7::ByteArray& Request::getResponseBody() const
{
    LOCK_GUARD();
    if (_state != PROCESSED) {
        throw Exception(EC_NotAllowed, "Response body is not available");
    }
    return _response_body;
}

const ResponseObjectPtr& Request::getResponseObject() const
{
    LOCK_GUARD();
    if (_state != PROCESSED) {
        throw Exception(EC_NotAllowed, "Response body is not available");
    }
    return _response_object;
}

void Request::processFailure(ErrorCode ec, const std::string& msg, std::exception_ptr failure)
{
    _state = FAILED;
    CC7_LOG("Request failure (%d): %s", ec, msg.c_str());
    if (_on_cancel) {
        _on_cancel();
        _on_cancel = nullptr;
    }
    cleanup();
    Exception::reThrowWrapped(ec, msg, failure);
}

void Request::cleanup()
{
    _encryptor = nullptr;
    _authenticator = nullptr;
    _on_prepare = nullptr;
    _on_cancel = nullptr;
    _on_response = nullptr;
}

// MARK: - Request prepare

void Request::prepareRequest()
{
    LOCK_GUARD();
    if (_state != WAITING) {
        throw Exception(EC_NotAllowed, "Request is already prepared");
    }
    try {
        doPrepareRequest();
        _state = PENDING;
    } catch (...) {
        processFailure(EC_InvalidData, "Failed to prepare request", std::current_exception());
    }
}

void Request::doPrepareRequest()
{
    auto is_encrypted = isEncrypted();
    auto is_authenticated = isAuthenticated();

    prepareRequestBody();

    if (is_encrypted) {
        // Endpoint needs encryption
        auto cryptogram = _encryptor->encryptRequest(_request_body);
        // Encode cryptogram to body
        _request_body = cc7::json::JsonWriter::toJsonData(cryptogram.requestPayload);
        // Insert headers into request headers
        if (!is_authenticated) {
            // Insert encryption header only if this is not signed request.
            _request_headers.insert(_request_headers.end(),
                                    cryptogram.requestHeaders.begin(),
                                    cryptogram.requestHeaders.end());
        }
    }
    if (is_authenticated) {
        // Calculate authorization header
        auto header = _authenticator->calculateOnlineAuthenticationHeader(*_authentication, {
            _endpoint.method,
            _endpoint.uriId,
            _request_body
        });
        _authenticator = nullptr;
        _request_headers.push_back(header);
    }
}

void Request::prepareRequestBody()
{
    if (_on_prepare) {
        _request_json = _on_prepare(*this);
        _on_prepare = nullptr;
    }
    if (_request_json.isValid()) {
        if (_endpoint.requireWrappedRequestResponse()) {
            auto wrapper = cc7::json::JsonValue::object();
            wrapper["requestObject"] = _request_json;
            _request_body = cc7::json::JsonWriter::toJsonData(wrapper);
        } else {
            _request_body = cc7::json::JsonWriter::toJsonData(_request_json);
        }
        // Request and response is JSON, so add appropriate headers
        _request_headers.push_back({ "Content-Type", "application/json" });
        _request_headers.push_back({ "Accept",       "application/json" });
    }
}

// MARK: - Response process

void Request::setFailed() noexcept
{
    LOCK_GUARD();
    if (!isDone()) {
        CC7_LOG("Request set as failed");
        _state = FAILED;
    }
}

void Request::processResponse(const cc7::ByteRange& response_data)
{
    LOCK_GUARD();
    if (_state != PENDING) {
        throw Exception(EC_NotAllowed, "Cannot process response, because request is in wrong state");
    }
    try {
        doProcessResponse(response_data);
        _state = PROCESSED;
        if (_on_response) {
            _response_object = _on_response(*this, _response_json);
            _on_response = nullptr;
        }
        cleanup();
    } catch (...) {
        processFailure(EC_InvalidData, "Failed to process response", std::current_exception());
    }
}

void Request::doProcessResponse(const cc7::ByteRange& response_data)
{
    auto root = cc7::json::JsonReader::fromJsonData(response_data);
    if (_endpoint.requireWrappedRequestResponse()) {
        if (root["status"].asString() == "OK") {
            _response_json = root["responseObject"];
        } else {
            throw Exception(EC_InvalidData, "Non-OK response received");
        }
    } else {
        _response_json = root;
    }
    if (_endpoint.isEncrypted()) {
        _response_body = _encryptor->decryptResponse({ _response_json });
        _encryptor = nullptr;
    } else {
        _request_body = response_data;
    }
}

} // namespace powerAuth
