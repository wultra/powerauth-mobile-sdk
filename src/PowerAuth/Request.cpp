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

#include <PowerAuth/Task.h>
#include <PowerAuth/Encryptor.h>
#include <PowerAuth/AuthenticationService.h>

#include "request/EndpointSpec.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex)

Request::Request(const SharedMutexPtr& mutex, const EndpointSpec& endpoint) :
    _mutex(mutex),
    _endpoint(endpoint),
    _task_tag(0),
    _state(WAITING)
{
}

Request::~Request()
{
    cancel();
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

void Request::cancel() noexcept
{
    LOCK_GUARD();
    if (_state < PROCESSED) {
        return;
    }
    _state = CANCELED;
    notifyResult();
    cleanup();
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

const cc7::json::JsonValue& Request::getResponseJson() const
{
    LOCK_GUARD();
    if (_state != PROCESSED) {
        throw Exception(EC_NotAllowed, "Response body is not available");
    }
    return _response_json;
}

const cc7::crypto::Parameter& Request::getCustomParameter() const noexcept
{
    return _custom_parameter;
}

void Request::setParentTask(const std::shared_ptr<Task> &task, int tag)
{
    LOCK_GUARD();
    if (_state != WAITING) {
        throw Exception(EC_NotAllowed, "Too late to set parent task");
    }
    if (_task) {
        throw Exception(EC_NotAllowed, "Parent task is already set");
    }
    _task = task;
    _task_tag = tag;
}

const TaskPtr& Request::getParentTask() const noexcept
{
    return _task;
}

int Request::getParentTaskTag() const noexcept
{
    return _task_tag;
}

// MARK: - Failure and cleanup

void Request::setFailed(std::exception_ptr exception) noexcept
{
    LOCK_GUARD();
    if (!isDone()) {
        CC7_LOG("Request set as failed");
        _state = FAILED;
        _failure = Exception::wrapException(exception);
    }
}

void Request::reThrowFailure() const
{
    LOCK_GUARD();
    if (isFailed()) {
        if (_failure) {
            std::rethrow_exception(_failure);
        }
        throw Exception(EC_Other, "Request failed with no exact reason");
    }
    throw Exception(EC_NotAllowed, "Request did not fail");
}

void Request::processFailure(ErrorCode ec, const std::string& msg, std::exception_ptr failure)
{
    _state = FAILED;
    CC7_LOG("Request failure (%d): %s", ec, msg.c_str());
    _failure = Exception::wrapException(ec, msg, failure);
    notifyResult();
    cleanup();
    std::rethrow_exception(_failure);
}

void Request::cleanup() noexcept
{
    _encryptor_factory = nullptr;
    _encryptor = nullptr;
    _authenticator = nullptr;
    _on_prepare = nullptr;
    _on_cancel = nullptr;
    _on_response = nullptr;
    _task = nullptr;
}

void Request::notifyResult() noexcept
{
    if ((_state == FAILED || _state == CANCELED) && _on_cancel) {
        try {
            auto callback = std::move(_on_cancel);
            callback();
        } catch (...) {
            // TODO: log exception
            CC7_LOG("Cancel callback in request failed");
        }
    }
    if (_task) {
        try {
            auto task = std::move(_task);
            task->setRequestCompleted(*this);
        } catch (...) {
            // TODO: log exception
            CC7_LOG("Task completion callback in request failed");
        }
    }
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
    
    // Sanity checks
    if (is_encrypted && !_encryptor_factory) {
        throw Exception(EC_InternalError, "No encryptor factory is set for encrypted request");
    }
    if (is_authenticated && !_authenticator) {
        throw Exception(EC_InternalError, "No authenticator is set for authenticated request");
    }

    prepareRequestBody();

    if (is_encrypted) {
        // Endpoint needs encryption
        _encryptor = _encryptor_factory->getClientEncryptor(_endpoint.encryptorId);
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
        // Calculate authentication header
        auto header = _authenticator->calculateOnlineAuthenticationHeader(*_authentication, {
            _endpoint.uriId,
            _endpoint.method,
            _endpoint.isAllowedInPendingRegistration(),
            _endpoint.isAllowedInUpgrade()
        }, _request_body);
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

void Request::processResponse(const cc7::ByteRange& response_data)
{
    LOCK_GUARD();
    if (_state != PENDING) {
        throw Exception(EC_NotAllowed, "Cannot process response, because request is in wrong state");
    }
    try {
        doProcessResponse(response_data);
        if (_on_response) {
            _response_object = _on_response(*this, _response_json);
            _on_response = nullptr;
        }
        _state = PROCESSED;
        notifyResult();
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
            if (root.containsValueAtPath("responseObject")) {
                _response_json = root["responseObject"];
            } else {
                _response_json = cc7::json::JsonValue::null();
            }
        } else {
            throw Exception(EC_InvalidData, "Non-OK response received");
        }
    } else {
        _response_json = root;
    }
    if (_endpoint.isEncrypted()) {
        _response_body = _encryptor->decryptResponse({ _response_json });
        _response_json = cc7::json::JsonReader::fromJsonData(_response_body);
        _encryptor = nullptr;
    } else {
        _request_body = response_data;
    }
}

} // namespace powerAuth
