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
#include "Context.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex)

Task::Task(const std::string& name, const ContextPtr& context) :
    _name(name),
    _mutex(context->getSharedMutexPtr()),
    _context(context),
    _state(State::CREATED),
    _processed_requests(0),
    _completion_processed(false)
{
    //log("Task allocated");
}

Task::~Task()
{
    //log("Task deleted");
}

const std::string& Task::name() const noexcept
{
    return _name;
}

const ResponseObjectPtr& Task::getResponseObject() const
{
    LOCK_GUARD();
    if (_state != State::COMPLETED) {
        throw Exception(EC_NotAllowed, "Response object is not available");
    }
    return _response_object;
}

const cc7::json::JsonValue& Task::getResponseJson() const
{
    LOCK_GUARD();
    if (_state != State::COMPLETED) {
        throw Exception(EC_NotAllowed, "Response JSON is not available");
    }
    return _response_json;
}

void Task::log(const std::string &message) const noexcept
{
    CC7_LOG("%s: %s", _name.c_str(), message.c_str());
}

void Task::start() noexcept
{
    LOCK_GUARD();
    if (_state == State::CREATED) {
        _state = State::PENDING;
        try {
            onTaskStart();
        } catch (...) {
            captureExceptionAndComplete();
        }
    }
}

void Task::cancel() noexcept
{
    LOCK_GUARD();
    _state = State::CANCELED;
    if (_next_request) {
        _next_request->cancel();
        _next_request = nullptr;
    }
    cancelCurrentRequest();
}

bool Task::isDone() const noexcept
{
    LOCK_GUARD();
    return _state > State::PENDING;
}

bool Task::isCanceled() const noexcept
{
    LOCK_GUARD();
    return _state == State::CANCELED;
}

bool Task::isCompleted() const noexcept
{
    LOCK_GUARD();
    return _state == State::COMPLETED;
}

bool Task::isFailed() const noexcept
{
    LOCK_GUARD();
    return _state == State::FAILED;
}

void Task::setFailed(std::exception_ptr exception) noexcept
{
    LOCK_GUARD();
    captureExceptionAndComplete(exception);
}

void Task::setCompleted(bool clear_failure) noexcept
{
    LOCK_GUARD();
    try {
        cancelCurrentRequest();
        if (_state < State::COMPLETED) {
            if (_processed_requests) {
                _state = State::COMPLETED;
            } else {
                throw Exception(EC_InternalError, "No request processed in the task");
            }
        }
        if (!_completion_processed) {
            _completion_processed = true;
            if (clear_failure) {
                _failure = nullptr;
            }
            onTaskEnd();
        }
    } catch (...) {
        captureExceptionAndComplete();
    }
}

void Task::reThrowFailure()
{
    LOCK_GUARD();
    if (isFailed()) {
        if (_failure) {
            std::rethrow_exception(_failure);
        }
        throw Exception(EC_Other, "Task failed with no exact reason");
    }
    throw Exception(EC_NotAllowed, "Task did not fail");
}

RequestPtr Task::getNextRequest()
{
    LOCK_GUARD();
    if (_state == State::CREATED) {
        start();
    }
    if (_state == State::PENDING) {
        if (_next_request) {
            auto request = std::move(_next_request);
            request->setParentTask(shared_from_this(), _current_request_tag);
            _current_request = request;
            return request;
        }
        setCompleted();
    }
    if (_state == State::FAILED) {
        reThrowFailure();
    }
    return nullptr;
}

void Task::setNextRequest(const RequestPtr &request, int tag, int flags)
{
    LOCK_GUARD();
    if (!request) {
        throw Exception(EC_InternalError, "Next request is null");
    }
    if (_next_request) {
        throw Exception(EC_InternalError, "Next request is already set");
    }
    _processed_requests++;
    _next_request = request;
    _current_request_tag = tag;
    _current_request_flags = flags;
}

void Task::cancelCurrentRequest() noexcept
{
    if (auto request = _current_request.lock()) {
        _current_request.reset();
        request->cancelFromTask();
    }
}

void Task::setRequestCompleted(const Request &request) noexcept
{
    LOCK_GUARD();
    try {
        if (request.getParentTaskTag() != _current_request_tag) {
            throw Exception(EC_InternalError, "Unknown tag in request");
        }
        const auto is_primary = (_current_request_flags & RF_PRIMARY) == RF_PRIMARY;
        const auto ignore_fail = (_current_request_flags & RF_IGNORE_FAILURE) == RF_IGNORE_FAILURE;
        if (request.isCompleted()) {
            log(request.getRelativePath() + ": Request succeeded");
            if (_state == State::PENDING) {
                if (is_primary) {
                    _response_object = request.getResponseObject();
                    if (request.isPublicResponseJson()) {
                        _response_json = request.getResponseJson();
                    } else {
                        _response_json = cc7::json::JsonValue();
                    }
                }
                onRequestSuccess(request);
            }
        } else if (request.isFailed()) {
            log(request.getRelativePath() + ": Request failed");
            if (_state == State::PENDING) {
                if (!ignore_fail) {
                    _response_object = nullptr;
                    _response_json = cc7::json::JsonValue();
                    try {
                        request.reThrowFailure();
                    } catch (...) {
                        captureException();
                    }
                }
                // Always notify about failure
                onRequestFailure(request);
            }
        } else if (request.isCanceled()) {
            log(request.getRelativePath() + ": Request canceled");
            if (_state == State::PENDING) {
                onRequestCancel(request);
            }
        } else {
            throw Exception(EC_InternalError, "Completion is set in unknown request's state");
        }
    } catch (...) {
        captureExceptionAndComplete();
    }
}

void Task::captureException(std::exception_ptr exception) noexcept
{
    if (_state != State::CANCELED) {
        if (!_failure) {
            _failure = Exception::wrapException(exception);
        }
        _state = State::FAILED;
    }
}

void Task::captureExceptionAndComplete(std::exception_ptr exception) noexcept
{
    captureException(exception);
    setCompleted();
}

ContextPtr Task::lockContext()
{
    if (auto context = _context.lock()) {
        return context;
    }
    throw Exception(EC_InternalError, "Session object is no longer valid");
}

// MARK: - Overridable methods

void Task::onTaskStart()
{
    log("Task started");
}

void Task::onTaskEnd()
{
    switch (_state) {
        case State::COMPLETED:
            log("Task finished with success");
            break;
        case State::FAILED:
            log("Task finished with failure");
            break;
        case State::CANCELED:
            log("Task finished with cancel");
        default:
            break;
    }
}

void Task::onRequestSuccess(const Request& request)
{
    // empty
}

void Task::onRequestFailure(const Request& request)
{
    // By default, set task as completed
    setCompleted();
}

void Task::onRequestCancel(const Request& request)
{
    // empty
}


} // namespace powerAuth
