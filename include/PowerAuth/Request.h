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

#include <PowerAuth/Types.h>
#include <cc7/json/Json.h>

#include <functional>
#include <memory>

namespace powerAuth {

class Request;

class ResponseObject
{
public:
    virtual ~ResponseObject();
};

typedef std::shared_ptr<ResponseObject> ResponseObjectPtr;

using ResponseCallback = std::function<ResponseObjectPtr(const Request&, const cc7::json::JsonValue&)>;
using CancelCallback   = std::function<void()>;


struct EndpointSpec;
class IClientEncryptor;
class IAuthHeaderCalculator;
class Credentials;

class Request
{
public:
    
    ~Request();
    
    void cancel();
    
    void prepareRequest();
    void processResponse(const cc7::ByteRange& response_data);
    
    bool isCompleted() const noexcept;
    bool isCanceled() const noexcept;
    bool isFailed() const noexcept;
    bool isDone() const noexcept;
    
    const std::string& getLocalPath() const noexcept;
    const std::string& getHttpMethod() const noexcept;
        
    bool requireSynchronizedTime() const noexcept;
    bool requireSerialQueue() const noexcept;
    bool isAllowedInUpgrade() const noexcept;
    bool isEncrypted() const noexcept;
    bool isAuthenticated() const noexcept;

    const cc7::ByteArray& getRequestBody() const;
    const std::vector<HttpHeader>& getRequestHeaders() const;

    const cc7::ByteArray& getResponseBody() const;
    
    const ResponseObjectPtr& getResponseObject() const;
    
    template <typename T> std::shared_ptr<T> getTypedResponseObject() const
    {
        return std::dynamic_pointer_cast<T>(_response_object);
    }
    
private:
    
    enum State
    {
        WAITING,
        PENDING,
        PROCESSED,
        FAILED,
        CANCELED,
    };
    
    friend class RequestBuilder;
    
    Request(const SharedMutexPtr& mutex, const EndpointSpec& endpoint);

    void doPrepareRequest();
    void doProcessResponse(const cc7::ByteRange& response_data);

    void cleanup();
    void prepareRequestBody();
    void processFailure [[noreturn]] (ErrorCode ec, const std::string& msg, std::exception_ptr failure);
    
    const EndpointSpec & _endpoint;
    ResponseCallback _on_response;
    CancelCallback _on_cancel;
    
    std::shared_ptr<IClientEncryptor> _encryptor;
    std::shared_ptr<IAuthHeaderCalculator> _authenticator;
    std::shared_ptr<Credentials> _authentication;
    
    SharedMutexPtr _mutex;
    State _state;
    std::vector<HttpHeader> _request_headers;

    cc7::ByteArray _request_body;
    cc7::json::JsonValue _request_json;

    cc7::ByteArray _response_body;
    cc7::json::JsonValue _response_json;
    ResponseObjectPtr _response_object;
};

typedef std::unique_ptr<Request> RequestPtr;

} // namespace powerAuth
