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

CC7_SHARED_PTR(ResponseObject)

using PrepareRequestCallback = std::function<cc7::json::JsonValue(const Request&)>;
using ResponseCallback = std::function<ResponseObjectPtr(const Request&, const cc7::json::JsonValue&)>;
using CancelCallback   = std::function<void()>;

struct EndpointSpec;
class IClientEncryptor;
class IAuthHeaderCalculator;
class Credentials;

/// The `Request` class contains information about HTTP request created in the core module.
/// The core module doesn't perform any networking, so the higher level SDK is responsible
/// for the request execution and the response delegate back to this request object.
///
/// Be aware, that the Request is designed only to process a successful responses, and therefore
/// non-200 responses has to be processed in the networking code.
class Request
{
public:
    
    /// Object's destructor.
    ~Request();
    
    /// Cancel the request. The networking code should call this method also when the
    /// non-200 response code is received.
    void cancel();
    
    /// Prepare the request body and the headers. You have to call this method before you
    /// call `getRequestBody()` or `getRequestHeaders()`.
    ///
    /// The method should be called from the background thread dedicated for the networking,
    /// because preparation may take a significant amount of CPU time (for example, if activation
    /// is being created).
    void prepareRequest();
    
    /// Process response and set request completed.
    /// - Parameter response_data: Response data.
    void processResponse(const cc7::ByteRange& response_data);
        
    bool isCompleted() const noexcept;
    bool isCanceled() const noexcept;
    bool isFailed() const noexcept;
    bool isDone() const noexcept;
    
    const std::string& getRelativePath() const noexcept;
    const std::string& getHttpMethod() const noexcept;
        
    bool requireSynchronizedTime() const noexcept;
    bool requireSerialQueue() const noexcept;
    bool isAllowedInUpgrade() const noexcept;
    bool isEncrypted() const noexcept;
    bool isAuthenticated() const noexcept;
    EncryptorScope encryptorScope() const;
    
    const cc7::ByteArray& getRequestBody() const;
    const HttpHeaderList& getRequestHeaders() const;

    const cc7::ByteArray& getResponseBody() const;
    
    const ResponseObjectPtr& getResponseObject() const;
    
    template <typename T> std::shared_ptr<T> getTypedResponseObject() const
    {
        return std::dynamic_pointer_cast<T>(getResponseObject());
    }
    
    /// Execute operation while internal lock is granted.
    /// - Parameter operation: Operation to execute.
    /// - Returns: Value returned from operation function.
    template <typename T> T executeOperation(std::function<T()> operation)
    {
        std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex);
        return operation();
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
    PrepareRequestCallback _on_prepare;
    ResponseCallback _on_response;
    CancelCallback _on_cancel;
    
    std::shared_ptr<IClientEncryptor> _encryptor;
    std::shared_ptr<IAuthHeaderCalculator> _authenticator;
    std::shared_ptr<Credentials> _authentication;
    
    SharedMutexPtr _mutex;
    State _state;
    HttpHeaderList _request_headers;

    cc7::ByteArray _request_body;
    cc7::json::JsonValue _request_json;

    cc7::ByteArray _response_body;
    cc7::json::JsonValue _response_json;
    ResponseObjectPtr _response_object;
};

typedef std::unique_ptr<Request> RequestPtr;

} // namespace powerAuth
