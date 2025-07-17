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
    
    /// Set request as failed.
    void setFailed() noexcept;

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
            
    /// Returns `true` if request completed with success.
    bool isCompleted() const noexcept;
    
    /// Returns `true` if request was canceled.
    bool isCanceled() const noexcept;
    
    /// Returns `true` if request completed with failure.
    bool isFailed() const noexcept;
    
    /// Returns `true` if request is completed with any type of result (success, cancel, failure).
    bool isDone() const noexcept;
    
    /// Returns relative part of path to endpoint's URL.
    const std::string& getRelativePath() const noexcept;
    
    /// Returns HTTP method.
    const std::string& getHttpMethod() const noexcept;
        
    /// Returns `true` if request require synchronized time for proper processing.
    bool requireSynchronizedTime() const noexcept;
    
    /// Returns `true` if request must be executed in serial queue.
    bool requireSerialQueue() const noexcept;
    
    /// Returns `true` if request is allowed during the protocol upgrade.
    bool isAllowedInUpgrade() const noexcept;
    
    /// Returns `true` if request is encrypted.
    bool isEncrypted() const noexcept;
    
    /// Returns `true` if request is authenticated with authentication header.
    bool isAuthenticated() const noexcept;
    
    /// Returns scope of temporary key required for proper processing. If request is not
    /// encrypted, then throws exception.
    EncryptorScope encryptorScope() const;
    
    
    /// Returns request's body.
    ///
    /// You have to call `prepareRequest()` from the processing queue, before you
    /// get the body, otherwise exception is raised.
    const cc7::ByteArray& getRequestBody() const;
    
    /// Returns request's headers.
    ///
    /// You have to call `prepareRequest()` from the processing queue, before you
    /// get the headers, otherwise exception is raised.
    const HttpHeaderList& getRequestHeaders() const;

    
    /// Returns response body.
    ///
    /// You have to call `processResponse()` before you get the response, otherwise
    /// the exception is raised.
    const cc7::ByteArray& getResponseBody() const;
    
    /// Returns response object or `nullptr` if response object was not created in the response
    /// processing.
    ///
    /// You have to call `processResponse()` before you get the response, otherwise
    /// the exception is raised.
    const ResponseObjectPtr& getResponseObject() const;
    
    /// Get typed response object.
    ///
    /// - Parameter required: If true, then exception is raised if type of object is different
    ///                       or no response object was created during the processing.
    /// - Returns: Smart pointer to typed response object.
    template <typename T> std::shared_ptr<T> getTypedResponseObject(bool required = true) const
    {
        auto response = getResponseObject();
        auto typed = std::dynamic_pointer_cast<T>(response);
        if (required && typed == nullptr) {
            if (response != nullptr) {
                throw Exception(EC_InvalidResponse, "Wrong response object type created");
            } else {
                throw Exception(EC_InvalidResponse, "Response object is null");
            }
        }
        return typed;
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
        /// Request is waiting to prepare request body and headers.
        WAITING,
        /// Request is awaiting response from the server.
        PENDING,
        /// Request successfully processed the response.
        PROCESSED,
        /// Request failed.
        FAILED,
        /// Request is canceled.
        CANCELED,
    };
    
    friend class RequestBuilder;
    
    /// Request constructor.
    /// - Parameters:
    ///   - mutex: Shared mutex.
    ///   - endpoint: Endpoint specification.
    Request(const SharedMutexPtr& mutex, const EndpointSpec& endpoint);

    /// Prepare request body and headers.
    void doPrepareRequest();
    
    /// Process response data.
    /// - Parameter response_data: Response data to process.
    void doProcessResponse(const cc7::ByteRange& response_data);

    /// Cleanup request. The method clears all pointers to callbacks and breaks possible retain loops.
    void cleanup();
    
    /// Prepares request body.
    void prepareRequestBody();
    
    /// Process failure and re-throw the provided exception.
    void processFailure [[noreturn]] (ErrorCode ec, const std::string& msg, std::exception_ptr failure);
    
    /// Cancel implementation.
    /// - Parameter destruct: Indicate that cancel is called from object's destructor.
    void cancelImpl(bool destruct);
    
    /// Endpoint specification.
    const EndpointSpec & _endpoint;
    
    /// Prepare callback.
    PrepareRequestCallback _on_prepare;
    /// Response callback.
    ResponseCallback _on_response;
    /// Cancel callback.
    CancelCallback _on_cancel;
    
    /// If request is encrypted then contains encryptor.
    std::shared_ptr<IClientEncryptor> _encryptor;
    /// If request is authenticated then contains authentication code calculator.
    std::shared_ptr<IAuthHeaderCalculator> _authenticator;
    /// If request is authenticated then contains user's credentials.
    std::shared_ptr<Credentials> _authentication;
    
    /// Shared mutex.
    SharedMutexPtr _mutex;
    /// State of the request.
    State _state;
    /// Request headers.
    HttpHeaderList _request_headers;

    /// Request body.
    cc7::ByteArray _request_body;
    /// Request JSON.
    cc7::json::JsonValue _request_json;
    /// Response body.
    cc7::ByteArray _response_body;
    /// Response JSON.
    cc7::json::JsonValue _response_json;
    /// Response object, if created.
    ResponseObjectPtr _response_object;
};

typedef std::unique_ptr<Request> RequestPtr;

} // namespace powerAuth
