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

namespace powerAuth {

/// The `Task` is a base class for executing a complex operations composed
/// from more than one HTTP request.
class Task :
    public std::enable_shared_from_this<Task>
{
public:
    
    /// Base class destructor.
    virtual ~Task();

    /// Construct task with required parameters.
    /// - Parameters:
    ///   - name: Task name. The value will appear in debug log and in exceptions.
    ///   - context: Context pointer.
    Task(const std::string& name, const std::shared_ptr<Context>& context);
    
    /// Contains name of the task.
    const std::string& name() const noexcept;
    
    /// Return next request to execute. If the task is not started yet, then it starts automatically.
    ///
    /// To avoid cyclic reference between `Task` and `Request` this function removes strong reference to the returned
    /// request. The caller must capture immediately the request's reference to keep it alive during its execution.
    /// The task then keeps only a weak reference for the cancelation purpose.
    ///
    /// - Returns: Next request to execute or `nullptr` in case the task is completed.
    /// - Throws: `Exception` if task start did fail. If task is already failed, then the method re-throws previously
    ///           captured exception.
    RequestPtr getNextRequest();
    
    /// Method re-throws internally captured exception in case that task failed. The method is useful when you need
    /// to know exact reason of the failure.
    ///
    /// If task did not fail, then throws exception with `EC_NotAllowed` error code. This may be colliding with actual
    ///  task's failure result, so it's recommended to test `isFailed()` before you try to determine the failure.
    void reThrowFailure [[noreturn]] ();
    
    /// Invoke task's start. If task is already started, then method does nothing.
    void start() noexcept;
    
    /// Cancel the task.
    void cancel() noexcept;
    
    /// Test whether task is finished its execution no matter of the type of the result.
    bool isDone() const noexcept;
    
    /// Test whether task has been canceled.
    bool isCanceled() const noexcept;
    
    /// Test whether task is completed with success.
    bool isCompleted() const noexcept;
    
    /// Test whether task is completed with failure.
    bool isFailed() const noexcept;
    
    /// Set external reason of the failure.
    /// - Parameter exception: External reason of the failure.
    void setFailed(std::exception_ptr exception) noexcept;
    
    /// Get response object.
    /// - Returns: Response object.
    /// - Throws: `Exception` with `EC_NotAllowed` if task is not finished yet.
    const ResponseObjectPtr& getResponseObject() const;
    
    /// Get response JSON.
    /// - Returns: Response JSON.
    /// - Throws: `Exception` with `EC_NotAllowed` if task is not finished yet.
    const cc7::json::JsonValue& getResponseJson() const;
    
protected:
    enum RequestFlags
    {
        /// If set, then the request is primary request. Task will keep its result
        /// object in case of success.
        RF_PRIMARY              = 1<<0,
        /// If set, then already captured response object from the primary request
        /// is not discarded in case of failure.
        RF_IGNORE_FAILURE       = 1<<1
    };
    
    /// Set next request for execution. Be aware that only one request can be executed
    /// at the same time.
    /// - Parameters:
    ///   - request: Request pointer.
    ///   - tag: Tag identifying this request.
    ///   - flags: Response processing flags.
    void setNextRequest(const RequestPtr& request, int tag, int flags);
    
    /// Set task as completed.
    void setCompleted() noexcept;
    
    // Overridable methods
    
    /// Overridable method, called when task is started.
    virtual void onTaskStart();
    
    /// Overridable method, called when task is ended.
    virtual void onTaskEnd();

    /// Overridable method, called when partial request ends with success.
    /// - Parameters:
    ///   - request: Request that just finished.
    virtual void onRequestSuccess(const Request& request);
    
    /// Overridable method, called when partial request ends with failure.
    /// - Parameters:
    ///   - request: Request that just failed.
    virtual void onRequestFailure(const Request& request);
    
    /// Overridable method, called when partial request is canceled.
    /// - Parameters:
    ///   - request: Request that just finished.
    virtual void onRequestCancel(const Request& request);
        
    /// Helper method that allows you acquire context from internal weak reference.
    /// Method throws exception if context cannot be acquired.
    std::shared_ptr<Context> lockContext();
    
    /// Print message to the debug log. The task name is used as prefix to the message.
    void log(const std::string& message) const noexcept;
    
    /// Contains task's name.
    const std::string _name;
    /// Contains shared mutex.
    const SharedMutexPtr& _mutex;
    
private:
    friend class Request;
    
    enum class State
    {
        CREATED,
        PENDING,
        COMPLETED,
        FAILED,
        CANCELED
    };
    
    /// Set request as completed. The method is called from `Request` when the request ends
    /// its execution.
    /// - Parameters:
    ///   - request: Reference to just finished request.
    void setRequestCompleted(const Request& request) noexcept;
    
    /// Helper method that captures the failure.
    void captureException(std::exception_ptr failure = std::current_exception()) noexcept;
    
    /// Helper method that captures the failure and sets task as completed.
    void captureExceptionAndComplete(std::exception_ptr failure = std::current_exception()) noexcept;
    
    /// Cancels current Request captured in weak pointer.
    void cancelCurrentRequest() noexcept;
    
    /// State of the task.
    State _state;
    /// Indicate that completion callbacks were processed.
    bool _completion_processed;
    /// Contains number of processed requests.
    int _processed_requests;
    
    /// Pointer to weak context
    std::weak_ptr<Context> _context;
    /// Strong reference to the next request.
    RequestPtr _next_request;
    /// Weak reference to the pending request.
    RequestWeakPtr _current_request;
    /// Next / current request's tag.
    int _current_request_tag;
    /// Next / current request's processing flags.
    int _current_request_flags;
    
    // Result
    
    /// Captured response object from the primary request.
    ResponseObjectPtr _response_object;
    /// Captured response JSON from the primary request.
    cc7::json::JsonValue _response_json;
    /// Captured reason of failure.
    std::exception_ptr _failure;
};

CC7_SHARED_PTR(Task)

} // namespace powerAuth
