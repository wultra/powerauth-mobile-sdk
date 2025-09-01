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

#include <cc7/BaseException.h>

namespace powerAuth {

/// Reason of the failure.
enum ErrorCode
{
    /// Session has no activation but activation is required for the operation.
    EC_MissingActivation = 1,
    /// Activation is in wrong state for the requested operation.
    EC_WrongActivationState,
    /// Wrong input parameter provided.
    EC_WrongParameter,
    /// Biometry factor is not configured.
    EC_BiometryNotAllowed,
    /// Operation is not allowed in the current object's state. For example,
    /// if you try to already used encryptor object.
    EC_NotAllowed,
    /// Operation require synchronized time.
    EC_TimeNotSynchronized,
    /// Invalid data. Error is reported in situations, when configuration or
    /// serialized data format is not valid.
    EC_InvalidData,
    /// Invalid response received from the server.
    EC_InvalidResponse,
    /// Internal library error.
    EC_InternalError,
    /// Operation failed in the cryptographic provider.
    EC_Cryptography,
    /// Operation was canceled from elsewhere.
    EC_Canceled,
    /// Other, unspecified type of error.
    EC_Other
};

/// The `Exception` class is error type reported from this library in case the operation fails.
class Exception : public cc7::BaseException
{
public:
    /// Construct exception with error code. The default error message is used.
    Exception(ErrorCode error) noexcept :
        cc7::BaseException(defaultMessage(error)),
        _error(error)
    {
    }
    
    /// Construct exception with error code, message and optional original cause of the failure.
    /// - Parameters:
    ///   - error: Reason of the failure.
    ///   - message: Error message
    ///   - cause: Original cause. If `nullptr` then there's no original cause of the failure.
    Exception(ErrorCode error, const std::string& message, std::exception_ptr cause = nullptr) noexcept :
        cc7::BaseException(message.empty() ? defaultMessage(error) : message, cause),
        _error(error)
    {
    }

    /// Construct exception with error code, message and optional original cause of the failure.
    /// - Parameters:
    ///   - error: Reason of the failure.
    ///   - message: Error message
    ///   - cause: Original cause. If `nullptr` then there's no original cause of the failure.
    Exception(ErrorCode error, const char* message, std::exception_ptr cause = nullptr) noexcept :
        cc7::BaseException(message ? std::string(message) : defaultMessage(error), cause),
        _error(error)
    {
    }

    /// Returns reason of the failure.
    ErrorCode error() const noexcept
    {
        return _error;
    }
    
    /// Wrap the current exception into library's Exception object and throw this new created failure.
    /// If the current exception is already our `Exception` type, then re-throws this exception with
    /// no additional processing.
    ///
    /// This variant of the method determine `ErrorCode` and exception's message from the current
    /// exception.
    ///
    /// This is the typical usage of the method:
    /// ```
    /// try {
    ///     // code that should crash
    /// } catch (...) {
    ///     Exception::reThrowWrapped();
    /// }
    /// ```
    /// - Parameter failure:
    /// - Throws: Function always throws `Exception` type.
    static void reThrowWrapped [[noreturn]] (std::exception_ptr failure = std::current_exception());
    
    /// Wrap the current exception into library's Exception object and throw this new created failure.
    /// If the current exception is already our `Exception` type, then re-throws this exception with
    /// no additional processing.
    ///
    /// This variant of the method determine `ErrorCode` from the current exception but use a provided
    /// message for the wrapping exception. If no wrapping is used, then the message is ignored.
    ///
    /// - Parameters:
    ///   - message: Message to use in wrapped exception.
    ///   - failure: Original failure.
    /// - Throws: Function always throws `Exception` type.
    static void reThrowWrapped [[noreturn]] (const std::string & message, std::exception_ptr failure = std::current_exception());
    
    /// Wrap the current exception into library's Exception object and throw this new created failure.
    /// If the current exception is already our `Exception` type, then re-throws this exception with
    /// no additional processing.
    ///
    /// This variant of the allows you to specify `ErrorCode` and the message for the wrapping exception.
    /// If no wrapping is used, then the code and message is ignored.
    ///
    /// - Parameters:
    ///   - error: Error code to use in wrapped exception.
    ///   - message: Message to use in wrapped exception.
    ///   - failure: Original failure.
    /// - Throws: Function always throws `Exception` type.
    static void reThrowWrapped [[noreturn]] (ErrorCode error, const std::string & message, std::exception_ptr failure = std::current_exception());
    
    // cc7::BaseException
    
    const std::string & exceptionClass() const noexcept override
    {
        return CLASS_NAME;
    }

private:
    
    /// The private constructor used internally by `reThrowWrapped()` methods.
    /// - Parameters:
    ///   - error: Error code to use.
    ///   - cause: Original failure.
    Exception(ErrorCode error, std::exception_ptr cause) noexcept :
        cc7::BaseException(defaultMessage(error), cause),
        _error(error)
    {
    }

    /// Function return string with default error message for given error code.
    /// - Parameter error: Error code.
    /// - Returns: Default error message for given code.
    static std::string defaultMessage(ErrorCode error) noexcept;
    
    /// Error code.
    const ErrorCode _error;
    
    /// Name of the class.
    static const std::string CLASS_NAME;
};

} // namespace powerAuth
