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

enum ErrorCode
{
    EC_Ok,
    EC_MissingActivation,
    EC_WrongActivationState,
    EC_WrongParameter,
    EC_BiometryNotAllowed,
    EC_NotAllowed,
    EC_InvalidData,
    EC_InvalidResponse,
    EC_InternalError,
    EC_Cryptography,
    EC_Other
};

class Exception : public cc7::BaseException
{
public:
    Exception(ErrorCode error) noexcept :
        cc7::BaseException(defaultMessage(error)),
        _error(error)
    {
    }

    Exception(ErrorCode error, const std::string& message, std::exception_ptr cause = nullptr) noexcept :
        cc7::BaseException(message.empty() ? defaultMessage(error) : message, cause),
        _error(error)
    {
    }

    Exception(ErrorCode error, const char* message, std::exception_ptr cause = nullptr) noexcept :
        cc7::BaseException(message ? std::string(message) : defaultMessage(error), cause),
        _error(error)
    {
    }
    
    ErrorCode error() const noexcept
    {
        return _error;
    }
    
    const std::string & exceptionClass() const noexcept override
    {
        return CLASS_NAME;
    }
    
    static void reThrowWrapped [[noreturn]] (std::exception_ptr = std::current_exception());
    static void reThrowWrapped [[noreturn]] (const std::string & message, std::exception_ptr = std::current_exception());
    static void reThrowWrapped [[noreturn]] (ErrorCode error, const std::string & message, std::exception_ptr = std::current_exception());
    
private:
    
    Exception(ErrorCode error, std::exception_ptr cause) noexcept :
        cc7::BaseException(defaultMessage(error), cause),
        _error(error)
    {
    }

    
    static std::string defaultMessage(ErrorCode error) noexcept;
    
    ErrorCode _error;
    
    static const std::string CLASS_NAME;
};

} // namespace powerAuth
