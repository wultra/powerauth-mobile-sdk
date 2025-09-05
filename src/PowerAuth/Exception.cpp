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

#include <PowerAuth/Exception.h>
#include <cc7/crypto/CryptoException.h>
#include <cc7/json/JsonException.h>

namespace powerAuth {

const std::string Exception::CLASS_NAME("powerAuth::PowerAuthException");

std::string Exception::defaultMessage(ErrorCode error) noexcept
{
    switch (error) {
        case EC_Canceled:
            return "Operation canceled from elsewhere";
        case EC_MissingActivation:
            return "Activation is missing";
        case EC_WrongActivationState:
            return "Wrong activation state";
        case EC_WrongParameter:
            return "Invalid input parameter";
        case EC_Cryptography:
            return "Cryptographic operation failed";
        case EC_InvalidData:
            return "Invalid input data";
        case EC_InvalidResponse:
            return "Invalid response received";
        case EC_BiometryNotAllowed:
            return "Biometry not configured";
        case EC_NotAllowed:
            return "Operation is not allowed in object's state";
        case EC_TimeNotSynchronized:
            return "Operation require time synchronized with server";
        case EC_InternalError:
            return "Internal library error";
        case EC_Other:
            return "Other error";
        default:
            return "Unknown error";
    }
}

static ErrorCode inspectErrorCode(std::exception_ptr e, bool& no_wrap_needed)
{
    no_wrap_needed = false;
    try {
        std::rethrow_exception(e);
    } catch (Exception & e) {
        no_wrap_needed = true;
        return e.error();
    } catch (cc7::json::JsonException & e) {
        return EC_InvalidData;
    } catch (cc7::crypto::UnsupportedAlgorithm & e) {
        return EC_InternalError;
    } catch (cc7::crypto::InternalError & e) {
        return EC_InternalError;
    } catch (cc7::crypto::CryptoException & e) {
        return EC_Cryptography;
    } catch (std::invalid_argument & e) {
        return EC_WrongParameter;
    } catch (std::domain_error & e) {
        return EC_Cryptography;
    } catch (std::logic_error & e) {
        return EC_InternalError;
    } catch (...) {
        return EC_Other;
    }
}

void Exception::reThrowWrapped(std::exception_ptr e)
{
    bool no_wrap = false;
    auto ec = inspectErrorCode(e, no_wrap);
    if (no_wrap) {
        std::rethrow_exception(e);
    }
    throw Exception(ec, e);
}

void Exception::reThrowWrapped(const std::string & message, std::exception_ptr e)
{
    bool no_wrap = false;
    auto ec = inspectErrorCode(e, no_wrap);
    if (no_wrap) {
        std::rethrow_exception(e);
    }
    throw Exception(ec, message, e);
}

void Exception::reThrowWrapped(ErrorCode error, const std::string & message, std::exception_ptr e)
{
    bool no_wrap = false;
    auto ec = inspectErrorCode(e, no_wrap);
    if (no_wrap || ec == error) {
        std::rethrow_exception(e);
    }
    throw Exception(ec, message, e);
}

std::exception_ptr Exception::wrapException(std::exception_ptr failure) noexcept
{
    try {
        reThrowWrapped(failure);
    } catch (...) {
        return std::current_exception();
    }
}

std::exception_ptr Exception::wrapException(ErrorCode error, const std::string &message, std::exception_ptr failure) noexcept
{
    try {
        reThrowWrapped(error, message, failure);
    } catch (...) {
        return std::current_exception();
    }
}

} // namespace powerAuth
