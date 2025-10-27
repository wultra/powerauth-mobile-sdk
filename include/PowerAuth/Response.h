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

namespace powerAuth {

/// The `ResponseObject` is a base class for all response objects.
class ResponseObject
{
public:
    virtual ~ResponseObject() = default;
};

CC7_SHARED_PTR(ResponseObject)


/// The `DataResponse` class is useful for generic data response created
/// in the request processing.
class DataResponse : public ResponseObject
{
public:
    /// Construct response with provided data.
    /// - Parameter data: Data to capture in the response.
    DataResponse(const cc7::ByteRange& data) noexcept : _data(data) {}
    
    /// Get data stored in the response.
    const cc7::ByteArray& data() const noexcept
    {
        return _data;
    }
    
private:
    const cc7::ByteArray _data;
};


/// The `JsonResponse` class is useful for generic JSON response created
/// in the request processing.
class JsonResponse : public ResponseObject
{
public:
    /// Construct response with provided JSON object.
    /// - Parameter json: JSON to capture in the response.
    JsonResponse(const cc7::json::JsonValue& json) noexcept : _json(json) {}
    
    /// Get JSON stored in the response.
    const cc7::json::JsonValue& json() const noexcept
    {
        return _json;
    }
    
private:
    const cc7::json::JsonValue _json;
};


/// The `StringResponse` class is useful for generic string response created
/// in the request processing.
class StringResponse : public ResponseObject
{
public:
    /// Construct response with provided string.
    /// - Parameter string: String to capture in the response.
    StringResponse(const std::string_view& string) noexcept : _string(string) {}
    
    /// Get string stored in the response.
    const std::string& string() const noexcept
    {
        return _string;
    }
    
private:
    const std::string _string;
};


} // namespace powerAuth
