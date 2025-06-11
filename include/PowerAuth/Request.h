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

using ResponseCallback = std::function<void(const cc7::json::JsonValue&)>;
using CancelCallback   = std::function<void()>;

class Request
{
public:
    void cancel();
    
    virtual ~Request();
    virtual void prepareRequest();
    virtual void processResponse(const cc7::ByteRange& response_data);
    
    const std::string& getLocalPath() const;
    const std::string& getMethod() const;
    const cc7::ByteArray& getBody() const;
    const std::vector<HttpHeader>& getHeaders() const;
    
    bool isSynchronized() const noexcept;
    
    
};

typedef std::unique_ptr<Request> RequestPtr;

template <typename Response>
class TypedRequest : public Request {
public:
    
    const Response& getTypedResponse();
    void setTypedResponse(const std::shared_ptr<Response>& response);
    
private:
    std::shared_ptr<Response> _typed_response;
};

} // namespace powerAuth
