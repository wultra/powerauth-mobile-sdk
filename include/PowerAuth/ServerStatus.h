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

#include <PowerAuth/Response.h>

namespace powerAuth {

class ServerStatus : public ResponseObject
{
public:
    ServerStatus(const cc7::json::JsonValue& response);
    
    const std::string& applicationName() const noexcept;
    const std::string& applicationVersion() const noexcept;
    Timestamp serverTime() const noexcept;
    
private:
    std::string _applicationName;
    std::string _applicationVersion;
    Timestamp _serverTime;
};

CC7_SHARED_PTR(ServerStatus)

} // namespace powerAuth
