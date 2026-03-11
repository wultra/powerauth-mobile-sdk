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

#include <PowerAuth/ServerStatus.h>

namespace powerAuth {

ServerStatus::ServerStatus(const cc7::json::JsonValue& response)
{
    _serverTime = response["serverTime"].asInteger();
    if (response.containsValueAtPath("application")) {
        _applicationName = response.stringAtPath("application.name");
        _applicationVersion = response.stringAtPath("application.version");
    }
}

Timestamp ServerStatus::serverTime() const noexcept
{
    return _serverTime;
}

const std::string& ServerStatus::applicationName() const noexcept
{
    return _applicationName;
}

const std::string& ServerStatus::applicationVersion() const noexcept
{
    return _applicationVersion;
}


} // namespace powerAuth
