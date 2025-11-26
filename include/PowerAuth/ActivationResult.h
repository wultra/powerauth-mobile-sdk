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

class ActivationResult : public ResponseObject
{
public:
    
    ActivationResult(const std::string & activation_fingerprint,
                     const cc7::json::JsonValue& response);
    
    const std::string& activationFingerprint() const noexcept;
    const cc7::json::JsonValue& customAttributes() const noexcept;
    const cc7::json::JsonValue& userInfo() const noexcept;
    
private:
    const std::string _activation_fingerprint;
    const cc7::json::JsonValue _custom_attributes;
    const cc7::json::JsonValue _user_info;
};

CC7_SHARED_PTR(ActivationResult);

} // namespace powerAuth
