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

#include <PowerAuth/ActivationResult.h>

namespace powerAuth {

static cc7::json::JsonValue GetOptionalJsonObject(const cc7::json::JsonValue& response, const std::string& key)
{
    auto value = response.findValueAtPath(key);
    return value ? *value : cc7::json::JsonValue::object();
}

ActivationResult::ActivationResult(const std::string & activation_fingerprint,
                                   const cc7::json::JsonValue& response) :
    _activation_fingerprint(activation_fingerprint),
    _custom_attributes(GetOptionalJsonObject(response, "customAttributes")),
    _user_info(GetOptionalJsonObject(response, "userInfo"))
{
}

const std::string& ActivationResult::activationFingerprint() const noexcept
{
    return _activation_fingerprint;
}

const cc7::json::JsonValue& ActivationResult::customAttributes() const noexcept
{
    return _custom_attributes;
}

const cc7::json::JsonValue& ActivationResult::userInfo() const noexcept
{
    return _user_info;
}

} // namespace powerAuth
