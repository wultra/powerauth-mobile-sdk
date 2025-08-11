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

#include <PowerAuth/AuthenticationService.h>
#include <cc7/utils/URLEncoding.h>

namespace powerAuth {

cc7::ByteArray IAuthenticationService::normalizeGetRequestParameters(std::map<std::string, std::string>& map) const
{
    // Create a vector of keys
    std::vector<const std::string *> keys;
    keys.reserve(map.size());
    size_t expected_result_size = 0;
    for (auto && kvpair : map) {
        expected_result_size += 2 + kvpair.first.length() + kvpair.second.length();
        keys.push_back(&kvpair.first);
    }
    // Sort that keys
    std::sort(keys.begin(), keys.end(), [](const std::string * a, const std::string * b) {
        return a->compare(*b) < 0;
    });
    // Concat sorted keys & values into: 'key1=value1&keyN=valueN' byte blob
    cc7::ByteArray result;
    result.reserve(expected_result_size);
    for (auto && key_ptr : keys) {
        const std::string & key   = *key_ptr;
        const std::string & value = map.find(key)->second;
        if (!result.empty()) {
            result.append('&');
        }
        result.append(cc7::utils::ConvertStringToUrlEncodedData(key));
        result.append('=');
        result.append(cc7::utils::ConvertStringToUrlEncodedData(value));
    }
    return result;
}

static std::string VerifyCredentialsReasonToString(VerifyCredentialsReason reason)
{
    switch (reason) {
        case VerifyCredentialsReason::VALIDATE_PASSWORD:
            return "VALIDATE_PASSWORD";
        case VerifyCredentialsReason::COUNTER_SYNCHRONIZATION:
            return "COUNTER_SYNCHRONIZATION";
    }
}

RequestPtr IAuthenticationService::verifyCredentialsWithReason(const CredentialsPtr &credentials, VerifyCredentialsReason reason)
{
    auto request = cc7::json::JsonValue::object({
        { "reason", cc7::json::JsonValue::string(VerifyCredentialsReasonToString(reason)) }
    });
    return verifyCredentials(credentials, request);
}

RequestPtr IAuthenticationService::verifyPassword(const Password &password)
{
    return verifyCredentialsWithReason(Credentials::knowledge(password.passwordData()),
                                       VerifyCredentialsReason::VALIDATE_PASSWORD);
}

} // namespace powerAuth
