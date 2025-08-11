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

#include "FunctionsV4.h"
#include "../model/Constants.h"
#include "../common/CommonFunctions.h"
#include <PowerAuth/Algorithms.h>

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

static std::vector<cc7::ByteArray> CalculateAuthorizationCodeComponents(const std::vector<cc7::ByteRange>& factor_keys,
                                                                        const cc7::ByteRange& counter,
                                                                        const cc7::ByteRange& data)
{
    // Prepare KMAC and parameters
    const auto& kmac = algorithms().v4.kmac256();
    ParameterList kmac_params {
        { MAC_PARAM_CUSTOM_STRING, Parameter::ref("PA4CODE") },
        { MAC_PARAM_DIGEST_LENGTH, Parameter::take(v4::AUTH_CODE_COMPONENT_LENGTH) },
    };
    
    // Reserve components
    std::vector<ByteArray> components;
    components.reserve(factor_keys.size());
    for (auto i = 0; i < factor_keys.size(); i++) {
        auto key_derived = kmac.token(factor_keys[0], counter, kmac_params);
        // ... compute authentication code key using more than one keys, at most 2 extra keys
        // ... this skips the key with index 0 when i == 0
        for (auto j = 0; j < i; j++) {
            auto key_derived_current = kmac.token(factor_keys[j + 1], counter, kmac_params);
            key_derived = kmac.token(key_derived_current, key_derived, kmac_params);
        }
        // ... sign the data
        components.push_back(kmac.token(key_derived, data, kmac_params));
    }
    return components;
}
cc7::ByteArray CalculateOnlineAuthorizationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                                const cc7::ByteRange& counter,
                                                const cc7::ByteRange& data)
{
    auto components = CalculateAuthorizationCodeComponents(factor_keys, counter, data);
    ByteArray auth_code;
    auth_code.reserve(components.size() * v4::AUTH_CODE_COMPONENT_LENGTH);
    for (const auto& c : components) {
        auth_code.append(c);
    }
    return auth_code;
}

std::string CalculateOfflineAuthorizationCode(const std::vector<cc7::ByteRange>& factor_keys,
                                              const cc7::ByteRange& counter,
                                              const cc7::ByteRange& data,
                                              size_t component_size)
{
    auto components = CalculateAuthorizationCodeComponents(factor_keys, counter, data);
    std::string result;
    result.reserve((component_size + 1)* components.size() - 1);
    for (const auto& c : components) {
        auto code = common::CalculateHumanReadableCodeFromHash(c, component_size);
        if (result.empty()) {
            result.assign(code);
        } else {
            result.append("-");
            result.append(code);
        }
    }
    return result;
}

} // namespace v4
} // namespace powerAuth
