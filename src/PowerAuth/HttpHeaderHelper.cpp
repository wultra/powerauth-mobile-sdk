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

#include "HttpHeaderHelper.h"
#include "model/Constants.h"

namespace powerAuth {

HttpHeader HttpHeaderHelper::buildEncryptionRequestHeader(const EncryptorParameters& parameters) noexcept
{
    std::string value;
    value.reserve(60 + parameters.protocolVersion.size() + parameters.applicationKey.size() + parameters.activationIdentifier.size());
    value = "PowerAuth version=\"";
    value += parameters.protocolVersion;
    value += "\", application_key=\"";
    value += parameters.applicationKey;
    if (!parameters.activationIdentifier.empty()) {
        value += "\", activation_id=\"";
        value += parameters.activationIdentifier;
    }
    value += "\"";
    return { common::PA_ENCRYPTION_HEADER_NAME, value };
}

} // namespace powerAuth
