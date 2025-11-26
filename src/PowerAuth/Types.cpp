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

#include <PowerAuth/Types.h>
#include <PowerAuth/Exception.h>
#include "model/Constants.h"

namespace powerAuth {

// MARK: - ProtocolVersion

const std::string& ProtocolVersion_GetHttpHeaderVersion(ProtocolVersion protocol_version)
{
    if (protocol_version == Version_NA) {
        protocol_version = Version_Latest;
    }
    switch (protocol_version) {
        case Version_V3: return v3::PA_VERSION_STRING;
        case Version_V4: return v4::PA_VERSION_STRING;
        default:
            throw Exception(EC_WrongParameter, "Unsupported protocol version");
    }
}

} // namespace powerAuth

