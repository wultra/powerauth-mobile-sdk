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

#include "Constants.h"

namespace powerAuth {

// MARK: - Common
namespace common {
    // Encryption header name
    const std::string PA_ENCRYPTION_HEADER_NAME("X-PowerAuth-Encryption");

    // Authentication header name
    const std::string PA_AUTHENTICATION_HEADER_NAME("X-PowerAuth-Authorization");

    // Token header name
    const std::string PA_TOKEN_HEADER_NAME("X-PowerAuth-Token");

    // App secret & key for offline signatures
    const std::string PA_OFFLINE_APP_SECRET("offline");

    // Empty IV (16 bytes filled with 0)
    const cc7::ByteArray ZERO16_IV(16, 0);

    // Various constant strings
    const std::string AMP("&");
    const std::string DASH("-");

} // namespace common



// MARK: - Protocol V4
namespace v4 {
    // PA version string for protocol V4
    const std::string PA_VERSION_STRING("4.0");


} // namespace v4




// MARK: - Protocol V3
namespace v3 {
    // PA version string for protocol V3
    const std::string PA_VERSION_STRING("3.3");

} // namespace v3

} // namespace powerAuth
