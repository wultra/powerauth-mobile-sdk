/*
 * Copyright 2021 Wultra s.r.o.
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

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
    // Power Auth version string
    const std::string   PA_VERSION_V2("2.1");
    const std::string   PA_VERSION_V3("3.1");
    
    // PA HTTP Auth header.
    const std::string   PA_AUTH_HEADER_NAME                 ("X-PowerAuth-Authorization");
    
    // Other header fragments
    const std::string   PA_AUTH_FRAGMENT_BEGIN_VERSION      ("PowerAuth pa_version=\"");
    const std::string   PA_AUTH_FRAGMENT_ACTIVATION_ID      ("\", pa_activation_id=\"");
    const std::string   PA_AUTH_FRAGMENT_APPLICATION_KEY    ("\", pa_application_key=\"");
    const std::string   PA_AUTH_FRAGMENT_NONCE              ("\", pa_nonce=\"");
    const std::string   PA_AUTH_FRAGMENT_SIGNATURE_TYPE     ("\", pa_signature_type=\"");
    const std::string   PA_AUTH_FRAGMENT_SIGNATURE          ("\", pa_signature=\"");
    const std::string   PA_AUTH_FRAGMENT_END                ("\"");
    const size_t        PA_AUTH_FRAGMENTS_LENGTH =
                            PA_AUTH_FRAGMENT_BEGIN_VERSION.length() +
                            PA_AUTH_FRAGMENT_ACTIVATION_ID.length() +
                            PA_AUTH_FRAGMENT_APPLICATION_KEY.length() +
                            PA_AUTH_FRAGMENT_NONCE.length() +
                            PA_AUTH_FRAGMENT_SIGNATURE_TYPE.length() +
                            PA_AUTH_FRAGMENT_SIGNATURE.length() +
                            PA_AUTH_FRAGMENT_END.length();
    
    // App secret & key for offline signatures
    const std::string   PA_OFFLINE_APP_SECRET("offline");

    // Ampersand
    const std::string   AMP("&");
    const std::string   DASH("-");

    // Empty IV
    const cc7::ByteArray ZERO_IV(16, 0);
    
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io

