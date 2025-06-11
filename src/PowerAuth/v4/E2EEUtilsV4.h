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

#include <PowerAuth/Encryptor.h>

namespace powerAuth {
namespace v4 {

extern cc7::ByteArray E2EE_BuildAssociatedData(const EncryptorParameters& parameters) noexcept;
extern HttpHeader E2EE_BuildRequestHeader(const EncryptorParameters& parameters) noexcept;

extern EncryptorSecretsPtr E2EE_ApplicationScopeSecrets(const cc7::ByteRange& envelope_key,
                                                        const cc7::ByteRange& application_secret);

extern EncryptorSecretsPtr E2EE_ActivationScopeSecrets(const cc7::ByteRange& envelope_key,
                                                       const cc7::ByteRange& application_secret,
                                                       const cc7::ByteRange& e2ee_shared_info2_key);

extern std::map<std::string, std::string> E2EE_ParseHeaders(const std::string & header_value);

} // namespace v4
} // namespace powerAuth
