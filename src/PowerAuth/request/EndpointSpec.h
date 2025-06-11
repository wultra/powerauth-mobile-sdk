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

struct EndpointSpec
{
    enum Flags
    {
        FL_SERIALIZED           = 1 << 0,
        FL_ALLOWED_IN_UPGRADE   = 1 << 1,
        FL_SYNCHRONIZE_TIME     = 1 << 2
    };
    ProtocolVersion version;
    std::string localPath;
    std::string method;
    std::string uriId;
    EncryptorId encryptorId;
    cc7::U32 flags;
};

namespace v4 {

extern const EndpointSpec Endpoint_TemporaryKey;
extern const EndpointSpec Endpoint_ActivationStart;
extern const EndpointSpec Endpoint_ActivationConfirm;
extern const EndpointSpec Endpoint_ActivationStatus;
extern const EndpointSpec Endpoint_PasswordChange;
extern const EndpointSpec Endpoint_BiometryOn;
extern const EndpointSpec Endpoint_BiometryOff;
extern const EndpointSpec Endpoint_VaultUnlock;
extern const EndpointSpec Endpoint_TokenCreate;

} // namespace v4

namespace v3 {

//extern const EndpointSpec Endpoint_RemoveActivation;
//extern const EndpointSpec Endpoint_ValidateSignature;

} // namespace v3

} // namespace powerAuth
