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
        /// If set, then the request must be processed in serialized queue.
        FL_SERIALIZED               = 1 << 0,
        /// If set, then request is allowed while protocol upgrade is pending.
        FL_ALLOWED_IN_UPGRADE       = 1 << 1,
        /// If set, then request require synchronized time.
        FL_SYNCHRONIZE_TIME         = 1 << 2,
        /// If set, then the request and response objects are not wrapped in standard RESTFul API objects.
        FL_NOT_WRAPPED              = 1 << 3,
        /// If set, then request is allowed while registration is pending.
        FL_PENDING_REGISTRATION     = 1 << 4,
        /// If set, then encryption header is enforced in request.
        FL_FORCE_ENCRYPTION_HEADER  = 1 << 5,
        /// If set, then response JSON is marshaled to managed environments, such as Java or Objective-C.
        FL_PUBLIC_RESPONSE_JSON     = 1 << 6
    };
    
    ProtocolVersion version;
    std::string relativePath;
    std::string uriId;
    EncryptorId encryptorId;
    cc7::U32 flags = 0;
    std::string method = "POST";
    
    bool isEncrypted() const noexcept
    {
        return encryptorId != EncryptorId::NONE;
    }
    
    bool isAuthenticated() const noexcept
    {
        return !uriId.empty();
    }
    
    bool requireSerialQueue() const noexcept
    {
        return isAuthenticated() || (flags & FL_SERIALIZED) == FL_SERIALIZED;
    }
    
    bool isAllowedInUpgrade() const noexcept
    {
        return (flags & FL_ALLOWED_IN_UPGRADE) == FL_ALLOWED_IN_UPGRADE;
    }
    
    bool isAllowedInPendingRegistration() const noexcept
    {
        return (flags & FL_PENDING_REGISTRATION) == FL_PENDING_REGISTRATION;
    }
    
    bool isPublicResponseJson() const noexcept
    {
        return (flags & FL_PUBLIC_RESPONSE_JSON) == FL_PUBLIC_RESPONSE_JSON;
    }
    
    bool requireSynchronizedTime() const noexcept
    {
        return (flags & FL_SYNCHRONIZE_TIME) == FL_SYNCHRONIZE_TIME;
    }
    
    bool requireWrappedRequestResponse() const noexcept
    {
        return !isEncrypted() && (flags & FL_NOT_WRAPPED) == 0;
    }
    
    bool forceEncryptionHeader() const noexcept
    {
        return (flags & FL_FORCE_ENCRYPTION_HEADER) == FL_FORCE_ENCRYPTION_HEADER;
    }
};

namespace v4 {

extern const EndpointSpec Endpoint_SystemStatus;
extern const EndpointSpec Endpoint_TemporaryKey;
extern const EndpointSpec Endpoint_ActivationCreate;
extern const EndpointSpec Endpoint_ActivationConfirm;
extern const EndpointSpec Endpoint_ActivationStatus;
extern const EndpointSpec Endpoint_ActivationRemove;
extern const EndpointSpec Endpoint_PasswordChange;
extern const EndpointSpec Endpoint_BiometryAdd;
extern const EndpointSpec Endpoint_BiometryRemove;
extern const EndpointSpec Endpoint_VaultUnlock;
extern const EndpointSpec Endpoint_TokenCreate;
extern const EndpointSpec Endpoint_TokenRemove;
extern const EndpointSpec Endpoint_ValidateCredentials;
extern const EndpointSpec Endpoint_ProtocolUpgradeStart;
extern const EndpointSpec Endpoint_ProtocolUpgradeConfirm;
extern const EndpointSpec Endpoint_UserInfo;

} // namespace v4

namespace v3 {

extern const EndpointSpec Endpoint_SystemStatus;
extern const EndpointSpec Endpoint_TemporaryKey;
extern const EndpointSpec Endpoint_ActivationCreate;
extern const EndpointSpec Endpoint_ActivationStatus;
extern const EndpointSpec Endpoint_ActivationRemove;
extern const EndpointSpec Endpoint_SignatureValidate;
extern const EndpointSpec Endpoint_VaultUnlock;
extern const EndpointSpec Endpoint_TokenCreate;
extern const EndpointSpec Endpoint_TokenRemove;
extern const EndpointSpec Endpoint_UserInfo;

} // namespace v3

} // namespace powerAuth
