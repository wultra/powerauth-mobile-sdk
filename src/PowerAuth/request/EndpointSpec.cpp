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

#include "EndpointSpec.h"

namespace powerAuth {

namespace v4 {

const EndpointSpec Endpoint_SystemStatus {
    Version_V4, "/pa/v4/status", "", EncryptorId::NONE, EndpointSpec::FL_ALLOWED_IN_UPGRADE
};

const EndpointSpec Endpoint_TemporaryKey {
    Version_V4, "/pa/v4/keystore/create", "", EncryptorId::NONE
};

const EndpointSpec Endpoint_ActivationCreate {
    Version_V4, "/pa/v4/activation/create", "", EncryptorId::APPLICATION_SCOPE_GENERIC
};

const EndpointSpec Endpoint_ActivationConfirm {
    Version_V4, "/pa/v4/activation/confirm", "/pa/activation/confirm", EncryptorId::NONE, EndpointSpec::Flags::FL_PENDING_REGISTRATION
};

const EndpointSpec Endpoint_ActivationRemove {
    Version_V4, "/pa/v4/activation/remove", "/pa/activation/remove", EncryptorId::NONE
};

const EndpointSpec Endpoint_ActivationStatus {
    Version_V4, "/pa/v4/activation/status", "", EncryptorId::ACTIVATION_SCOPE_GENERIC, EndpointSpec::Flags::FL_PENDING_REGISTRATION // NOTE: V4 allows status during registration
};

const EndpointSpec Endpoint_PasswordChange {
    Version_V4, "/pa/v4/password/change", "/pa/password/change", EncryptorId::PASSWORD_CHANGE
};

const EndpointSpec Endpoint_BiometryAdd {
    Version_V4, "/pa/v4/biometry/add", "/pa/biometry/add", EncryptorId::BIOMETRY_ADD
};

const EndpointSpec Endpoint_BiometryRemove {
    Version_V4, "/pa/v4/biometry/remove", "/pa/biometry/remove", EncryptorId::NONE
};

const EndpointSpec Endpoint_VaultUnlock {
    
};

const EndpointSpec Endpoint_TokenCreate {
    Version_V4, "/pa/v4/token/create", "/pa/token/create", EncryptorId::CREATE_TOKEN
};

const EndpointSpec Endpoint_TokenRemove {
    Version_V4, "/pa/v4/token/remove", "/pa/token/remove", EncryptorId::NONE
};

const EndpointSpec Endpoint_ValidateCredentials {
    Version_V4, "/pa/v4/auth/validate", "/pa/auth/validate", EncryptorId::NONE
};

/// Authenticated with V3.3 authentication code
const EndpointSpec Endpoint_ProtocolUpgradeStart {
    Version_V4, "/pa/v4/upgrade/start", "/pa/upgrade/start", EncryptorId::UPGRADE_START,
    EndpointSpec::FL_ALLOWED_IN_UPGRADE | EndpointSpec::FL_SERIALIZED | EndpointSpec::FL_FORCE_ENCRYPTION_HEADER
};

const EndpointSpec Endpoint_ProtocolUpgradeConfirm {
    Version_V4, "/pa/v4/upgrade/confirm", "/pa/upgrade/confirm", EncryptorId::NONE,
    EndpointSpec::FL_ALLOWED_IN_UPGRADE | EndpointSpec::FL_SERIALIZED
};

const EndpointSpec Endpoint_UserInfo {
    Version_V4, "/pa/v4/user/info", "", EncryptorId::ACTIVATION_SCOPE_GENERIC
};

} // namespace v4

namespace v3 {

const EndpointSpec Endpoint_SystemStatus {
    Version_V3, "/pa/v3/status", "", EncryptorId::NONE, EndpointSpec::FL_ALLOWED_IN_UPGRADE
};

const EndpointSpec Endpoint_TemporaryKey {
    Version_V3, "/pa/v3/keystore/create", "", EncryptorId::NONE
};

const EndpointSpec Endpoint_ActivationCreate {
    Version_V3, "/pa/v3/activation/create", "", EncryptorId::APPLICATION_SCOPE_GENERIC
};

const EndpointSpec Endpoint_ActivationStatus {
    Version_V3, "/pa/v3/activation/status", "", EncryptorId::NONE
};

const EndpointSpec Endpoint_ActivationRemove {
    Version_V3, "/pa/v3/activation/remove", "/pa/activation/remove", EncryptorId::NONE
};

const EndpointSpec Endpoint_SignatureValidate {
    Version_V3, "/pa/v3/signature/validate", "/pa/signature/validate", EncryptorId::NONE
};

const EndpointSpec Endpoint_VaultUnlock {
    Version_V3, "/pa/v3/vault/unlock", "/pa/vault/unlock", EncryptorId::VAULT_UNLOCK
};

const EndpointSpec Endpoint_TokenCreate {
    Version_V3, "/pa/v3/token/create", "/pa/token/create", EncryptorId::CREATE_TOKEN
};

const EndpointSpec Endpoint_TokenRemove {
    Version_V3, "/pa/v3/token/remove", "/pa/token/remove", EncryptorId::NONE
};

const EndpointSpec Endpoint_UserInfo {
    Version_V3, "/pa/v3/user/info", "", EncryptorId::ACTIVATION_SCOPE_GENERIC
};

} // namespace v3

} // namespace powerAuth
