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

const EndpointSpec Endpoint_TemporaryKey {
    Version_V4, "/pa/v4/keystore/create", "POST", "", EncryptorId::NONE
};

const EndpointSpec Endpoint_ActivationStart {
    Version_V4, "", "POST", "", EncryptorId::ACTIVATION_LAYER_2
};

const EndpointSpec Endpoint_ActivationConfirm {
    
};

const EndpointSpec Endpoint_ActivationStatus {
    
};

const EndpointSpec Endpoint_PasswordChange {
    
};

const EndpointSpec Endpoint_BiometryOn {
    
};

const EndpointSpec Endpoint_BiometryOff {
    
};

const EndpointSpec Endpoint_VaultUnlock {
    
};

const EndpointSpec Endpoint_TokenCreate {
    
};

} // namespace v4

namespace v3 {

//extern const EndpointSpec Endpoint_RemoveActivation;
//extern const EndpointSpec Endpoint_ValidateSignature;

} // namespace v3

} // namespace powerAuth
