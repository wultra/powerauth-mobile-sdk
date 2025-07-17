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

#include <PowerAuth/ActivationService.h>
#include "../model/SessionData.h"
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class ActivationServiceV4 :
    public Service,
    public IActivationService,
    public std::enable_shared_from_this<ActivationServiceV4>
{
public:
    ActivationServiceV4(const ContextPtr& context);
    
    ProtocolVersion protocolVersion() const noexcept override;
    IServicePtr asService() override;
    RequestPtr createActivation(cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data) override;
    RequestPtr confirmActivation(InitialCredentialsPtr credentials) override;
    
    void resetState() override;
    RequestPtr fetchActivationStatus() override;
    RequestPtr removeActivation(CredentialsPtr credentials) override;
    
    RequestPtr changePassword(PasswordPtr old_password, PasswordPtr new_password) override;
    RequestPtr addBiometricFactor(PasswordPtr password) override;
    RequestPtr removeBiometricFactor() override;
    
private:
    
    // Create
    ResponseObjectPtr processResponseActivationData(Context& context, const cc7::json::JsonValue& L1_data);
    cc7::json::JsonValue prepareRequestActivationData(Context& context, cc7::json::JsonValue L1_data, cc7::json::JsonValue L2_data);
    ResponseObjectPtr processResponseActivationConfirm(Context& context, InitialCredentialsPtr credentials);
    
    ContextPtr lockContext();
    
    ContextWeakPtr _weak_context;
    SessionDataPtr _session_data;
};

} // namespace v4
} // namespace powerAuth

