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

#include <PowerAuth/Task.h>
#include "../Context.h"

namespace powerAuth {

class GetActivationStatusTask : public Task
{
public:
    GetActivationStatusTask(const ContextPtr& context);
    
protected:
    void onTaskStart() override;
    void onRequestSuccess(const Request &request) override;
    void onRequestFailure(const Request &request) override;
    
    enum RequestId
    {
        FETCH_STATUS = 1,
        SYNC_COUNTER,
        CONFIRM_UPGRADE
    };
    
private:
    
    /// Process activation status received from the server.
    /// - Parameter status: Received status.
    void processActivationStatus(const ActivationStatus& status);
    
    /// Create the confirm protocol upgrade request.
    RequestPtr prepareRequestConfirmProtocolUpgrade();
    
    IActivationServicePtr _activation_service;
    IAuthenticationServicePtr _authentication_service;
};

} // namespace powerAuth
