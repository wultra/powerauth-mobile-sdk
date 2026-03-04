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
#include <PowerAuth/ProtocolUpgradeResult.h>
#include "../Context.h"

namespace powerAuth {

class ProtocolUpgradeTask : public Task
{
public:
    ProtocolUpgradeTask(const ContextPtr& context, const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek);
    
protected:
    void onTaskStart() override;
    void onRequestSuccess(const Request &request) override;
    void onRequestFailure(const Request &request) override;
    void onTaskEnd() override;
    
    enum RequestId
    {
        START_UPGRADE,
        CONFIRM_UPGRADE,
        FETCH_ACTIVATION_STATUS
    };
    
private:
    
    /// Prepare upgrade context and send the start protocol upgrade request to the server.
    void startProtocolUpgrade();
    /// Build the request body for the start protocol upgrade request.
    cc7::json::JsonValue prepareRequestStartProtocolUpgrade(const ContextPtr& upgrade_context);
    /// Process the start protocol upgrade response.
    /// On success, switch the protocol version to V4.
    ProtocolUpgradeResultPtr processResponseStartProtocolUpgrade(const cc7::json::JsonValue& response);
    
    /// Send the confirm protocol upgrade request to the server.
    void confirmProtocolUpgrade();
    
    /// Fetch activation status.
    void fetchActivationStatus(RequestFlags flags = RF_NONE);
    /// Process activation status. The main purpose is to check the protocol version registered
    /// on the server's side or to check if the confirm protocol upgrade request is still awaited.
    void processActivationStatus(const ActivationStatus& status);
    
    /// Reset the upgrade procedure.
    void resetState();
    
    /// Number of attempts to confirm the protocol upgrade.
    int _confirmAttempts;
    
    const SessionDataPtr _session_data;
    
    const PasswordPtr _password;
    const cc7::ByteArray _new_biometry_kek;
};

} // namespace powerAuth
