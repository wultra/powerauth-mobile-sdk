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

#include <PowerAuth/Request.h>

namespace powerAuth {

/**
 * Object representing result of the `ProtocolUpgradeTask`.
 */
class ProtocolUpgradeResult : public ResponseObject
{
public:
    
    /**
     * Constructs ProtocolUpgradeResult instance.
     * @param is_pending_upgrade_confirm True if the upgrade confirm is pending, false if confirmed.
     */
    ProtocolUpgradeResult(bool is_pending_upgrade_confirm);
    
    /**
     * Creates a `ProtocolUpgradeResult` indicating that the upgrade confirm is pending.
     */
    static std::shared_ptr<ProtocolUpgradeResult> UpgradeConfirmPending();
    /**
     * Creates a `ProtocolUpgradeResult` indicating that the upgrade has been confirmed.
     */
    static std::shared_ptr<ProtocolUpgradeResult> UpgradeConfirmed();
    
    /**
     * True if the upgrade confirmation is pending, false otherwise.
     */
    bool isPendingUpgradeConfirm() const noexcept;
    
private:
    
    // Indicates whether the protocol upgrade confirm is pending.
    const bool _is_pending_upgrade_confirm;
    
};

CC7_SHARED_PTR(ProtocolUpgradeResult);

} // namespace powerAuth
