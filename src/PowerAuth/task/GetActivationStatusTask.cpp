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

#include "GetActivationStatusTask.h"
#include "../request/RequestBuilder.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex)

GetActivationStatusTask::GetActivationStatusTask(const ContextPtr& context) :
    Task("GetActivationStatus", context),
    _activation_service(context->getActivationServicePtr()),
    _authentication_service(context->getAuthenticationServicePtr())
{
}

void GetActivationStatusTask::onTaskStart()
{
    Task::onTaskStart();
    setNextRequest(_activation_service->fetchActivationStatus(), FETCH_STATUS, RF_PRIMARY);
}

void GetActivationStatusTask::onRequestSuccess(const Request &request)
{
    switch (request.getParentTaskTag()) {
        case FETCH_STATUS:
            processActivationStatus(*request.getTypedResponseObject<ActivationStatus>());
            break;
        case PROTOCOL_UPGRADE_CONFIRM:
            lockContext()->sessionData().persistentData().v4().flags.pendingProtocolUpgrade = 0;
            break;
        case SYNC_COUNTER:
            setCompleted();
            break;
        default:
            throw Exception(EC_InternalError, "Unknown request tag");
    }
}

void GetActivationStatusTask::onRequestFailure(const Request &request)
{
    if (request.getParentTaskTag() == SYNC_COUNTER) {
        // Failure in this request is ignored. We can set the request as completed.
        // The previously captured status is preserved and reported as the final result of the task.
        setCompleted();
    }
}

void GetActivationStatusTask::processActivationStatus(const ActivationStatus &status)
{
    if (status.protocolVersion() == Version_V4) {
        auto context = lockContext();
        if (status.isPendingUpgradeConfirm()) {
            // Protocol upgrade is not confirmed yet.
            confirmProtocolUpgrade();
        } else if (context->hasProtocolUpgradePending()) {
            // Protocol upgrade confirmed, but locally the flag is still set.
            context->sessionData().persistentData().v4().flags.pendingProtocolUpgrade = 0;
        }
    } else if (status.isCounterSynchronizationRecommended()) {
        // Seems that local counter is too ahead against the server. It's recommended to calculate
        // dummy possession signature to allow server's counter to catch-up with the client.
        auto request = _authentication_service->verifyCredentialsWithReason(Credentials::possession(), VerifyCredentialsReason::COUNTER_SYNCHRONIZATION);
        setNextRequest(request, SYNC_COUNTER, RF_IGNORE_FAILURE);
    } else {
        setCompleted();
    }
}

void GetActivationStatusTask::confirmProtocolUpgrade()
{
    LOCK_GUARD();
    auto context = lockContext();
    
    auto request = RequestBuilder(*context, v4::Endpoint_ProtocolUpgradeConfirm)
        .withAuthentication(Credentials::possession())
        .build();
    
    setNextRequest(request, PROTOCOL_UPGRADE_CONFIRM, RF_NONE);
}

} // namespace powerAuth
