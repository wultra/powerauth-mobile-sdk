/*
 * Copyright 2026 Wultra s.r.o.
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

#include "ConfirmActivationTask.h"

namespace powerAuth {

ConfirmActivationTask::ConfirmActivationTask(const ContextPtr& context, const InitialCredentialsPtr& credentials) :
    Task("ConfirmActivation", context),
    _credentials(credentials),
    _session_data(context->getSessionDataPtr()),
    _activation_service(context->getActivationServicePtr()),
    _retry_count(2)
{
}

void ConfirmActivationTask::onTaskStart()
{
    Task::onTaskStart();
    if (_session_data->getCurrentProtocolVersion() < Version_V4) {
        throw Exception(EC_InternalError, "Confirm task is not supported in V3");
    }
    if (!_session_data->hasRegistrationData()) {
        throw Exception(EC_InternalError, "There's no pending registration to confirm");
    }
    if (_session_data->registrationData().v4().lastConfirmFailed) {
        // If previous confirm failed, then we have to start with status fetch
        fetchActivationStatus();
    } else {
        // Otherwise start with regular confirm
        confirmActivation(false);
    }
}

void ConfirmActivationTask::onRequestSuccess(const Request &request)
{
    // lock already acquired
    switch (request.getParentTaskTag()) {
        case CONFIRM_ACTIVATION:
            setCompleted(true);
            break;
        case FETCH_STATUS:
            processActivationStatus(*request.getTypedResponseObject<ActivationStatus>());
            break;
        default:
            throw Exception(EC_InternalError, "Unknown request tag");
    }
}

void ConfirmActivationTask::onRequestFailure(const Request &request)
{
    // lock already acquired
    switch (request.getParentTaskTag()) {
        case CONFIRM_ACTIVATION:
            _session_data->registrationData().v4().lastConfirmFailed = true;
            fetchActivationStatus();
            break;
        case FETCH_STATUS:
            setCompleted();
            break;
        default:
            throw Exception(EC_InternalError, "Unknown request tag");
    }
}

// Private

void ConfirmActivationTask::processActivationStatus(const ActivationStatus &status)
{
    // lock must be guaranteed
    auto state = status.activationState();
    if ((state != ActivationState::Active && state != ActivationState::PendingCommit)) {
        // Activation is in a complete wrong state. Only "ACTIVE" and "PENDING_COMMIT" states
        // are accepted at this point.
        throw Exception(EC_WrongActivationState, "Activation on the server is in wrong state");
    }
    if (status.isPendingActivationConfirm()) {
        // seems that confirm request did not reach the server, try to retry.
        confirmActivation(true);
    } else {
        // There's no longer pending confirm, so set the task as successfully completed.
        setCompleted(true);
    }
}

void ConfirmActivationTask::confirmActivation(bool retry)
{
    // lock must be acquired
    if (retry) {
        if (_retry_count-- == 0) {
            throw Exception(EC_Other, "Failed to confirm activation after several attempts");
        }
    }
    setNextRequest(_activation_service->confirmActivation(_credentials),
                   CONFIRM_ACTIVATION,
                   RF_PRIMARY | RF_IGNORE_FAILURE);
}

void ConfirmActivationTask::fetchActivationStatus()
{
    // lock must be acquired
    setNextRequest(_activation_service->fetchActivationStatus(),
                   FETCH_STATUS,
                   RF_NONE);
}

} // namespace powerAuth
