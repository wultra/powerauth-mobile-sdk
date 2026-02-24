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

GetActivationStatusTask::GetActivationStatusTask(const ContextPtr& context, const FetchActivationStatusData& data) :
    Task("GetActivationStatus", context),
    _session_data(context->getSessionDataPtr()),
    _activation_service(context->getActivationServicePtr()),
    _authentication_service(context->getAuthenticationServicePtr()),
    _fetch_data(data)
{
}

void GetActivationStatusTask::onTaskStart()
{
    Task::onTaskStart();
    fetchActivationStatus();
}

void GetActivationStatusTask::onRequestSuccess(const Request &request)
{
    switch (request.getParentTaskTag()) {
        case FETCH_STATUS:
            processActivationStatus(*request.getTypedResponseObject<ActivationStatus>());
            break;
        case PROTOCOL_UPGRADE_CONFIRM:
            lockContext()->sessionData().persistentData().v4().flags.pendingProtocolUpgrade = 0;
            setSessionStateSerializationRecommended();
            break;
        case SYNC_COUNTER:
            setCompleted();
            break;
        case REMOVE_BIOMETRIC_FACTOR:
            // Fetch status again after biometric factor remove.
            fetchActivationStatus();
            break;
        default:
            throw Exception(EC_InternalError, "Unknown request tag");
    }
}

void GetActivationStatusTask::onRequestFailure(const Request &request)
{
    if (request.getParentTaskTag() == SYNC_COUNTER) {
        // Failure in this requests are ignored. We can set the request as completed.
        // The previously captured status is preserved and reported as the final result of the task.
        setCompleted();
    }
}

void GetActivationStatusTask::processActivationStatus(ActivationStatus &status)
{
    if (status.protocolVersion() == Version_V4) {
        if (status.isPendingUpgradeConfirm()) {
            // Protocol upgrade is not confirmed yet.
            confirmProtocolUpgrade();
            return;
        }
        
        auto context = lockContext();
        if (context->hasProtocolUpgradePending()) {
            // Protocol upgrade confirmed, but locally the flag is still set.
            context->sessionData().persistentData().v4().flags.pendingProtocolUpgrade = 0;
            setSessionStateSerializationRecommended();
        }
        
        // Handle biometric factor. This is allowed only when the activation is properly created.
        if (status.biometricFactor() != ActivationStatus::BiometricFactor_NA &&
            !status.isPendingActivationConfirm() &&
            _session_data->hasPersistentData()) {
            // Status of biometry on the server is different than the local status.
            auto serverBioON = status.biometricFactor() == ActivationStatus::BiometricFactor_On;
            auto localBioON = _fetch_data.biometricKekAvailable && _session_data->persistentData().hasBiometricFactorKey();
            if (serverBioON != localBioON) {
                // Local and server's biometric state is different
                if (serverBioON) {
                    // remove biometric factor on the server. This operation also synchronize the counters.
                    removeBiometricFactor();
                    return;
                } else {
                    // remove biometric factor locally
                    _activation_service->cleanupBiometricFactorData();
                    status.setRemoveBiometricKekRecommended();
                    setSessionStateSerializationRecommended();
                }
            }
        }
    }
    
    if (status.isCounterSynchronizationRecommended()) {
        // Seems that local counter is too ahead against the server. It's recommended to calculate
        // dummy possession signature to allow server's counter to catch-up with the client.
        synchronizeCounters();
    } else {
        setCompleted();
    }
}

void GetActivationStatusTask::fetchActivationStatus()
{
    setNextRequest(_activation_service->fetchActivationStatus(), FETCH_STATUS, RF_PRIMARY);
}

void GetActivationStatusTask::confirmProtocolUpgrade()
{
    auto context = lockContext();
    
    auto request = RequestBuilder(*context, v4::Endpoint_ProtocolUpgradeConfirm)
        .withAuthentication(Credentials::possession())
        .build();
    
    setNextRequest(request, PROTOCOL_UPGRADE_CONFIRM, RF_NONE);
}

void GetActivationStatusTask::removeBiometricFactor()
{
    auto request = _activation_service->removeBiometricFactor();
    // If this request fails, then the whole operation fails. This basically instructs the application
    // to retry the status fetch operation.
    setNextRequest(request, REMOVE_BIOMETRIC_FACTOR, RF_NONE);
}

void GetActivationStatusTask::synchronizeCounters()
{
    auto request = _authentication_service->verifyCredentialsWithReason(Credentials::possession(), VerifyCredentialsReason::COUNTER_SYNCHRONIZATION);
    // Failure is not important, we'll try later in the next getting status task.
    setNextRequest(request, SYNC_COUNTER, RF_IGNORE_FAILURE);
}

} // namespace powerAuth
