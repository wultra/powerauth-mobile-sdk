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

#include "ProtocolUpgradeTask.h"
#include "../request/RequestBuilder.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_mutex)

ProtocolUpgradeTask::ProtocolUpgradeTask(const ContextPtr& context, const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek) :
    Task("ProtocolUpgradeTask", context),
    _session_data(context->getSessionDataPtr()),
    _password(password),
    _new_biometry_kek(new_biometry_kek),
    _confirmAttempts(3)
{
}

void ProtocolUpgradeTask::onTaskStart()
{
    Task::onTaskStart();
    // Fetch activation status to obtain the current state of the protocol upgrade.
    fetchActivationStatus();
}

void ProtocolUpgradeTask::onRequestSuccess(const Request &request)
{
    switch (request.getParentTaskTag()) {
        case START_UPGRADE:
            confirmProtocolUpgrade();
            break;
            
        case CONFIRM_UPGRADE:
            _session_data->persistentData().v4().flags.pendingProtocolUpgrade = 0;
            break;
            
        case FETCH_ACTIVATION_STATUS:
            processActivationStatus(*request.getTypedResponseObject<ActivationStatus>());
            break;
            
        default:
            throw Exception(EC_InternalError, "Unknown request tag in ProtocolUpgradeTask");
    }
}

void ProtocolUpgradeTask::onRequestFailure(const Request &request)
{
    switch (request.getParentTaskTag()) {
        case START_UPGRADE:
            /// Could not start the protocol upgrade.
            resetState();
            break;
        
        case CONFIRM_UPGRADE:
            /// Protocol upgrade confirm failed, either fetch the activation status to check if confirm is still needed.
            /// Or complete the task, if no attempts left.
            if (--_confirmAttempts > 0) {
                fetchActivationStatus(RF_IGNORE_FAILURE);
            }
            break;
    }
}

void ProtocolUpgradeTask::onTaskEnd()
{
    Task::onTaskEnd();
    resetState();
}

void ProtocolUpgradeTask::startProtocolUpgrade()
{
    LOCK_GUARD();
    auto current_context = lockContext();
    
    if (!_password) {
        throw Exception(EC_WrongParameter, "Password not present for the protocol upgrade.");
    }
    Credentials::validatePassword(*_password);
    if (_session_data->persistentData().hasBiometricFactorKey()) {
        Credentials::validateFactorKek(_new_biometry_kek, Version_V4);
    }
    
    auto new_ud = UpgradeData::create();
    _session_data->setUpgradeData(new_ud);
    
    auto upgrade_context = current_context->createTargetAlgorithmContext();
    
    auto self = std::dynamic_pointer_cast<ProtocolUpgradeTask>(Task::shared_from_this());
    auto request = RequestBuilder(*upgrade_context, v4::Endpoint_ProtocolUpgradeStart)
        .withJson(prepareRequestStartProtocolUpgrade(upgrade_context))
        .withResponseCallback([self](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            return self->processResponseStartProtocolUpgrade(body);
        })
        .withAuthenticator(current_context->getAuthenticationServicePtr())
        .withAuthentication(Credentials::knowledge(_password->passwordData()))
        .build();
    
    setNextRequest(request, START_UPGRADE, RF_PRIMARY);
}

cc7::json::JsonValue ProtocolUpgradeTask::prepareRequestStartProtocolUpgrade(const ContextPtr& upgrade_context)
{
    auto& ud = _session_data->upgradeData().v4();
    
    // Generate device public key-pairs
    ud.deviceKeyPair = upgrade_context->getSigningKeyPairFactoryPtr()->generateKeyPair();
    
    // Prepare shared secret
    SharedSecretRequest ss_request;
    std::tie(ss_request, ud.sharedSecretContext) = upgrade_context->sharedSecret().generateRequestCryptogram();
    ud.sharedSecretAlgorithm = upgrade_context->getSharedSecretPtr();
    
    return cc7::json::JsonValue::object({
        { "sharedSecretRequest", ss_request.toJson() },
        { "devicePublicKeys", v4::HybridKey_ToJson(ud.deviceKeyPair->getPublicKey(), upgrade_context->specification()) },
        { "enableBiometry", cc7::json::JsonValue(_session_data->persistentData().hasBiometricFactorKey()) }
    });
}

ProtocolUpgradeResultPtr ProtocolUpgradeTask::processResponseStartProtocolUpgrade(const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    auto current_context = lockContext();
    
    auto& ud = _session_data->upgradeData().v4();
    auto upgrade_context = current_context->getTargetAlgorithmContextPtr();
    
    // Extract public keys and calculate shared secret
    auto server_public_key = v4::HybridKey_FromJson(response["serverPublicKeys"], *upgrade_context->getSigningKeyPairFactoryPtr());
    auto shared_secret = ud.sharedSecretAlgorithm->computeSharedSecret(ud.sharedSecretContext, SharedSecretResponse::fromJson(response["sharedSecretResponse"]));
    auto ctr_data = response["ctrData"].asBase64();
    if (ctr_data.size() != v4::HASH_COUNTER_SIZE) {
        throw Exception(EC_InvalidData, "Invalid protocol upgrade data");
    }
    
    // Keep values in UD
    ud.authCodeCounterData      = ctr_data;
    ud.serverPublicKey          = server_public_key;
    ud.calculatedSharedSecret   = shared_secret;
    
    // Clear shared secret context and algorithm
    ud.sharedSecretContext = nullptr;
    ud.sharedSecretAlgorithm = nullptr;
    
    const auto credentials = _session_data->persistentData().hasBiometricFactorKey()
        ? *InitialCredentials::credentials(_password->passwordData(), _new_biometry_kek)
        : *InitialCredentials::credentials(_password->passwordData());
    
    auto& keyProvider = upgrade_context->keyProvider();
    auto secrets = keyProvider.unlockInitialSecretKeys(credentials, ud.calculatedSharedSecret);
    keyProvider.lockSecretKeys(secrets);
    
    if (!_session_data->hasPersistentData(Version_V4)) {
        throw Exception(EC_InternalError, "PersistentData V4 not created after lock");
    }
    
    // V4 persistent data were created, set flag protocol upgrade still pending.
    _session_data->persistentData().v4().flags.pendingProtocolUpgrade = 1;
    
    // Switch primary context to V4
    _session_data->resetUpgradeData();
    current_context->destroyTargetAlgorithmContext();
    current_context->updateAfterProtocolVersionChange();
    
    return ProtocolUpgradeResult::upgradeConfirmPending();
}

void ProtocolUpgradeTask::confirmProtocolUpgrade()
{
    LOCK_GUARD();
    auto context = lockContext();
    
    auto request = RequestBuilder(*context, v4::Endpoint_ProtocolUpgradeConfirm)
        .withResponseCallback([context](const Request& request, const cc7::json::JsonValue& body) -> ResponseObjectPtr {
            auto activation_fingerprint = context->activationService().calculateActivationFingerprint();
            return ProtocolUpgradeResult::upgradeConfirmed(activation_fingerprint);
        })
        .withAuthentication(Credentials::possession())
        .build();
    
    setNextRequest(request, CONFIRM_UPGRADE, RF_PRIMARY | RF_IGNORE_FAILURE);
}

void ProtocolUpgradeTask::fetchActivationStatus(RequestFlags flags)
{
    auto request = lockContext()->activationService().fetchActivationStatus();
    setNextRequest(request, FETCH_ACTIVATION_STATUS, flags);
}

void ProtocolUpgradeTask::processActivationStatus(const ActivationStatus &status)
{
    switch (_session_data->getCurrentProtocolVersion()) {
        case Version_V3:
            // SDK runs on V3, start the protocol upgrade, if available.
            if (status.isProtocolUpgradeAvailable()) {
                startProtocolUpgrade();
            }
            break;

        case Version_V4:
            // SDK runs on V4, confirm may still be necessary.
            if (status.protocolVersion() == Version_V4 && status.isPendingUpgradeConfirm()) {
                // Local protocol seems already upgraded, but server still awaits upgrade confirm.
                confirmProtocolUpgrade();
            }
            break;

        default:
            break;
    }
}

void ProtocolUpgradeTask::resetState()
{
    LOCK_GUARD();
    auto context = lockContext();
    
    _confirmAttempts = 3;
    _session_data->resetUpgradeData();
    context->destroyTargetAlgorithmContext();
}

} // namespace powerAuth
