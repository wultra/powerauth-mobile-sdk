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
    _new_biometry_kek(new_biometry_kek)
{
}

void ProtocolUpgradeTask::onTaskStart()
{
    Task::onTaskStart();
    
    switch (_session_data->getCurrentProtocolVersion()) {
        case Version_V3:
            startProtocolUpgrade();
            break;
            
        case Version_V4:
            /// Local activation is alredy on V4, check the server state and send the confirm request if expected.
            fetchActivationStatus();
            break;
            
        default:
            break;
    }
}

void ProtocolUpgradeTask::onRequestSuccess(const Request &request)
{
    switch (request.getParentTaskTag()) {
        case START_UPGRADE:
            processResponseStartProtocolUpgrade(request.getResponseJson());
            confirmProtocolUpgrade();
            break;
            
        case CONFIRM_UPGRADE:
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
            resetState();
            break;
        
        case CONFIRM_UPGRADE:
            fetchActivationStatus();
            break;
            
        case FETCH_ACTIVATION_STATUS:
            setCompleted();
            break;
    }
}

void ProtocolUpgradeTask::startProtocolUpgrade()
{
    LOCK_GUARD();
    auto current_context = lockContext();
    
    auto &pd = _session_data->persistentData().v3();
    pd.flags.pendingUpgradeVersion = Version_V4;
    
    auto new_ud = UpgradeData::create();
    _session_data->setUpgradeData(new_ud);
    
    auto upgrade_context = Context::getTargetAlgorithmInstance(current_context);
    _session_data->upgradeData().v4().context = upgrade_context;
    
    auto request = RequestBuilder(*upgrade_context, v4::Endpoint_ProtocolUpgradeStart)
        .withJson(prepareRequestStartProtocolUpgrade())
        .withAuthenticator(current_context->getAuthenticationServicePtr())
        .withAuthentication(Credentials::knowledge(_password->passwordData()))
        .build();
    
    setNextRequest(request, START_UPGRADE, RF_PRIMARY);
}

cc7::json::JsonValue ProtocolUpgradeTask::prepareRequestStartProtocolUpgrade()
{
    auto& ud = _session_data->upgradeData().v4();
    
    // Generate device public key-pairs
    ud.deviceKeyPair = ud.context->getSigningKeyPairFactoryPtr()->generateKeyPair();
    
    // Prepare shared secret
    SharedSecretRequest ss_request;
    std::tie(ss_request, ud.sharedSecretContext) = ud.context->sharedSecret().generateRequestCryptogram();
    ud.sharedSecretAlgorithm = ud.context->getSharedSecretPtr();
    
    return cc7::json::JsonValue::object({
        { "sharedSecretRequest", ss_request.toJson() },
        { "devicePublicKeys", v4::HybridKey_ToJson(ud.deviceKeyPair->getPublicKey(), ud.context->specification()) },
        { "enableBiometry", cc7::json::JsonValue(_session_data->persistentData().hasBiometricFactorKey()) }
    });
}

void ProtocolUpgradeTask::processResponseStartProtocolUpgrade(const cc7::json::JsonValue& response)
{
    LOCK_GUARD();
    auto& ud = _session_data->upgradeData().v4();
    auto upgrade_context = ud.context;
    
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
    
    auto& keyProvider = upgrade_context->keyProvider();
    auto secrets = keyProvider.unlockInitialSecretKeys(*InitialCredentials::credentials(_password->passwordData(), _new_biometry_kek), ud.calculatedSharedSecret);
    keyProvider.lockSecretKeys(secrets);
    
    if (!_session_data->hasPersistentData(Version_V4)) {
        throw Exception(EC_InternalError, "PersistentData V4 not created after lock");
    }
    
    // Switch primary context to V4
    upgrade_context->destroyServices();
    lockContext()->updateAfterProtocolVersionChange();
}

void ProtocolUpgradeTask::confirmProtocolUpgrade()
{
    LOCK_GUARD();
    auto context = lockContext();
    
    auto request = RequestBuilder(*context, v4::Endpoint_ProtocolUpgradeConfirm)
        .withAuthentication(Credentials::possession())
        .build();
    
    setNextRequest(request, CONFIRM_UPGRADE, RF_IGNORE_FAILURE);
}

void ProtocolUpgradeTask::fetchActivationStatus()
{
    auto request = lockContext()->activationService().fetchActivationStatus();
    setNextRequest(request, FETCH_ACTIVATION_STATUS, RF_IGNORE_FAILURE);
}

void ProtocolUpgradeTask::processActivationStatus(const ActivationStatus &status)
{
    if (status.protocolVersion() == Version_V4 && status.isPendingUpgradeConfirm()) {
        // Local protocol seems already upgraded, but server still awaits upgrade confirm.
        confirmProtocolUpgrade();
    }
}

void ProtocolUpgradeTask::resetState()
{
    LOCK_GUARD();
    auto context = lockContext();
    
    auto &pd = _session_data->persistentData().v3();
    pd.flags.pendingUpgradeVersion = Version_V4;
    
    auto &ud = _session_data->upgradeData().v4();
    ud.context->destroyServices();
    _session_data->resetUpgradeData();
}

} // namespace powerAuth
