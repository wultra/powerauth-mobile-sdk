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

#include <PowerAuth/Session.h>
#include "task/ConfirmActivationTask.h"
#include "task/GetActivationStatusTask.h"
#include "task/ProtocolUpgradeTask.h"
// EEK
#include "v3/LegacyUKE.h"

namespace powerAuth {

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

Session::Session(ContextPtr context) :
    _lock(context->getSharedMutexPtr()),
    _context(context)
{
}

SessionPtr Session::createInstance(ConfigurationPtr configuration)
{
    auto context = Context::getInstance(configuration);
    return std::make_shared<Session>(context);
}

// MARK: - State

ProtocolVersion Session::getProtocolVersion() const noexcept
{
    LOCK_GUARD();
    return _context->protocolVersion();
}

ConstPowerAuthSpecPtr Session::getPowerAuthSpec() const noexcept
{
    LOCK_GUARD();
    return _context->specification();
}

const ConfigurationPtr& Session::getConfiguration() const noexcept
{
    // Configuration is immutable, we don't need to acquire lock.
    return _context->getConfigurationPtr();
}

SessionData& Session::sessionData() noexcept
{
    return _context->sessionData();
}

const SessionData& Session::sessionData() const noexcept
{
    return _context->sessionData();
}


// MARK: - State serialization

bool Session::isModifiedState() const noexcept
{
    LOCK_GUARD();
    return sessionData().isModified();
}

void Session::loadState(const cc7::ByteRange &serialized_state)
{
    LOCK_GUARD();
    auto& sd = sessionData();
    auto spec_before = sd.getCurrentSpecification();
    sd.deserialize(serialized_state);
    if (spec_before != sd.getCurrentSpecification()) {
        _context->updateAfterProtocolVersionChange();
    }
    _context->restoreSensitiveData();
}

cc7::ByteArray Session::saveState()
{
    LOCK_GUARD();
    return sessionData().serialize();
}

void Session::resetState()
{
    LOCK_GUARD();
    _context->resetState();
}


// MARK: - Activation

bool Session::canCreateActivation() const noexcept
{
    LOCK_GUARD();
    const auto& sd = sessionData();
    return !sd.hasRegistrationData() && !sd.hasPersistentData();
}

bool Session::hasPendingCreateActivation() const noexcept
{
    LOCK_GUARD();
    return sessionData().hasRegistrationData();
}

RequestPtr Session::createActivation(const cc7::json::JsonValue& L1_data, const cc7::json::JsonValue& L2_data)
{
    LOCK_GUARD();
    if (!canCreateActivation()) {
        throw Exception(EC_WrongActivationState, "Cannot create activation");
    }
    return _context->activationService().createActivation(L1_data, L2_data);
}

TaskPtr Session::confirmActivation(const InitialCredentialsPtr& credentials)
{
    LOCK_GUARD();
    // Validate credentials in advance. This is typically done also in key provider,
    // but we don't want to wait for the response from the server.
    credentials->validate(_context->protocolVersion());
    auto& sd = sessionData();
    if (!sd.hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. There's no pending activation");
    }
    auto& rd = sd.registrationData();
    if (rd.getActivationId().empty()) {
        throw Exception(EC_WrongActivationState, "Cannot confirm activation. Key-exchange is not completed yet");
    }
    if (_context->protocolVersion() < Version_V4) {
        // V3 doesn't require HTTP communication for activation confirm
        _context->activationService().confirmActivation(credentials);
        return nullptr;
    }
    // V4+ uses ConfirmActivationTask
    return std::make_shared<ConfirmActivationTask>(_context, credentials);
}

bool Session::hasValidActivationData() const noexcept
{
    LOCK_GUARD();
    return sessionData().hasPersistentData();
}

bool Session::hasProtocolUpgradeAvailable() const noexcept
{
    LOCK_GUARD();
    auto last_activation_status = _context->sessionData().getActivationStatusPtr();
    return last_activation_status
        && last_activation_status->isProtocolUpgradeAvailable()
        && last_activation_status->isProtocolUpgradePossible(getProtocolVersion(), sessionData().getTargetSpecification()->protocolVersion());
}

bool Session::hasPendingProtocolUpgrade() const noexcept
{
    LOCK_GUARD();
    return _context->hasProtocolUpgradePending();
}

std::string Session::activationId() const noexcept
{
    LOCK_GUARD();
    try {
        return sessionData().getActivationId();
    } catch (...) {
        return std::string();
    }
}

std::string Session::activationFingerprint() const noexcept
{
    LOCK_GUARD();
    try {
        const auto& sd = sessionData();
        if (sd.hasPersistentData() || sd.hasRegistrationData()) {
            return _context->activationService().calculateActivationFingerprint();
        }
    } catch (...) {
        // do nothing...
    }
    return std::string();
}

TaskPtr Session::fetchActivationStatus()
{
    LOCK_GUARD();
    checkActivationData();
    return std::make_shared<GetActivationStatusTask>(_context);
}

TaskPtr Session::startProtocolUpgrade(const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    checkActivationData();
    auto task = std::make_shared<ProtocolUpgradeTask>(_context, password, new_biometry_kek);
    // Start the task to prepare upgrade structure in SessionData class.
    task->start();
    return task;
}

RequestPtr Session::removeActivation(const CredentialsPtr& credentials)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->activationService().removeActivation(credentials);
}

RequestPtr Session::verifyPassword(const PasswordPtr &password)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->authenticationService().verifyPassword(*password);
}

RequestPtr Session::changePassword(const PasswordPtr& old_password, const PasswordPtr& new_password)
{
    LOCK_GUARD();
    checkActivationData();
    return _context->activationService().changePassword(old_password, new_password);
}

bool Session::hasBiometricFactor() const
{
    LOCK_GUARD();
    checkActivationData();
    return sessionData().persistentData().hasBiometricFactorKey();
}

RequestPtr Session::addBiometricFactor(const PasswordPtr& password, const cc7::ByteRange& new_biometry_kek)
{
    LOCK_GUARD();
    checkActivationData();
    if (sessionData().persistentData().hasBiometricFactorKey()) {
        throw Exception(EC_NotAllowed, "Biometric factor is already set");
    }
    // Check inputs in advance
    Credentials::validatePassword(*password);
    Credentials::validateFactorKek(new_biometry_kek, _context->protocolVersion());
    return _context->activationService().addBiometricFactor(password, new_biometry_kek);
}

RequestPtr Session::removeBiometricFactor()
{
    LOCK_GUARD();
    checkActivationData();
    if (!sessionData().persistentData().hasBiometricFactorKey()) {
        throw Exception(EC_NotAllowed, "Biometric factor is not set");
    }
    return _context->activationService().removeBiometricFactor();
}

RequestPtr Session::fetchUserInfo()
{
    LOCK_GUARD();
    checkActivationData();
    return _context->activationService().fetchUserInfo();
}

cc7::json::JsonValue Session::lastUserInfo() const noexcept
{
    LOCK_GUARD();
    return _context->sessionData().getUserInfo();
}

ActivationStatusPtr Session::lastActivationStatus() const noexcept
{
    LOCK_GUARD();
    return _context->sessionData().getActivationStatusPtr();
}

void Session::checkActivationData() const
{
    if (!sessionData().hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
}

// MARK: - Authentication

HttpHeader Session::calculateOnlineAuthenticationHeader(const Credentials& credentials,
                                                        const std::string_view& uri_identifier,
                                                        const std::string_view& http_method,
                                                        const cc7::ByteRange& request_body)
{
    LOCK_GUARD();
    return _context->authenticationService().calculateOnlineAuthenticationHeader(credentials, {
        uri_identifier,
        http_method,
        false,
        false
    }, request_body);
}


std::string Session::calculateOfflineAuthenticationCode(const Credentials& credentials,
                                                        const std::string_view& uri_identifier,
                                                        const std::string_view& offline_nonce,
                                                        const cc7::ByteRange& data,
                                                        size_t code_length)
{
    LOCK_GUARD();
    return _context->authenticationService().calculateOfflineAuthenticationCode(credentials, {
        uri_identifier,
        offline_nonce,
        code_length
    }, data);
}

// MARK: - Tokens

HttpHeader Session::calculateTokenHeader(const std::string_view &token_identifier,
                                         const cc7::ByteRange &token_secret)
{
    LOCK_GUARD();
    return _context->tokenService().calculateTokenHeader({ token_identifier, token_secret });
}

RequestPtr Session::createAccessToken(const CredentialsPtr &credentials)
{
    LOCK_GUARD();
    return _context->tokenService().createAccessToken(credentials);
}

RequestPtr Session::removeAccessToken(const std::string_view &token_identifier)
{
    LOCK_GUARD();
    return _context->tokenService().removeAccessToken(token_identifier);
}

// MARK: - Vault key

RequestPtr Session::fetchVaultEncryptionKey(const CredentialsPtr& credentials, SecureVaultKeyId key_id, cc7::U64 index) const
{
    LOCK_GUARD();
    return _context->vaultService().fetchVaultEncryptionKey(credentials, key_id, index);
}

cc7::ByteArray Session::deriveVaultEncryptionKey(const cc7::ByteRange& key,
                                                 cc7::U64 index,
                                                 cc7::U64 key_size,
                                                 SecureVaultKeyId key_id)
{
    return VaultService::deriveVaultEncryptionKey(key, index, key_size, key_id);
}


// MARK: - Digital signatures

static DevicePublicKeyData _BuildDevicePublicKeyData(const cc7::crypto::PublicKey& public_key, cc7::crypto::KeyFormat key_format)
{
    auto key_type = public_key.getKeyType();
    return {
        SignatureKeySpec::keyTypeForKeyAlgorithm(key_type),
        key_type,
        public_key.exportKey(key_format)
    };
}

std::vector<DevicePublicKeyData> Session::exportDevicePublicKeys(cc7::crypto::KeyFormat key_format) const
{
    LOCK_GUARD();
    if (!_context->sessionData().hasActivationId()) {
        throw Exception(EC_MissingActivation);
    }
    const auto& public_key = _context->keyProvider().devicePublicKey();
    auto spec = _context->specification();
    std::vector<DevicePublicKeyData> result;
    if (!spec->isLegacy()) {
        const auto& key1 = v4::HybridKey_GetKey1(public_key);
        result.push_back(_BuildDevicePublicKeyData(key1, key_format));
        if (spec->isHybrid()) {
            const auto& key2 = v4::HybridKey_GetKey2(public_key);
            result.push_back(_BuildDevicePublicKeyData(key2, key_format));
        }
    } else {
        result.push_back(_BuildDevicePublicKeyData(public_key, key_format));
    }
    return result;
}

void Session::verifySignature(const cc7::ByteRange& signed_data,
                              const cc7::ByteRange& signature,
                              SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    _context->signatureService().verifySignature(signed_data, signature, key_to_use);
}

RequestPtr Session::signData(const CredentialsPtr& credentials,
                             const cc7::ByteRange& data_to_sign,
                             SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    return _context->signatureService().signData(credentials, data_to_sign, key_to_use);
}

void Session::jwsVerifySignature(const std::string &signed_data,
                                 SignatureKeyId key_to_use,
                                 bool is_compact_form,
                                 bool strict_verify) const
{
    LOCK_GUARD();
    cc7::jwt::JwsVerifyMode verify_mode = strict_verify ? cc7::jwt::JwsVerifyMode::VERIFY_ALL_KEYS : cc7::jwt::JwsVerifyMode::VERIFY_AT_LEAST_ONE;
    _context->signatureService().jwsVerifySignature(signed_data, key_to_use, is_compact_form, verify_mode);
}

RequestPtr Session::jwsSignData(const CredentialsPtr& credentials,
                                const cc7::ByteRange& data_to_sign,
                                const std::string& data_type,
                                SignatureKeyId key_to_use,
                                bool use_compact_form) const
{
    LOCK_GUARD();
    return _context->signatureService().jwsSignData(credentials, data_to_sign, data_type, key_to_use, use_compact_form);
}

RequestPtr Session::createCertificateSigningRequest(const CredentialsPtr& credentials,
                                                    const std::map<std::string, std::string>& dn_items,
                                                    const std::vector<std::string>& san_items,
                                                    SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    return _context->signatureService().createCSR(credentials, dn_items, san_items, key_to_use);
}

// MARK: - EEK

bool Session::hasExternalEncryptionKey() const noexcept
{
    LOCK_GUARD();
    auto& sd = _context->sessionData();
    if (sd.hasPersistentData(Version_V3)) {
        return sd.persistentData().v3().flags.usesExternalKey == 1;
    }
    return false;
}

/// Enables or disables EEK in V3 persistent data.
/// - Parameters:
///   - pd: Persistent data structure.
///   - eek: External encryption key.
///   - enable: Set 1 to enable, or 0 to disable EEK.
static void EEK_SetEnabled(PersistentData::V3& pd, const cc7::ByteRange& eek, cc7::byte enable)
{
    auto& uke = algorithms().v3.uke();
    auto has_biometry = !pd.cBiometryKey.empty();
    cc7::ByteArray knowledge;
    cc7::ByteArray biometry;
    if (enable) {
        knowledge = uke.wrap(eek, pd.cKnowledgeKey);
        if (has_biometry) {
            biometry = uke.wrap(eek, pd.cBiometryKey);
        }
    } else {
        knowledge = uke.unwrap(eek, pd.cKnowledgeKey);
        if (has_biometry) {
            biometry = uke.unwrap(eek, pd.cBiometryKey);
        }
    }
    // Update PD
    pd.cKnowledgeKey = knowledge;
    pd.cBiometryKey = biometry;
    pd.flags.usesExternalKey = enable;
}

void Session::removeExternalEncryptionKey(const cc7::ByteRange &eek)
{
    LOCK_GUARD();
    auto& sd = _context->sessionData();
    if (!sd.hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
    if (!sd.hasPersistentData(Version_V3)) {
        throw Exception(EC_WrongActivationState, "Removing EEK requires legacy activation");
    }
    auto& pd = sd.persistentData().v3();
    if (!pd.flags.usesExternalKey) {
        throw Exception(EC_WrongActivationState, "EEK is not present in activation data");
    }
    EEK_SetEnabled(pd, eek, 0);
}

void Session::addExternalEncryptionKeyForTest(const cc7::ByteRange &eek)
{
    LOCK_GUARD();
    auto& sd = _context->sessionData();
    if (!sd.hasPersistentData()) {
        throw Exception(EC_MissingActivation);
    }
    if (!sd.hasPersistentData(Version_V3)) {
        throw Exception(EC_WrongActivationState, "Adding EEK requires legacy activation");
    }
    auto& pd = sd.persistentData().v3();
    if (pd.flags.usesExternalKey) {
        throw Exception(EC_WrongActivationState, "EEK is already present in activation data");
    }
    EEK_SetEnabled(pd, eek, 1);
}

// MARK: - Utilities

cc7::ByteArray Session::generateFactorKek() const
{
    LOCK_GUARD();
    return generateFactorKekForProtocol(_context->protocolVersion());
}

cc7::ByteArray Session::generateFactorKekFromData(const cc7::ByteRange& data) const
{
    LOCK_GUARD();
    return generateFactorKekFromData(data, _context->protocolVersion());
}

cc7::ByteArray Session::generateFactorKekFromData(const cc7::ByteRange& data, ProtocolVersion version)
{
    switch (version) {
        case Version_V4: {
            return algorithms().v4.sha3_256().digest(data);
        }
        case Version_V3: {
            // Compatible with 1.9.x, Session::normalizeSignatureUnlockKeyFromData()
            auto kek = algorithms().v3.sha256().digest(data);
            kek.resize(v3::FACTOR_KEY_SIZE);
            return kek;
        }
        default:
            throw Exception(EC_WrongParameter, "Unsupported protocol version");
    }
}

cc7::ByteArray Session::generateFactorKekForProtocol(ProtocolVersion version)
{
    size_t kek_size;
    switch (version) {
        case Version_V4: kek_size = v4::FACTOR_KEY_SIZE; break;
        case Version_V3: kek_size = v3::FACTOR_KEY_SIZE; break;
        default:
            throw Exception(EC_WrongParameter, "Unsupported protocol version");
    }
    return cc7::crypto::GetRandomData(kek_size);
}

void Session::cleanupBiometricFactorData()
{
    LOCK_GUARD();
    return _context->activationService().cleanupBiometricFactorData();
}

// MARK: - Services

const TimeServicePtr& Session::getTimeService() const noexcept
{
    return _context->getTimeServicePtr();
}

const IClientEncryptorFactoryPtr& Session::getEncryptorFactory() const noexcept
{
    LOCK_GUARD();
    return _context->getEncryptorFactoryPtr();
}

const IAuthenticationServicePtr& Session::getAuthenticationService() const noexcept
{
    LOCK_GUARD();
    return _context->getAuthenticationServicePtr();
}

const ITokenServicePtr& Session::getTokenService() const noexcept
{
    LOCK_GUARD();
    return _context->getTokenServicePtr();
}

// Private service functions

IKeyProvider& Session::keyProvider() noexcept
{
    return _context->keyProvider();
}

IClientEncryptorFactory& Session::encryptorFactory() noexcept
{
    return _context->encryptorFactory();
}

} // namespace powerAuth
