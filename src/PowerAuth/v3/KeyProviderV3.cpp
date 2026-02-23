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

#include "KeyProviderV3.h"

namespace powerAuth {
namespace v3 {

KeyProviderV3::KeyProviderV3(const ContextPtr& context) :
    Service("KeyProviderV3", context->getSharedMutexPtr()),
    _configuration(context->getConfigurationPtr()),
    _session_data(context->getSessionDataPtr()),
    _specification(context->specification()),
    _signing_key_factory(context->getSigningKeyPairFactoryPtr()),
    _sec_key_created(false),
    _sec_key_token(1)
{
}

IServicePtr KeyProviderV3::asService()
{
    return shared_from_this();
}

void KeyProviderV3::doServiceDestroy()
{
    Service::doServiceDestroy();
    doClearSensitiveData();
}

void KeyProviderV3::clearSensitiveData()
{
    Service::clearSensitiveData();
    doClearSensitiveData();
}

void KeyProviderV3::clearActivationData()
{
    Service::clearActivationData();
    doClearSensitiveData();
}

void KeyProviderV3::doClearSensitiveData()
{
    _device_public_key = nullptr;
    _server_public_key = nullptr;
}

ProtocolVersion KeyProviderV3::protocolVersion() const noexcept
{
    return Version_V3;
}

cc7::crypto::ConstPublicKeyPtr KeyProviderV3::getMasterServerPublicKeyPtr()
{
    checkNotDestroyed();
    if (!_master_server_public_key) {
        _master_server_public_key = signingKeyFactory().newPublicKey(_configuration->p256MasterServerPublicKey(), cc7::crypto::KEY_FORMAT_X963);
    }
    return _master_server_public_key;
}

cc7::crypto::ConstPublicKeyPtr KeyProviderV3::getDevicePublicKeyPtr()
{
    checkNotDestroyed();
    if (!_device_public_key) {
        if (_session_data->hasPersistentData()) {
            _device_public_key = signingKeyFactory().newPublicKey(_session_data->persistentData().v3().devicePublicKey, cc7::crypto::KEY_FORMAT_X963);
        } else if (_session_data->hasRegistrationData() && _session_data->registrationData().isKeyExchangeComplete()) {
            _device_public_key = _session_data->registrationData().v3().deviceKeyPair->getPublicKeyPtr();
        } else {
            throw Exception(EC_NotAllowed, "Device public key is not available");
        }
    }
    return _device_public_key;
}

cc7::crypto::ConstPublicKeyPtr KeyProviderV3::getServerPublicKeyPtr()
{
    checkNotDestroyed();
    if (!_server_public_key) {
        if (_session_data->hasPersistentData()) {
            _server_public_key = signingKeyFactory().newPublicKey(_session_data->persistentData().v3().serverPublicKey, cc7::crypto::KEY_FORMAT_X963);
        } else if (_session_data->hasRegistrationData() && _session_data->registrationData().isKeyExchangeComplete()) {
            _server_public_key = _session_data->registrationData().v3().serverPublicKey;
        } else {
            throw Exception(EC_NotAllowed, "Server public key is not available");
        }
    }
    return _server_public_key;
}

void KeyProviderV3::clearActivationKeys() noexcept
{
    clearSensitiveData();
}

// MARK: - Secret Keys

ISecretKeysPtr KeyProviderV3::unlockInitialSecretKeys(const InitialCredentials &credentials, const cc7::ByteArray &shared_secret)
{
    auto keys = createSecretKeys();
    keys->loadInitialCredentials(*_session_data, credentials, shared_secret);
    return keys;
}

ISecretKeysPtr KeyProviderV3::unlockSecretKeys()
{
    auto keys = createSecretKeys();
    keys->loadSessionData(*_session_data);
    return keys;
}

ISecretKeysPtr KeyProviderV3::unlockSecretKeysForFactors(AuthFactors factors)
{
    throw Exception(EC_InternalError, "unlockSecretKeysForFactors is not supported for protocol V3");
}

ISecretKeysPtr KeyProviderV3::unlockSecretKeys(const Credentials &credentials)
{
    auto keys = createSecretKeys();
    keys->loadCredentials(*_session_data, credentials);
    return keys;
}

ISecretKeysPtr KeyProviderV3::unlockVaultKey(VaultKeyType vault_key_type, const cc7::ByteRange &vault_key)
{
    auto keys = createSecretKeys();
    keys->loadVaultKey(*_session_data, vault_key_type, vault_key);
    return keys;
}

ISecretKeysPtr KeyProviderV3::unlockVaultAndSecretKeys(const Credentials &credentials, VaultKeyType vault_key_type, const cc7::ByteRange &vault_key)
{
    auto keys = createSecretKeys();
    keys->loadCredentialsWithVaultKey(*_session_data, credentials, vault_key_type, vault_key);
    return keys;
}

void KeyProviderV3::lockSecretKeys(ISecretKeysPtr &secret_keys)
{
    auto typed_keys = dynamic_cast<SecretKeysV3*>(secret_keys.get());
    if (!typed_keys) {
        throw Exception(EC_InternalError, "Invalid ISecretKeysPtr type");
    }
    auto lock_mode = typed_keys->setReturned(_sec_key_token);
    _sec_key_created = false;
    
    auto keys = std::move(secret_keys);
    switch (lock_mode) {
        case SecretKeysV3::CM_INITIAL: {
            // Construct new persistent data
            auto new_pd = createPDFromSecretKeys(*typed_keys);
            _session_data->setPersistentData(new_pd);
            break;
        }
        case SecretKeysV3::CM_ACTIVE:
            // passthrough
        case SecretKeysV3::CM_VAULT:
            // Apply potential changes to persistent data
            updateSessionData(*typed_keys);
            break;
            
        default:
            break;
    }
    // destroy keys object
    keys = nullptr;
}

void KeyProviderV3::safeReleaseSecretKeys(const SecretKeysV3 &secret_keys, cc7::U64 instance_token)
{
    bool known_keys = instance_token == _sec_key_token;
    CC7_ASSERT(known_keys, "Unknown SecretKeysV3 instance released");
    if (_sec_key_created) {
        if (known_keys) {
            // This is in general safe, but not recommended way how to dispose secret keys
            _sec_key_created = false;
            if (secret_keys.isAuthenticationCodeBiometryUpdated() || secret_keys.isAuthenticationCodeKnowledgeUpdated()) {
                // Print warning, only if the secrets has been modified
                CC7_LOG("WARNING: Abandoned SecretKeysV3 instance released");
            }
        }
    }
}

// custom

const Configuration& KeyProviderV3::configuration() const
{
    return *_configuration;
}

const cc7::crypto::KeyPairFactory& KeyProviderV3::signingKeyFactory()
{
    if (!_key_pair_factory) {
        _key_pair_factory = _specification->getSigningKeyPairFactory();
    }
    return *_key_pair_factory;
}

// MARK: - Private

std::unique_ptr<SecretKeysV3> KeyProviderV3::createSecretKeys()
{
    checkNotDestroyed();
    if (_sec_key_created) {
        throw Exception(EC_NotAllowed, "Secret keys already created");
    }
    _sec_key_created = true;
    return std::make_unique<SecretKeysV3>(shared_from_this(), ++_sec_key_token);
}

std::unique_ptr<PersistentData> KeyProviderV3::createPDFromSecretKeys(SecretKeysV3& secret_keys)
{
    const auto& rd = _session_data->registrationData().v3();
    
    // create new V3 persistent data
    auto pd = std::make_unique<PersistentData::V3>();
    pd->activationId = rd.activationId;
    pd->authCodeCounterByte = 0;
    pd->authCodeCounterData = rd.authCodeCounterData;
    pd->passwordSalt = secret_keys.getInputData(SecretKeysV3::IN_PASSWORD_SALT);
    pd->passwordIterations = secret_keys.getPasswordIterations();
    
    // factor keys
    pd->cPossessionKey = secret_keys.ckeyAuthenticationCodePossession();
    pd->cKnowledgeKey = secret_keys.ckeyAuthenticationCodeKnowledge();
    pd->cBiometryKey = secret_keys.ckeyAuthenticationCodeBiometry();
    
    // auxiliary keys
    pd->cTransportKey = secret_keys.ckeyTransport();
    
    // public & private keys
    pd->devicePublicKey = rd.deviceKeyPair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_X963);
    pd->serverPublicKey = rd.serverPublicKey->exportKey(cc7::crypto::KEY_FORMAT_X963);
    pd->cDevicePrivateKey = secret_keys.ckeyDevicePrivate();
    
    return PersistentData::create(pd);
}

void KeyProviderV3::updateSessionData(SecretKeysV3 &secret_keys)
{
    auto& pd = _session_data->persistentData().v3();
    if (secret_keys.isAuthenticationCodeKnowledgeUpdated()) {
        pd.cKnowledgeKey = secret_keys.ckeyAuthenticationCodeKnowledge();
        pd.passwordSalt = secret_keys.getInputData(SecretKeysV3::IN_PASSWORD_SALT);
        pd.passwordIterations = secret_keys.getPasswordIterations();
    }
    if (secret_keys.isAuthenticationCodeBiometryUpdated()) {
        pd.cBiometryKey = secret_keys.ckeyAuthenticationCodeBiometry();
    }
}


} // namespace v3
} // namespace powerAuth
