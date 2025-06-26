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

#include "KeyProviderV4.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

KeyProviderV4::KeyProviderV4(Context& context) :
    _configuration(context.getConfigurationPtr()),
    _session_data(context.getSessionDataPtr()),
    _specification(context.specification()),
    _signing_key_factory(context.getSigningKeyPairFactoryPtr()),
    _sec_key_created(false),
    _sec_key_token(1)
{
}

ProtocolVersion KeyProviderV4::protocolVersion() const noexcept
{
    return Version_V4;
}

const cc7::crypto::PublicKey& KeyProviderV4::masterServerPublicKey()
{
    if (!_master_server_public_key) {
        _master_server_public_key = getKeyPairFactory().newPublicKeyFromData(_configuration->ecdsaMasterServerPublicKey(),
                                                                             cc7::crypto::KEY_FORMAT_X963,
                                                                             _configuration->mldsaMasterServerPublicKey(),
                                                                             cc7::crypto::KEY_FORMAT_SPKI);
    }
    return *_master_server_public_key;
}

const cc7::crypto::PublicKey& KeyProviderV4::devicePublicKey()
{
    if (!_device_public_key) {
        if (_session_data->hasPersistentData()) {
            _device_public_key = getKeyPairFactory()
                .cc7::crypto::KeyPairFactory::newPublicKey(_session_data->persistentData().v4().devicePublicKey,
                                                           cc7::crypto::KEY_FORMAT_DEFAULT);
        } else if (_session_data->hasRegistrationData()) {
            _device_public_key = _session_data->registrationData().v4().deviceKeyPair->getPublicKeyPtr();
        } else {
            throw Exception(EC_NotAllowed, "Device public key is not available");
        }
    }
    return *_device_public_key;
}

const cc7::crypto::PublicKey& KeyProviderV4::serverPublicKey()
{
    if (!_server_public_key) {
        if (_session_data->hasPersistentData()) {
            _server_public_key = getKeyPairFactory()
                .cc7::crypto::KeyPairFactory::newPublicKey(_session_data->persistentData().v4().serverPublicKey,
                                                           cc7::crypto::KEY_FORMAT_DEFAULT);
        } else if (_session_data->hasRegistrationData()) {
            _server_public_key = _session_data->registrationData().v4().serverPublicKey;
        } else {
            throw Exception(EC_NotAllowed, "Server public key is not available");
        }
    }
    return *_server_public_key;
}

void KeyProviderV4::clearActivationKeys() noexcept
{
    _device_public_key = nullptr;
    _server_public_key = nullptr;
}

// MARK: - Secret Keys

ISecretKeysPtr KeyProviderV4::unlockInitialSecretKeys(const InitialCredentials &credentials, const cc7::ByteArray &shared_secret)
{
    auto keys = createSecretKeys();
    keys->loadInitialCredentials(*_session_data, credentials, shared_secret);
    return keys;
}

ISecretKeysPtr KeyProviderV4::unlockSecretKeys()
{
    auto keys = createSecretKeys();
    keys->loadSessionData(*_session_data);
    return keys;
}

ISecretKeysPtr KeyProviderV4::unlockSecretKeys(const Credentials &credentials)
{
    auto keys = createSecretKeys();
    keys->loadCredentials(*_session_data, credentials);
    return keys;
}

ISecretKeysPtr KeyProviderV4::unlockVaultAndSecretKeys(const Credentials &credentials, VaultKeyType vault_key_type, const cc7::ByteRange &vault_key)
{
    auto keys = createSecretKeys();
    keys->loadCredentialsWithVaultKey(*_session_data, credentials, vault_key_type, vault_key);
    return keys;
}

void KeyProviderV4::lockSecretKeys(ISecretKeysPtr &secret_keys)
{
    auto typed_keys = dynamic_cast<SecretKeysV4*>(secret_keys.get());
    if (!typed_keys) {
        throw Exception(EC_InternalError, "Invalid ISecretKeysPtr type");
    }
    auto lock_mode = typed_keys->setReturned(_sec_key_token);
    _sec_key_created = false;
    
    auto keys = std::move(secret_keys);
    switch (lock_mode) {
        case SecretKeysV4::CM_INITIAL: {
            // Construct new persistent data
            auto new_pd = createPDFromSecretKeys(*typed_keys);
            _session_data->setPersistentData(new_pd);
            break;
        }
        case SecretKeysV4::CM_ACTIVE:
            // passthrough
        case SecretKeysV4::CM_VAULT:
            // Apply potential changes to persistent data
            updateSessionData(*typed_keys);
            break;
            
        default:
            break;
    }
    // destroy keys object
    keys = nullptr;
}

void KeyProviderV4::safeReleaseSecretKeys(const SecretKeysV4 &secret_keys, cc7::U64 instance_token)
{
    bool known_keys = instance_token == _sec_key_token;
    CC7_ASSERT(known_keys, "Unknown SecretKeysV4 instance released");
    if (_sec_key_created) {
        if (known_keys) {
            _sec_key_created = false;
            // This is in general safe, but not recommended way how to dispose secret keys
            CC7_LOG("WARNING: Abandoned SecretKeysV4 instance released");
        }
    }
}

const Configuration& KeyProviderV4::configuration() const
{
    return *_configuration;
}

const cc7::crypto::KeyPairFactory& KeyProviderV4::signingKeyFactory()
{
    return getKeyPairFactory();
}

// MARK: - Private

HybridKeyPairFactory& KeyProviderV4::getKeyPairFactory()
{
    if (!_key_pair_factory) {
        auto key_pair_algs = _specification->getSigningKeyPairAlgorithms();
        _key_pair_factory = HybridKeyPairFactory::getInstance(key_pair_algs.first, key_pair_algs.second);
    }
    return *_key_pair_factory;
}

std::unique_ptr<SecretKeysV4> KeyProviderV4::createSecretKeys()
{
    if (_sec_key_created) {
        throw Exception(EC_NotAllowed, "Secret keys already created");
    }
    _sec_key_created = true;
    return std::make_unique<SecretKeysV4>(shared_from_this(), ++_sec_key_token);
}

std::unique_ptr<PersistentData> KeyProviderV4::createPDFromSecretKeys(SecretKeysV4& secret_keys)
{
    auto spec = PowerAuthSpec::specForAlgorithm(_configuration->algorithm());
    const auto& rd = _session_data->registrationData().v4();
    
    // create new V4 persistent data
    auto pd = std::make_unique<PersistentData::V4>();
    
    pd->sharedSecretAlgorithm = spec->algorithmId();
    pd->activationId = rd.activationId;
    pd->authCodeCounterByte = 0;
    pd->authCodeCounterData = rd.authCodeCounterData;
    pd->passwordSalt = secret_keys.getInputData(SecretKeysV4::IN_PASSWORD_SALT);
    
    // factor keys
    pd->cPossessionKey = secret_keys.ckeyAuthenticationCodePossession();
    pd->cKnowledgeKey = secret_keys.ckeyAuthenticationCodeKnowledge();
    pd->cBiometryKey = secret_keys.ckeyAuthenticationCodeBiometry();
    
    // auxiliary keys
    pd->cKdkUtility = secret_keys.ckdkUtility();
    pd->cKdkEncryption = secret_keys.ckdkEncryption();

    // public and private keys
    pd->devicePublicKey = rd.deviceKeyPair->getPublicKey().exportKey();
    pd->serverPublicKey = rd.serverPublicKey->exportKey();
    pd->cDevicePrivateKey = secret_keys.ckeyDevicePrivate();
    
    return PersistentData::create(pd);
}

void KeyProviderV4::updateSessionData(SecretKeysV4 &secret_keys)
{
    auto& pd = _session_data->persistentData().v4();
    if (secret_keys.isAuthenticationCodeKnowledgeUpdated()) {
        pd.cKnowledgeKey = secret_keys.ckeyAuthenticationCodeKnowledge();
        pd.passwordSalt = secret_keys.getInputData(SecretKeysV4::IN_PASSWORD_SALT);
    }
    if (secret_keys.isAuthenticationCodeBiometryUpdated()) {
        pd.cBiometryKey = secret_keys.ckeyAuthenticationCodeBiometry();
    }
}

} // namespace v4
} // powerAuth
