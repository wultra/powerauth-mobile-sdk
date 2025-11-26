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
#include "FunctionsV3.h"

namespace powerAuth {
namespace v3 {

using namespace cc7;
using namespace common;

// MARK: - Constants

const KT::INPUT             SecretKeysV3::any_input     { 0 };
const KT::INPUT             SecretKeysV3::default_input { v3::FACTOR_KEY_SIZE };
const KT::INPUT             SecretKeysV3::uke_encrypted { v3::FACTOR_KEY_SIZE };
const KT::INPUT             SecretKeysV3::input_32      { 32 };

const common::KT::LegacyUKE SecretKeysV3::uke_encrypt   { KT::ENCRYPT };
const common::KT::LegacyUKE SecretKeysV3::uke_decrypt   { KT::DECRYPT };

// MARK: - Construction

SecretKeysV3::SecretKeysV3(std::shared_ptr<KeyProviderV3> owner, cc7::U64 instance_token) :
    _owner(owner),
    _instance_token(instance_token),
    _pool({
        KID_INPUT,
        KID_INPUT_OUTPUT,
        KID_COUNT,
        v3::FACTOR_KEY_SIZE,
        1024,
        keyNameResolver
    })
{
}

SecretKeysV3::~SecretKeysV3()
{
    if (_instance_token) {
        _owner->safeReleaseSecretKeys(*this, _instance_token);
        _instance_token = 0;
    }
}

void SecretKeysV3::loadSessionData(const SessionData& session_data)
{
    setupCreationMode(session_data.hasPersistentData() ? CM_ACTIVE : CM_BASIC);
    setupSessionData(session_data);
}

void SecretKeysV3::loadInitialCredentials(const SessionData& session_data,
                                          const InitialCredentials& credentials,
                                          const ByteRange& shared_secret)
{
    credentials.validate(Version_V3);
    if (session_data.hasPersistentData()) {
        throw Exception(EC_WrongActivationState, "Persistent data already created");
    }
    if (!session_data.hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Cannot load initial credentials due to missing pending activation");
    }
    
    setupCreationMode(CM_INITIAL);
    // Shared secret may be empty, because we can deduce the value with using ECDH.
    if (!shared_secret.empty()) {
        _pool.setKey(KEY_SHARED_SECRET, default_input, shared_secret);
    }
    setupNewPassword(credentials.knowledgeKEK());
    
    setupSessionData(session_data);
    
    if ((_has_biometry = credentials.hasBiometryKEK())) {
        _pool.setKey(KEK_AUTHENTICATION_BIOMETRY, default_input, credentials.biometryKEK());
    }
    _has_credentials = true;
}

void SecretKeysV3::loadCredentials(const SessionData& session_data,
                                   const Credentials& credentials)
{
    setupCreationMode(CM_ACTIVE);
    setupCredentials(session_data, credentials);
}

void SecretKeysV3::loadVaultKey(const SessionData &session_data, VaultKeyType key_type, const cc7::ByteRange &key_data)
{
    setupCreationMode(CM_VAULT);
    setupSessionData(session_data);
    setupVaultKey(key_type, key_data);
}

void SecretKeysV3::loadCredentialsWithVaultKey(const SessionData& session_data,
                                               const Credentials &credentials,
                                               VaultKeyType key_type,
                                               const cc7::ByteRange &key_data)
{
    setupCreationMode(CM_VAULT);
    setupCredentials(session_data, credentials);
    setupVaultKey(key_type, key_data);
}

void SecretKeysV3::setupSessionData(const SessionData &session_data)
{
    if (_loaded) {
        throw Exception(EC_InternalError, "Context is already loaded in SecretKeysV3");
    }
    _loaded = true;

    const auto& configuration = _owner->configuration();
    _pool.setKey(IN_APP_SECRET, default_input, MakeRange(configuration.applicationSecretBytes()));
    _pool.setKey(IN_DEVICE_SPECIFIC_DATA, any_input, configuration.deviceSpecificData());

    if ((_has_activation = session_data.hasPersistentData())) {
        //
        // Registration complete
        //
        const auto& pd = session_data.persistentData().v3();
        // factor keys
        _has_biometry = !pd.cBiometryKey.empty();
        _pool.setKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypted, pd.cPossessionKey);
        _pool.setKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypted, pd.cKnowledgeKey);
        if (!pd.cBiometryKey.empty()) {
            _pool.setKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypted, pd.cBiometryKey);
        }
        // encrypted keys
        _pool.setKey(CKEY_TRANSPORT, uke_encrypted, pd.cTransportKey);
        _pool.setKey(CKEY_DEVICE_PRIVATE, any_input, pd.cDevicePrivateKey);
        
    } else if (session_data.hasRegistrationData()) {
        //
        // Pending registration
        //
        const auto& rd = session_data.registrationData().v3();
        // TODO: this may be useful during the activation process, when keys are not confirmed,
        if (!rd.calculatedSharedSecret.empty() && !_pool.isSet(KEY_SHARED_SECRET)) {
            // Shared secret is already calculated and not set yet in final phase.
            // This may be useful for situ
            _pool.setKey(KEY_SHARED_SECRET, default_input, rd.calculatedSharedSecret);
        }
        // Use generated device private key
        if (rd.deviceKeyPair) {
            _device_private = rd.deviceKeyPair->getPrivateKeyPtr();
        }
    }
}

void SecretKeysV3::setupCredentials(const SessionData& session_data, const Credentials& credentials)
{
    if (!session_data.hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Cannot load credentials due to missing activation");
    }
    credentials.validate(Version_V3);

    bool credentials_with_biometry;
    switch (credentials.factors()) {
        case AuthFactors::POSSESSION:
            credentials_with_biometry = false;
            break;
        case AuthFactors::POSSESSION_KNOWLEDGE: {
            const auto& pd = session_data.persistentData().v3();
            _pool.setKey(IN_PASSWORD, any_input, credentials.knowledgeKEK());
            _pool.setKey(IN_PASSWORD_SALT, default_input, pd.passwordSalt);
            _password_iterations = pd.passwordIterations;
            credentials_with_biometry = false;
            break;
        }
        case AuthFactors::POSSESSION_BIOMETRY:
            _pool.setKey(KEK_AUTHENTICATION_BIOMETRY, default_input, credentials.biometryKEK());
            credentials_with_biometry = true;
            break;
    }
    setupSessionData(session_data);

    if (credentials_with_biometry && !_has_biometry) {
        throw Exception(EC_BiometryNotAllowed, "Biometric factor is not configured");
    }
    _has_credentials = true;
}

void SecretKeysV3::setupVaultKey(VaultKeyType key_type, const cc7::ByteRange &key_data)
{
    switch (key_type) {
        case VaultKeyType::KEK_DEVICE_PRIVATE:
            _pool.setKey(CKEY_ENCRYPTION_VAULT, input_32, key_data);
            break;
        default:
            throwNotSupported();
    }
}

SecretKeysV3::CreationMode SecretKeysV3::setReturned(cc7::U64 instance_token)
{
    if (_instance_token != instance_token) {
        throw Exception(EC_InternalError, "Wrong instance returned");
    }
    _instance_token = 0;
    return _creation_mode;
}

void SecretKeysV3::setupNewPassword(const cc7::ByteRange &password)
{
    _pool.setKey(IN_PASSWORD, any_input, password);
    _pool.setKey(IN_PASSWORD_SALT, default_input, crypto::GetRandomData(v3::PBKDF2_SALT_SIZE));
    _password_iterations = v3::PBKDF2_PASS_ITERATIONS;
}

cc7::U32 SecretKeysV3::getPasswordIterations() const
{
    if (_password_iterations) {
        return _password_iterations;
    }
    throw Exception(EC_InternalError, "PBKDF2 iterations not set");
}

ProtocolVersion SecretKeysV3::protocolVersion() const noexcept
{
    return Version_V3;
}

// MARK: - Authentication

cc7::ByteRange SecretKeysV3::kekAuthenticationCodePossession()
{
    return keyDeviceSpecific();
}

cc7::ByteRange SecretKeysV3::kekAuthenticationCodeKnowledge()
{
    return _pool.getKey(KEK_AUTHENTICATION_KNOWLEDGE, [this]() -> KT::LegacyPBKDF2Keys {
        return {
            _pool.getKey(IN_PASSWORD, any_input),
            _pool.getKey(IN_PASSWORD_SALT, default_input),
            getPasswordIterations()
        };
    });
}

cc7::ByteRange SecretKeysV3::keyAuthenticationCodePossession()
{
    checkAccessLevel(KEY_AUTHENTICATION_POSSESSION, AL_ACTIVE, false);
    
    if (_pool.isSet(CKEY_AUTHENTICATION_POSSESSION)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_POSSESSION, uke_decrypt, [this]() -> KT::LegacyUKEKeys {
            return {
                kekAuthenticationCodePossession(),                          // KEK
                _pool.getKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypted) // encrypted factor key
            };
        });
    } else {
        // CKEY Not set, try to derive
        static const KT::LegacyKDF derive { 1 };
        return _pool.getKey(KEY_AUTHENTICATION_POSSESSION, derive, [this]() -> KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV3::keyAuthenticationCodeKnowledge()
{
    checkAccessLevel(KEY_AUTHENTICATION_KNOWLEDGE, AL_ACTIVE, true);
    
    if (_pool.isSet(CKEY_AUTHENTICATION_KNOWLEDGE)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_KNOWLEDGE, uke_decrypt, [this]() -> KT::LegacyUKEKeys {
            return {
                kekAuthenticationCodeKnowledge(),                           // KEK
                _pool.getKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypted)  // encrypted factor key
            };
        });
    } else {
        // CKEY Not set, try to derive
        static const KT::LegacyKDF derive { 2 };
        return _pool.getKey(KEY_AUTHENTICATION_KNOWLEDGE, derive, [this]() -> KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV3::keyAuthenticationCodeBiometry()
{
    if (!_biometry_key_update) {
        checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_ACTIVE, true);
    } else {
        checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_VAULT);
    }
    
    if (!_has_biometry) {
        throw Exception(EC_BiometryNotAllowed);
    }
    if (_pool.isSet(CKEY_AUTHENTICATION_BIOMETRY)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_BIOMETRY, uke_decrypt, [this]() -> KT::LegacyUKEKeys {
            return {
                _pool.getKey(KEK_AUTHENTICATION_BIOMETRY, default_input),   // KEK
                _pool.getKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypted)   // encrypted factor key
            };
        });
    } else {
        // Not set, try to derive
        static const KT::LegacyKDF derive { 3 };
        return _pool.getKey(KEY_AUTHENTICATION_BIOMETRY, derive, [this]() -> KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV3::ckeyAuthenticationCodePossession()
{
    return _pool.getKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypt, [this]() -> KT::LegacyUKEKeys {
        return {
            kekAuthenticationCodePossession(),                              // KEK
            keyAuthenticationCodePossession()                               // factor key
        };
    });
}

cc7::ByteRange SecretKeysV3::ckeyAuthenticationCodeKnowledge()
{
    return _pool.getKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypt, [this]() -> KT::LegacyUKEKeys {
        return {
            kekAuthenticationCodeKnowledge(),                               // KEK
            keyAuthenticationCodeKnowledge()                                // factor key
        };
    });
}

cc7::ByteRange SecretKeysV3::ckeyAuthenticationCodeBiometry()
{
    if (_pool.isSet(KEK_AUTHENTICATION_BIOMETRY)) {
        // has biometry KEK set, so factor is important
        return _pool.getKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypt, [this]() -> KT::LegacyUKEKeys {
            return {
                _pool.getKey(KEK_AUTHENTICATION_BIOMETRY, default_input),   // KEK
                keyAuthenticationCodeBiometry()                             // factor key
            };
        });
    }
    // Biometry factor is not set, just return empty range.
    // Don't fail
    return ByteRange();
}

void SecretKeysV3::updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_key,
                                                        const cc7::ByteRange& new_kek)
{
    // Decrypt knowledge key. The call also validates proper access level.
    keyAuthenticationCodeKnowledge();

    // cleanup
    _pool.clearKey(CKEY_AUTHENTICATION_KNOWLEDGE);
    _pool.clearKey(KEK_AUTHENTICATION_KNOWLEDGE);
    _pool.clearKey(IN_PASSWORD);
    _pool.clearKey(IN_PASSWORD_SALT);
    _password_iterations = 0;
    
    // new setup
    setupNewPassword(new_kek);
    
    _knowledge_key_update = true;
}

void SecretKeysV3::updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_key,
                                                       const cc7::ByteRange& new_kek)
{
    // Vault access is required
    checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_VAULT);
    
    // derive keyActivationSecret
    keyActivationSecret();

    // clear possible stored keys
    _pool.clearKey(CKEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEK_AUTHENTICATION_BIOMETRY);

    // store new KEK only. KEY_AUTHENTICATION_BIOMETRY will be derived automatically
    // during the secrets locking.
    
    _pool.setKey(KEK_AUTHENTICATION_BIOMETRY, default_input, new_kek);
    
    _biometry_key_update = true;
    _has_biometry = true;
}

void SecretKeysV3::removeKeyAuthenticationCodeBiometry()
{
    checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_ACTIVE);
    
    _pool.clearKey(CKEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEK_AUTHENTICATION_BIOMETRY);
    
    _biometry_key_update = true;
    _has_biometry = false;
}

bool SecretKeysV3::isAuthenticationCodeKnowledgeUpdated() const noexcept
{
    return _knowledge_key_update;
}

bool SecretKeysV3::isAuthenticationCodeBiometryUpdated() const noexcept
{
    return _biometry_key_update;
}

cc7::ByteRange SecretKeysV3::getInputData(KeyId key_id)
{
    return _pool.getKey(key_id, any_input);
}

// MARK: - Encryption

cc7::ByteRange SecretKeysV3::keyDeviceSpecific()
{
    static const KT::CUSTOM derivation { v3::FACTOR_KEY_SIZE };
    return _pool.getKey(KEY_DEVICE_SPECIFIC, derivation, [this]() -> KT::Key {
        auto data = _pool.getKey(IN_DEVICE_SPECIFIC_DATA, any_input);
        auto digest = algorithms().v3.sha256().digest(data);
        digest.resize(v3::FACTOR_KEY_SIZE);
        return digest;
    });
}

cc7::ByteRange SecretKeysV3::keyLocalData()
{
    throwNotSupported();
}

// MARK: - Vault


cc7::ByteRange SecretKeysV3::kekDevicePrivate()
{
    checkAccessLevel(KEY_ENCRYPTION_VAULT, AL_VAULT);
    
    if (_pool.isSet(CKEY_ENCRYPTION_VAULT)) {
        // Encrypted vault key is set. Use transport key to decrypt it.
        KT::Cipher cipher { KT::DECRYPT, algorithms().v3.pointers.aes128_cbc };
        return _pool.getKey(KEY_ENCRYPTION_VAULT, cipher, [this]() -> KT::CipherKeys {
            return {
                legacyKeyTransport(),
                ZERO16_IV,
                _pool.getKey(CKEY_ENCRYPTION_VAULT, any_input)
            };
        });
    } else {
        // Otherwise try to derive key from shared secret
        static const KT::LegacyKDF derive { 2000 };
        return _pool.getKey(KEY_ENCRYPTION_VAULT, derive, [this]() -> KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV3::kdkAppVaultKnowledge()
{
    throwNotSupported();
}

cc7::ByteRange SecretKeysV3::kdkAppVault2FA()
{
    throwNotSupported();
}

// MARK: - Utility

cc7::ByteRange SecretKeysV3::keyMacCtrData()
{
    checkAccessLevel(KEY_TRANSPORT_CTR, AL_ACTIVE);
    
    static const KT::LegacyKDF derive { 4000 };
    return _pool.getKey(KEY_TRANSPORT_CTR, derive, [this]() -> KT::KeyRef {
        return legacyKeyTransport();
    });
}

cc7::ByteRange SecretKeysV3::keyMacStatus()
{
    throwNotSupported();
}

cc7::ByteRange SecretKeysV3::keyMacGetAppTempKey()
{
    return _pool.getKey(IN_APP_SECRET, default_input);
}

cc7::ByteRange SecretKeysV3::keyMacGetActTempKey()
{
    checkAccessLevel(KEY_MAC_GET_APP_TEMP_KEY, AL_ACTIVE);
    
    return _pool.getKey(KEY_MAC_GET_APP_TEMP_KEY, [this]() -> KT::LegacyKDFIntKeys {
        return {
            legacyKeyTransport(),
            _pool.getKey(IN_APP_SECRET, default_input)
        };
    });
}

cc7::ByteRange SecretKeysV3::keyMacPersonalizedData()
{
    throwNotSupported();
}

cc7::ByteRange SecretKeysV3::keyE2EESharedInfo2()
{
    throwNotSupported();
}

cc7::ByteRange SecretKeysV3::kdkAppUtility()
{
    throwNotSupported();
}


// MARK: - Other

cc7::ByteRange SecretKeysV3::keyActivationSecret()
{
    static const KT::CUSTOM derivation { v3::FACTOR_KEY_SIZE };
    return _pool.getKey(KEY_SHARED_SECRET, derivation, [this]() -> KT::Key {
        // If KEY_SHARED_SECRET is not set, then deduce secret with ECDH
        auto secret = algorithms().v3.ecdhWithNullKdf().phase(devicePrivateKey(), _owner->serverPublicKey());
        return ReduceSharedSecret(secret->getKeyData());
    });
}

const cc7::crypto::PrivateKeyPtr& SecretKeysV3::getDevicePrivateKeyPtr()
{
    checkAccessLevel(KEY_ENCRYPTION_VAULT, AL_VAULT);
    if (!_device_private) {
        auto key = kekDevicePrivate();
        auto key_data = algorithms().v3.aes128cbc().decrypt(key,
                                                            ZERO16_IV,
                                                            _pool.getKey(CKEY_DEVICE_PRIVATE, any_input));
        _device_private = _owner->signingKeyFactory().newPrivateKey(key_data, cc7::crypto::KEY_FORMAT_RAW);
        _device_private->setSealed();
    }
    return _device_private;
}

cc7::ByteRange SecretKeysV3::ckeyDevicePrivate()
{
    KT::Cipher encrypt { KT::ENCRYPT, algorithms().v3.pointers.aes128_cbc };
    return _pool.getKey(CKEY_DEVICE_PRIVATE, encrypt, [this]() -> KT::CipherKeys {
        if (!_device_private) {
            throw Exception(EC_NotAllowed, "Device private key is not set");
        }
        return {
            kekDevicePrivate(),
            ZERO16_IV,
            _device_private->exportKey(crypto::KEY_FORMAT_RAW)
        };
    });
}


// MARK: - Legacy

cc7::ByteRange SecretKeysV3::legacyKeyTransport()
{
    checkAccessLevel(KEY_TRANSPORT, AL_ACTIVE);
    
    if (_pool.isSet(CKEY_TRANSPORT)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_TRANSPORT, uke_decrypt, [this]() -> KT::LegacyUKEKeys {
            return {
                keyDeviceSpecific(),                                        // KEK
                _pool.getKey(CKEY_TRANSPORT, uke_encrypted)                 // encrypted factor key
            };
        });
    } else {
        // CKEY Not set, try to derive
        static const KT::LegacyKDF derive { 1000 };
        return _pool.getKey(KEY_TRANSPORT, derive, [this]() -> KT::KeyRef {
            return _pool.getKey(KEY_SHARED_SECRET, default_input);
        });
    }
}

cc7::ByteRange SecretKeysV3::legacyKeyTransportIV()
{
    checkAccessLevel(KEY_TRANSPORT_IV, AL_ACTIVE);
    
    // CKEY Not set, try to derive
    static const KT::LegacyKDF derive { 3000 };
    return _pool.getKey(KEY_TRANSPORT_IV, derive, [this]() -> KT::KeyRef {
        return legacyKeyTransport();
    });
}

cc7::ByteRange SecretKeysV3::ckeyTransport()
{
    return _pool.getKey(CKEY_TRANSPORT, uke_encrypt, [this]() -> KT::LegacyUKEKeys {
        return {
            keyDeviceSpecific(),
            legacyKeyTransport()
        };
    });
}

// MARK: - Private

void SecretKeysV3::setupCreationMode(CreationMode mode)
{
    _creation_mode = mode;
    switch (mode) {
        case CM_BASIC:
            // If there's activation, then maximum access level is AL_PUBLIC.
            // If no activation, then AL_BASIC
            _access_level = AL_BASIC;
            break;
        case CM_ACTIVE:
            _access_level = AL_ACTIVE;
            break;
        case CM_VAULT:
            // In vault mode, all keys are allowed
        case CM_INITIAL:
            // In initial creation mode, all keys are allowed
            _access_level = AL_VAULT;
            break;
        default:
            throw Exception(EC_InternalError, "Wrong CreationMode");
    }
}

void SecretKeysV3::checkAccessLevel(int key_id, AccessLevel al, bool with_credentials) const
{
    if (al > _access_level) {
        throw Exception(EC_NotAllowed, "Access to key " + keyNameResolver(key_id) + " is denied");
    }
    if (with_credentials && !_has_credentials) {
        throw Exception(EC_NotAllowed, "Access to key " + keyNameResolver(key_id) + " require user credentials");
    }
}

void SecretKeysV3::throwNotSupported()
{
    throw Exception(EC_NotAllowed, "V4 key not available");
}

std::string SecretKeysV3::keyNameResolver(int key_id) noexcept
{
#if DEBUG
    switch (key_id) {
        case KEY_SHARED_SECRET: return "KEY_SHARED_SECRET";
        case KEK_AUTHENTICATION_KNOWLEDGE: return "KEK_AUTHENTICATION_KNOWLEDGE";
        case KEK_AUTHENTICATION_BIOMETRY: return "KEK_AUTHENTICATION_BIOMETRY";
        case CKEY_ENCRYPTION_VAULT: return "CKEY_ENCRYPTION_VAULT";
        case CKEY_AUTHENTICATION_POSSESSION: return "CKEY_AUTHENTICATION_POSSESSION";
        case CKEY_AUTHENTICATION_KNOWLEDGE: return "CKEY_AUTHENTICATION_KNOWLEDGE";
        case CKEY_AUTHENTICATION_BIOMETRY: return "CKEY_AUTHENTICATION_BIOMETRY";
        case CKEY_TRANSPORT: return "CKEY_TRANSPORT";
        case CKEY_DEVICE_PRIVATE: return "CKEY_DEVICE_PRIVATE";
        case IN_DEVICE_SPECIFIC_DATA: return "IN_DEVICE_SPECIFIC_DATA";
        case IN_PASSWORD: return "IN_PASSWORD";
        case IN_PASSWORD_SALT: return "IN_PASSWORD_SALT";
        case IN_APP_SECRET: return "IN_APP_SECRET";
        case KEY_AUTHENTICATION_POSSESSION: return "KEY_AUTHENTICATION_POSSESSION";
        case KEY_AUTHENTICATION_KNOWLEDGE: return "KEY_AUTHENTICATION_KNOWLEDGE";
        case KEY_AUTHENTICATION_BIOMETRY: return "KEY_AUTHENTICATION_BIOMETRY";
        case KEY_ENCRYPTION_VAULT: return "KEY_ENCRYPTION_VAULT";
        case KEY_TRANSPORT: return "KEY_TRANSPORT";
        case KEY_TRANSPORT_IV: return "KEY_TRANSPORT_IV";
        case KEY_TRANSPORT_CTR: return "KEY_TRANSPORT_CTR";
        case KEY_MAC_GET_APP_TEMP_KEY: return "KEY_MAC_GET_APP_TEMP_KEY";
        case KEY_MAC_GET_ACT_TEMP_KEY: return "KEY_MAC_GET_ACT_TEMP_KEY";
        case KEY_DEVICE_SPECIFIC: return "KEY_DEVICE_SPECIFIC";
        default:
            break;
    }
#endif
    return "#" + std::to_string(key_id);
}


} // namespace v3
} // namespace powerAuth
