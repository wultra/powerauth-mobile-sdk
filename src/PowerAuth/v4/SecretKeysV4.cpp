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
#include "PowerAuthUKE.h"
#include "PowerAuthAEAD.h"

namespace powerAuth {
namespace v4 {

using namespace cc7;
using namespace common;

// MARK: - Constants

const KT::INPUT SecretKeysV4::any_input     { 0 };
const KT::INPUT SecretKeysV4::input_16      { 16 };
const KT::INPUT SecretKeysV4::default_input { v4::FACTOR_KEY_SIZE };
const KT::INPUT SecretKeysV4::uke_encrypted { PowerAuthUKE::CIPHERTEXT_SIZE };
const KT::INPUT SecretKeysV4::uke_plain     { v4::FACTOR_KEY_SIZE };

const KT::INPUT SecretKeysV4::aead_generic_plain     { v4::FACTOR_KEY_SIZE };
const KT::INPUT SecretKeysV4::aead_generic_encrypted { v4::FACTOR_KEY_SIZE + PowerAuthAEAD::TAG_SIZE + PowerAuthAEAD::NONCE_SIZE };

const KT::UKE SecretKeysV4::uke_encrypt     { KT::ENCRYPT };
const KT::UKE SecretKeysV4::uke_decrypt     { KT::DECRYPT };

// MARK: - Construction

SecretKeysV4::SecretKeysV4(std::shared_ptr<KeyProviderV4> owner, cc7::U64 instance_token) :
    _owner(owner),
    _instance_token(instance_token),
    _pool({
        KID_INPUT,
        KID_INPUT_OUTPUT,
        KID_COUNT,
        v4::FACTOR_KEY_SIZE,
        1024,
        keyNameResolver
    })
{
}

SecretKeysV4::~SecretKeysV4()
{
    if (_instance_token) {
        _owner->safeReleaseSecretKeys(*this, _instance_token);
        _instance_token = 0;
    }
}

void SecretKeysV4::loadSessionData(const SessionData& session_data)
{
    setupCreationMode(session_data.hasPersistentData() ? CM_ACTIVE : CM_BASIC);
    setupSessionData(session_data);
}

void SecretKeysV4::loadInitialCredentials(const SessionData& session_data,
                                          const InitialCredentials& credentials,
                                          const ByteRange& shared_secret)
{
    credentials.validate(Version_V4);
    if (session_data.hasPersistentData()) {
        throw Exception(EC_WrongActivationState, "Persistent data already created");
    }
    if (!session_data.hasRegistrationData()) {
        throw Exception(EC_WrongActivationState, "Cannot load initial credentials due to missing pending activation");
    }
    
    setupCreationMode(CM_INITIAL);
    
    _pool.setKey(KEY_SHARED_SECRET, default_input, shared_secret);
    setupNewPassword(credentials.knowledgeKEK());
    
    setupSessionData(session_data);
    
    if ((_has_biometry = credentials.hasBiometryKEK())) {
        _pool.setKey(KEK_AUTHENTICATION_BIOMETRY, default_input, credentials.biometryKEK());
    }
    _has_credentials = true;
}

void SecretKeysV4::loadCredentials(const SessionData& session_data,
                                   const Credentials& credentials)
{
    setupCreationMode(CM_ACTIVE);
    setupCredentials(session_data, credentials);
}

void SecretKeysV4::loadVaultKey(const SessionData &session_data, VaultKeyType key_type, const cc7::ByteRange &key_data)
{
    setupCreationMode(CM_VAULT);
    setupSessionData(session_data);
    setupVaultKey(key_type, key_data);
}

void SecretKeysV4::loadCredentialsWithVaultKey(const SessionData& session_data,
                                               const Credentials& credentials,
                                               VaultKeyType key_type,
                                               const cc7::ByteRange &key_data)
{
    setupCreationMode(CM_VAULT);
    setupCredentials(session_data, credentials);
    setupVaultKey(key_type, key_data);
}

void SecretKeysV4::setupSessionData(const SessionData &session_data)
{
    if (_loaded) {
        throw Exception(EC_InternalError, "Context is already loaded in SecretKeysV4");
    }
    _loaded = true;

    const auto& configuration = _owner->configuration();
    _pool.setKey(IN_APP_SECRET, input_16, configuration.applicationSecretBytes());
    _pool.setKey(IN_DEVICE_SPECIFIC_DATA, any_input, configuration.deviceSpecificData());

    if ((_has_activation = session_data.hasPersistentData())) {
        //
        // Registration complete
        //
        const auto& pd = session_data.persistentData().v4();
        // factor keys
        _has_biometry = !pd.cBiometryKey.empty();
        _pool.setKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypted, pd.cPossessionKey);
        _pool.setKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypted, pd.cKnowledgeKey);
        if (!pd.cBiometryKey.empty()) {
            _pool.setKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypted, pd.cBiometryKey);
        }
        // encrypted keys
        _pool.setKey(CKDK_UTILITY, aead_generic_encrypted, pd.cKdkUtility);
        _pool.setKey(CKDK_ENCRYPTION, aead_generic_encrypted, pd.cKdkEncryption);
        _pool.setKey(CKEY_DEVICE_PRIVATE, any_input, pd.cDevicePrivateKey);
        
        // other data
        _pool.setKey(IN_ACTIVATION_ID, any_input, MakeRange(pd.activationId));
        
    } else if (session_data.hasRegistrationData()) {
        //
        // Pending registration
        //
        const auto& rd = session_data.registrationData().v4();
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
        
        // other data
        _pool.setKey(IN_ACTIVATION_ID, any_input, MakeRange(rd.activationId));
    }
}

void SecretKeysV4::setupCredentials(const SessionData& session_data, const Credentials& credentials)
{
    if (!session_data.hasPersistentData()) {
        throw Exception(EC_MissingActivation, "Cannot load credentials due to missing activation");
    }
    credentials.validate(Version_V4);

    bool credentials_with_biometry;
    switch (credentials.factors()) {
        case AuthFactors::POSSESSION:
            credentials_with_biometry = false;
            break;
        case AuthFactors::POSSESSION_KNOWLEDGE:
            _pool.setKey(IN_PASSWORD, any_input, credentials.knowledgeKEK());
            _pool.setKey(IN_PASSWORD_SALT, default_input, session_data.persistentData().v4().passwordSalt);
            credentials_with_biometry = false;
            break;
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

void SecretKeysV4::setupVaultKey(VaultKeyType key_type, const cc7::ByteRange &key_data)
{
    switch (key_type) {
        case VaultKeyType::KEK_DEVICE_PRIVATE:
            _pool.setKey(KEK_DEVICE_PRIVATE, default_input, key_data);
            break;
        case VaultKeyType::KDK_APP_VAULT_KNOWLEDGE:
            _pool.setKey(KDK_APP_VAULT_KNOWLEDGE, default_input, key_data);
            break;
        case VaultKeyType::KDK_APP_VAULT_2FA:
            _pool.setKey(KDK_APP_VAULT_2FA, default_input, key_data);
            break;
    }
}

SecretKeysV4::CreationMode SecretKeysV4::setReturned(cc7::U64 instance_token)
{
    if (_instance_token != instance_token) {
        throw Exception(EC_InternalError, "Wrong instance returned");
    }
    _instance_token = 0;
    return _creation_mode;
}

void SecretKeysV4::setupNewPassword(const cc7::ByteRange &password)
{
    _pool.setKey(IN_PASSWORD, any_input, password);
    _pool.setKey(IN_PASSWORD_SALT, default_input, crypto::GetRandomData(v4::PASSKDF_SALT_SIZE));
}

// MARK: - Methods

ProtocolVersion SecretKeysV4::protocolVersion() const noexcept
{
    return Version_V4;
}

// MARK: - Authentication

cc7::ByteRange SecretKeysV4::kdkAuthenticationCode()
{
    static const KT::KDF derive { "auth" };
    return _pool.getKey(KDK_AUTHENTICATION_CODE, derive, [this]() -> KT::KeyRef {
        return keyActivationSecret();
    });
}

cc7::ByteRange SecretKeysV4::kekAuthenticationCodePossession()
{
    static const KT::KDF derive { "enc/kek-possession" };
    return _pool.getKey(KEK_AUTHENTICATION_POSSESSION, derive, [this]() -> KT::KeyRef {
        return keyDeviceSpecific();
    });
}

cc7::ByteRange SecretKeysV4::kekAuthenticationCodeKnowledge()
{
    static const KT::PKDF derive { v4::FACTOR_KEY_SIZE };
    return _pool.getKey(KEK_AUTHENTICATION_KNOWLEDGE, derive, [this]() -> KT::PKDFKeys {
        return {
            _pool.getKey(IN_PASSWORD, any_input),
            _pool.getKey(IN_PASSWORD_SALT, default_input)
        };
    });
}

cc7::ByteRange SecretKeysV4::keyAuthenticationCodePossession()
{
    checkAccessLevel(KEY_AUTHENTICATION_POSSESSION, AL_ACTIVE, false);
    
    if (_pool.isSet(CKEY_AUTHENTICATION_POSSESSION)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_POSSESSION, uke_decrypt, [this]() -> KT::UKEKeys {
            return {
                kekAuthenticationCodePossession(),                          // KEK
                _pool.getKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypted) // encrypted factor key
            };
        });
    } else {
        // CKEY Not set, try to derive
        static const KT::KDF derive { "auth/possession" };
        return _pool.getKey(KEY_AUTHENTICATION_POSSESSION, derive, [this]() -> KT::KeyRef {
            return kdkAuthenticationCode();
        });
    }
}

cc7::ByteRange SecretKeysV4::keyAuthenticationCodeKnowledge()
{
    checkAccessLevel(KEY_AUTHENTICATION_KNOWLEDGE, AL_ACTIVE, true);
    
    if (_pool.isSet(CKEY_AUTHENTICATION_KNOWLEDGE)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_KNOWLEDGE, uke_decrypt, [this]() -> KT::UKEKeys {
            return {
                kekAuthenticationCodeKnowledge(),                           // KEK
                _pool.getKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypted)  // encrypted factor key
            };
        });
    } else {
        // CKEY Not set, try to derive
        static const KT::KDF derive { "auth/knowledge" };
        return _pool.getKey(KEY_AUTHENTICATION_KNOWLEDGE, derive, [this]() -> KT::KeyRef {
            return kdkAuthenticationCode();
        });
    }
}

cc7::ByteRange SecretKeysV4::keyAuthenticationCodeBiometry()
{
    checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_ACTIVE, true);
    
    if (!_has_biometry) {
        throw Exception(EC_BiometryNotAllowed);
    }
    if (_pool.isSet(CKEY_AUTHENTICATION_BIOMETRY)) {
        // Encrypted key is set, so try to decrypt key
        return _pool.getKey(KEY_AUTHENTICATION_BIOMETRY, uke_decrypt, [this]() -> KT::UKEKeys {
            return {
                _pool.getKey(KEK_AUTHENTICATION_BIOMETRY, default_input),   // KEK
                _pool.getKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypted)   // encrypted factor key
            };
        });
    } else {
        // Not set, try to derive
        static const KT::KDF derive { "auth/biometry" };
        return _pool.getKey(KEY_AUTHENTICATION_BIOMETRY, derive, [this]() -> KT::KeyRef {
            return kdkAuthenticationCode();
        });
    }
}

cc7::ByteRange SecretKeysV4::ckeyAuthenticationCodePossession()
{
    return _pool.getKey(CKEY_AUTHENTICATION_POSSESSION, uke_encrypt, [this]() -> KT::UKEKeys {
        return {
            kekAuthenticationCodePossession(),                              // KEK
            keyAuthenticationCodePossession()                               // factor key
        };
    });
}

cc7::ByteRange SecretKeysV4::ckeyAuthenticationCodeKnowledge()
{
    return _pool.getKey(CKEY_AUTHENTICATION_KNOWLEDGE, uke_encrypt, [this]() -> KT::UKEKeys {
        return {
            kekAuthenticationCodeKnowledge(),                               // KEK
            keyAuthenticationCodeKnowledge()                                // factor key
        };
    });
}

cc7::ByteRange SecretKeysV4::ckeyAuthenticationCodeBiometry()
{
    if (_pool.isSet(KEK_AUTHENTICATION_BIOMETRY)) {
        // has biometry KEK set, so factor is important
        return _pool.getKey(CKEY_AUTHENTICATION_BIOMETRY, uke_encrypt, [this]() -> KT::UKEKeys {
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

void SecretKeysV4::updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_key,
                                                        const cc7::ByteRange& new_kek)
{
    checkAccessLevel(KEY_AUTHENTICATION_KNOWLEDGE, AL_ACTIVE, true);
    
    // cleanup
    _pool.clearKey(CKEY_AUTHENTICATION_KNOWLEDGE);
    _pool.clearKey(KEY_AUTHENTICATION_KNOWLEDGE);
    _pool.clearKey(KEK_AUTHENTICATION_KNOWLEDGE);
    _pool.clearKey(IN_PASSWORD);
    _pool.clearKey(IN_PASSWORD_SALT);
    
    // new key
    _pool.setKey(KEY_AUTHENTICATION_KNOWLEDGE, default_input, new_key);   // factor key
    setupNewPassword(new_kek);
    
    _knowledge_key_update = true;
}

void SecretKeysV4::updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_key,
                                                       const cc7::ByteRange& new_kek)
{
    checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_ACTIVE, false);
    
    // cleanup
    _pool.clearKey(CKEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEK_AUTHENTICATION_BIOMETRY);

    // new key
    _pool.setKey(KEY_AUTHENTICATION_BIOMETRY, default_input, new_key);    // factor key
    _pool.setKey(KEK_AUTHENTICATION_BIOMETRY, default_input, new_kek);    // kek
    
    _biometry_key_update = true;
    _has_biometry = true;
    _has_credentials = true;
}

void SecretKeysV4::removeKeyAuthenticationCodeBiometry()
{
    checkAccessLevel(KEY_AUTHENTICATION_BIOMETRY, AL_ACTIVE);
    
    _pool.clearKey(CKEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEY_AUTHENTICATION_BIOMETRY);
    _pool.clearKey(KEK_AUTHENTICATION_BIOMETRY);
    
    _biometry_key_update = true;
    _has_biometry = false;
}

bool SecretKeysV4::isAuthenticationCodeKnowledgeUpdated() const noexcept
{
    return _knowledge_key_update;
}

bool SecretKeysV4::isAuthenticationCodeBiometryUpdated() const noexcept
{
    return _biometry_key_update;
}

cc7::ByteRange SecretKeysV4::getInputData(KeyId key_id)
{
    return _pool.getKey(key_id, any_input);
}

// MARK: - Encryption

cc7::ByteRange SecretKeysV4::kdkEncryption()
{
    if (_pool.isSet(CKDK_ENCRYPTION)) {
        // CKEY is set, try to decrypt
        static const KT::AEAD decrypt { KT::DECRYPT, "enc/kdk-encryption" };
        return _pool.getKey(KDK_ENCRYPTION, decrypt, [this]() -> KT::AEADKeys {
            return {
                keyLocalData(),                                         // key - must be set
                _pool.getKey(CKDK_ENCRYPTION, aead_generic_encrypted),  // data - is set
                _pool.getKey(IN_ACTIVATION_ID, any_input)
            };
        });
    } else {
        // CKEY is not set, try to derive
        static const KT::KDF derive { "enc" };
        return _pool.getKey(KDK_ENCRYPTION, derive, [this]() -> const KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV4::ckdkEncryption()
{
    static const KT::AEAD encrypt { KT::ENCRYPT, "enc/kdk-encryption" };
    return _pool.getKey(CKDK_ENCRYPTION, encrypt, [this]() -> KT::AEADKeys {
        return {
            keyLocalData(),                                             // key - must be set
            kdkEncryption(),                                            // data - can be derived
            _pool.getKey(IN_ACTIVATION_ID, any_input)
        };
    });
}

cc7::ByteRange SecretKeysV4::keyDeviceSpecific()
{
    static const KT::CUSTOM derive { v4::FACTOR_KEY_SIZE };
    return _pool.getKey(KEY_DEVICE_SPECIFIC, derive, [this]() -> KT::Key {
        auto data = _pool.getKey(IN_DEVICE_SPECIFIC_DATA, any_input);
        return algorithms().v4.sha3_256().digest(data);
    });
}

cc7::ByteRange SecretKeysV4::keyLocalData()
{
    static const KT::KDF derive { "enc/local" };
    return _pool.getKey(KEY_LOCAL_DATA, derive, [this]() -> KT::KeyRef {
        return keyDeviceSpecific();
    });
}

// MARK: - Vault

cc7::ByteRange SecretKeysV4::kdkVault()
{
    static const KT::KDF derive { "vault" };
    return _pool.getKey(KDK_VAULT, derive, [this]() -> KT::KeyRef {
        return keyActivationSecret();
    });
}
cc7::ByteRange SecretKeysV4::deriveKdkVault(int key_id, const common::KT::KDF& kdf)
{
    checkAccessLevel(key_id, AL_VAULT);
    return _pool.getKey(key_id, kdf, [this]() -> KT::KeyRef {
        return kdkVault();
    });
}

cc7::ByteRange SecretKeysV4::kekDevicePrivate()
{
    static const KT::KDF derive { "vault/kek-device-private" };
    return deriveKdkVault(KEK_DEVICE_PRIVATE, derive);
}

cc7::ByteRange SecretKeysV4::kdkAppVaultKnowledge()
{
    static const KT::KDF derive { "vault/kdk-app-vault-knowledge" };
    return deriveKdkVault(KDK_APP_VAULT_KNOWLEDGE, derive);
}

cc7::ByteRange SecretKeysV4::kdkAppVault2FA()
{
    static const KT::KDF derive { "vault/kdk-app-vault-2fa" };
    return deriveKdkVault(KDK_APP_VAULT_2FA, derive);
}

// MARK: - Utility

cc7::ByteRange SecretKeysV4::kdkUtility()
{
    if (_pool.isSet(CKDK_UTILITY)) {
        // CKEY is set, try to decrypt
        static const KT::AEAD decrypt { KT::DECRYPT, "enc/kdk-utility" };
        return _pool.getKey(KDK_ENCRYPTION, decrypt, [this]() -> KT::AEADKeys {
            return {
                keyLocalData(),                                         // key - always available
                _pool.getKey(CKDK_UTILITY, aead_generic_encrypted),     // data - is set
                _pool.getKey(IN_ACTIVATION_ID, any_input)               // aad
            };
        });
    } else {
        // CKEY is not set, try to derive
        static const KT::KDF derive { "util" };
        return _pool.getKey(KDK_UTILITY, derive, [this]() -> KT::KeyRef {
            return keyActivationSecret();
        });
    }
}

cc7::ByteRange SecretKeysV4::ckdkUtility()
{
    static const KT::AEAD encrypt { KT::ENCRYPT, "enc/kdk-utility" };
    return _pool.getKey(CKDK_UTILITY, encrypt, [this]() -> KT::AEADKeys {
        return {
            keyLocalData(),                                             // key - always available
            kdkUtility(),                                               // data - can be derived
            _pool.getKey(IN_ACTIVATION_ID, any_input)                   // aad
        };
    });
}

cc7::ByteRange SecretKeysV4::deriveKdkUtility(int key_id, const common::KT::KDF& kdf)
{
    return _pool.getKey(key_id, kdf, [this]() -> KT::KeyRef {
        return kdkUtility();
    });
}

cc7::ByteRange SecretKeysV4::keyMacCtrData()
{
    static const KT::KDF derive { "util/mac/ctr-data" };
    return deriveKdkUtility(KEY_MAC_CTR_DATA, derive);
}

cc7::ByteRange SecretKeysV4::keyMacStatus()
{
    static const KT::KDF derive { "util/mac/status" };
    return deriveKdkUtility(KEY_MAC_STATUS, derive);
}

cc7::ByteRange SecretKeysV4::keyMacGetAppTempKey()
{
    static const KT::KDF derive { "util/mac/get-app-temp-key" };
    return _pool.getKey(KEY_MAC_GET_APP_TEMP_KEY, derive, [this]() -> KT::KeyRef {
        return _pool.getKey(IN_APP_SECRET, input_16);
    });
}

cc7::ByteRange SecretKeysV4::keyMacGetActTempKey()
{
    static const KT::KDF derive { "util/mac/get-act-temp-key" };
    return deriveKdkUtility(KEY_MAC_GET_ACT_TEMP_KEY, derive);
}

cc7::ByteRange SecretKeysV4::keyMacPersonalizedData()
{
    static const KT::KDF derive { "util/mac/personalized-data" };
    return deriveKdkUtility(KEY_MAC_PERSONALIZED_DATA, derive);
}

cc7::ByteRange SecretKeysV4::keyE2EESharedInfo2()
{
    static const KT::KDF derive { "util/key-e2ee-sh2" };
    return deriveKdkUtility(KEY_E2EE_SHARED_INFO2, derive);
}

cc7::ByteRange SecretKeysV4::kdkAppUtility()
{
    static const KT::KDF derive { "util/app" };
    checkAccessLevel(KDK_APP_UTILITY, AL_ACTIVE);
    return deriveKdkUtility(KDK_APP_UTILITY, derive);
}


// MARK: - Other

cc7::ByteRange SecretKeysV4::keyActivationSecret()
{
    return _pool.getKey(KEY_SHARED_SECRET, default_input);
}

const cc7::crypto::PrivateKey& SecretKeysV4::devicePrivateKey()
{
    checkAccessLevel(KEK_DEVICE_PRIVATE, AL_VAULT);
    if (!_device_private) {
        auto key = cc7::crypto::SymmetricKey::getInstance(kekDevicePrivate());
        key->setKeyContext(MakeRange("enc/kek-device-private"));
        auto key_data = algorithms().v4.aead().open(*key,
                                                    _pool.getKey(IN_ACTIVATION_ID, any_input),
                                                    _pool.getKey(CKEY_DEVICE_PRIVATE, any_input));
        _device_private = _owner->signingKeyFactory().newPrivateKey(key_data);
    }
    return *_device_private;
}

cc7::ByteRange SecretKeysV4::ckeyDevicePrivate()
{
    static const KT::AEAD encrypt { KT::ENCRYPT, "enc/kek-device-private" };
    return _pool.getKey(CKEY_DEVICE_PRIVATE, encrypt, [this]() -> KT::AEADKeys {
        if (!_device_private) {
            throw Exception(EC_NotAllowed, "Device private key is not set");
        }
        return {
            kekDevicePrivate(),
            _device_private->exportKey(crypto::KEY_FORMAT_DEFAULT),
            _pool.getKey(IN_ACTIVATION_ID, any_input)
        };
    });
}


// MARK: - Legacy

cc7::ByteRange SecretKeysV4::legacyKeyTransport()
{
    throwNotSupported();
}
cc7::ByteRange SecretKeysV4::legacyKeyTransportIV()
{
    throwNotSupported();
}

// MARK: - Private

void SecretKeysV4::setupCreationMode(CreationMode mode)
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

void SecretKeysV4::checkAccessLevel(int key_id, AccessLevel al, bool with_credentials) const
{
    if (al > _access_level) {
        throw Exception(EC_NotAllowed, "Access to key " + keyNameResolver(key_id) + " is denied");
    }
    if (with_credentials && !_has_credentials) {
        throw Exception(EC_NotAllowed, "Access to key " + keyNameResolver(key_id) + " require user credentials");
    }
}

void SecretKeysV4::throwNotSupported()
{
    throw Exception(EC_NotAllowed, "V3 key not available");
}

std::string SecretKeysV4::keyNameResolver(int key_id) noexcept
{
#if DEBUG
    switch (key_id) {
            // Input keys
        case KEY_SHARED_SECRET: return "KEY_SHARED_SECRET";
        case KEK_AUTHENTICATION_KNOWLEDGE: return "KEK_AUTHENTICATION_KNOWLEDGE";
        case KEK_AUTHENTICATION_BIOMETRY: return "KEK_AUTHENTICATION_BIOMETRY";
        case CKEY_AUTHENTICATION_POSSESSION: return "CKEY_AUTHENTICATION_POSSESSION";
        case CKEY_AUTHENTICATION_KNOWLEDGE: return "CKEY_AUTHENTICATION_KNOWLEDGE";
        case CKEY_AUTHENTICATION_BIOMETRY: return "CKEY_AUTHENTICATION_BIOMETRY";
        case CKDK_UTILITY: return "CKDK_UTILITY";
        case CKDK_ENCRYPTION: return "CKDK_ENCRYPTION";
        case CKEY_DEVICE_PRIVATE: return "CKEY_DEVICE_PRIVATE";
        case IN_DEVICE_SPECIFIC_DATA: return "IN_DEVICE_SPECIFIC_DATA";
        case IN_PASSWORD: return "IN_PASSWORD";
        case IN_PASSWORD_SALT: return "IN_PASSWORD_SALT";
        case IN_ACTIVATION_ID: return "IN_ACTIVATION_ID";
        case IN_APP_SECRET: return "IN_APP_SECRET";
        case KEY_AUTHENTICATION_POSSESSION: return "KEY_AUTHENTICATION_POSSESSION";
        case KEY_AUTHENTICATION_KNOWLEDGE: return "KEY_AUTHENTICATION_KNOWLEDGE";
        case KEY_AUTHENTICATION_BIOMETRY: return "KEY_AUTHENTICATION_BIOMETRY";
        case KEK_DEVICE_PRIVATE: return "KEK_DEVICE_PRIVATE";
        case KDK_APP_VAULT_KNOWLEDGE: return "KDK_APP_VAULT_KNOWLEDGE";
        case KDK_APP_VAULT_2FA: return "KDK_APP_VAULT_2FA";
        case KDK_VAULT: return "KDK_VAULT";
        case KDK_AUTHENTICATION_CODE: return "KDK_AUTHENTICATION_CODE";
        case KDK_UTILITY: return "KDK_UTILITY";
        case KDK_ENCRYPTION: return "KDK_ENCRYPTION";
        case KDK_APP_UTILITY: return "KDK_APP_UTILITY";
        case KEY_MAC_CTR_DATA: return "KEY_MAC_CTR_DATA";
        case KEY_MAC_STATUS: return "KEY_MAC_STATUS";
        case KEY_MAC_GET_APP_TEMP_KEY: return "KEY_MAC_GET_APP_TEMP_KEY";
        case KEY_MAC_GET_ACT_TEMP_KEY: return "KEY_MAC_GET_ACT_TEMP_KEY";
        case KEY_MAC_PERSONALIZED_DATA: return "KEY_MAC_PERSONALIZED_DATA";
        case KEY_E2EE_SHARED_INFO2: return "KEY_E2EE_SHARED_INFO2";
        case KEK_AUTHENTICATION_POSSESSION: return "KEK_AUTHENTICATION_POSSESSION";
        case KEY_LOCAL_DATA: return "KEY_LOCAL_DATA";
        case KEY_DEVICE_SPECIFIC: return "KEY_DEVICE_SPECIFIC";
        default:
            break;
    }
#endif
    return "#" + std::to_string(key_id);
}

} // namespace v4
} // namespace powerAuth
