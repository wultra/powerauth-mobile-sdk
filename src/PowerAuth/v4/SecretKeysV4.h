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

#include <PowerAuth/KeyProvider.h>
#include "../common/SecretKeysPool.h"
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class KeyProviderV4;

class SecretKeysV4 : public ISecretKeys
{
public:
    
    enum KeyId
    {
        // Input keys
        KEY_SHARED_SECRET,
        
        KEK_AUTHENTICATION_KNOWLEDGE,
        KEK_AUTHENTICATION_BIOMETRY,
        
        CKEY_AUTHENTICATION_POSSESSION, // UKE (48 = 16+32)
        CKEY_AUTHENTICATION_KNOWLEDGE,  // UKE (48 = 16+32)
        CKEY_AUTHENTICATION_BIOMETRY,   // UKE (48 = 16+32)
        
        CKDK_UTILITY,                   // AEAD (80 = 16+32+32)
        CKDK_ENCRYPTION,                // AEAD (80 = 16+32+32)
        CKEY_DEVICE_PRIVATE,            // AEAD variable size
        
        IN_DEVICE_SPECIFIC_DATA,        // any data
        IN_PASSWORD,                    // any data
        IN_PASSWORD_SALT,               // 32 bytes
        IN_ACTIVATION_ID,               // activation-ID (UUID)
        IN_APP_SECRET,                  // app secret    (16B)
        
        // Keys below this marker are input keys

        KID_INPUT,
        
        // Input or derived keys
        
        KEY_AUTHENTICATION_POSSESSION = KID_INPUT,
        KEY_AUTHENTICATION_KNOWLEDGE,
        KEY_AUTHENTICATION_BIOMETRY,
        
        KEK_DEVICE_PRIVATE,
        KDK_APP_VAULT_KNOWLEDGE,
        KDK_APP_VAULT_2FA,
        
        // Keys below this marker can be set at input, or derived if
        // appropriate source key is available
        KID_INPUT_OUTPUT,
        
        // Derived only keys
        KDK_VAULT = KID_INPUT_OUTPUT,
        KDK_AUTHENTICATION_CODE,
        KDK_UTILITY,
        KDK_ENCRYPTION,
        KDK_APP_UTILITY,
        KEY_MAC_CTR_DATA,
        KEY_MAC_STATUS,
        KEY_MAC_GET_APP_TEMP_KEY,
        KEY_MAC_GET_ACT_TEMP_KEY,
        KEY_MAC_PERSONALIZED_DATA,
        KEY_E2EE_SHARED_INFO2,
                
        // Encryption
        KEK_AUTHENTICATION_POSSESSION,
        KEY_LOCAL_DATA,
        KEY_DEVICE_SPECIFIC,

        // Number of keys
        KID_COUNT
    };
    
    enum CreationMode
    {
        CM_BASIC,
        CM_FACTORS,
        CM_INITIAL,
        CM_ACTIVE,
        CM_VAULT
    };
    
    enum AccessLevel
    {
        /// Basic access level to "application scoped" keys
        AL_BASIC,
        /// Access to utility keys and generic keys publicly available for the application.
        AL_ACTIVE,
        /// Access to vault keys
        AL_VAULT,
    };
    
    enum FactorMask
    {
        FM_NONE       = 0x000,
        FM_POSSESSION = 0x001,
        FM_KNOWLEDGE  = 0x010,
        FM_BIOMETRY   = 0x100,
    };
    
    ProtocolVersion protocolVersion() const noexcept override;
    
    // Authentication
    cc7::ByteRange kdkAuthenticationCode();
    cc7::ByteRange kekAuthenticationCodePossession();
    cc7::ByteRange kekAuthenticationCodeKnowledge();

    cc7::ByteRange keyAuthenticationCodePossession() override;
    cc7::ByteRange keyAuthenticationCodeKnowledge() override;
    cc7::ByteRange keyAuthenticationCodeBiometry() override;

    cc7::ByteRange ckeyAuthenticationCodePossession();
    cc7::ByteRange ckeyAuthenticationCodeKnowledge();
    cc7::ByteRange ckeyAuthenticationCodeBiometry();

    void updateKeyAuthenticationCodeKnowledge(const cc7::ByteRange& new_key,
                                              const cc7::ByteRange& new_kek) override;
    void updateKeyAuthenticationCodeBiometry(const cc7::ByteRange& new_key,
                                             const cc7::ByteRange& new_kek) override;
    void removeKeyAuthenticationCodeBiometry() override;
    
    
    // Encryption
    cc7::ByteRange kdkEncryption();
    cc7::ByteRange ckdkEncryption();
    cc7::ByteRange keyDeviceSpecific() override;
    cc7::ByteRange keyLocalData() override;

    // Vault
    cc7::ByteRange kdkVault();
    cc7::ByteRange kekDevicePrivate() override;
    cc7::ByteRange kdkAppVaultKnowledge() override;
    cc7::ByteRange kdkAppVault2FA() override;
    
    // Utility
    cc7::ByteRange kdkUtility();
    cc7::ByteRange ckdkUtility();
    
    cc7::ByteRange keyMacCtrData() override;
    cc7::ByteRange keyMacStatus() override;
    
    cc7::ByteRange keyMacGetAppTempKey() override;
    cc7::ByteRange keyMacGetActTempKey() override;
    cc7::ByteRange keyMacPersonalizedData() override;
    cc7::ByteRange keyE2EESharedInfo2() override;
    cc7::ByteRange kdkAppUtility() override;
    
    // Other
    cc7::ByteRange keyActivationSecret();
    const cc7::crypto::PrivateKeyPtr& getDevicePrivateKeyPtr() override;
    
    // Legacy
    cc7::ByteRange legacyKeyTransport() override;
    cc7::ByteRange legacyKeyTransportIV() override;
    
    // Construction
    
    SecretKeysV4(std::shared_ptr<KeyProviderV4> owner, cc7::U64 instance_token);
    ~SecretKeysV4();

    void loadSessionData(const SessionData& session_data);
    
    void loadInitialCredentials(const SessionData& session_data,
                                const InitialCredentials& credentials,
                                const cc7::ByteRange& shared_secret);
    
    void loadFactors(const SessionData& session_data,
                     AuthFactors factors);
    
    void loadCredentials(const SessionData& session_data,
                         const Credentials& credentials);

    void loadVaultKey(const SessionData& session_data,
                      VaultKeyType key_type,
                      const cc7::ByteRange& key_data);
    
    void loadCredentialsWithVaultKey(const SessionData& session_data,
                                     const Credentials& credentials,
                                     VaultKeyType key_type,
                                     const cc7::ByteRange& key_data);
    
    CreationMode setReturned(cc7::U64 instance_token);
    
    // Custom getters
    
    cc7::ByteRange ckeyDevicePrivate();
    
    bool isAuthenticationCodeKnowledgeUpdated() const noexcept;
    bool isAuthenticationCodeBiometryUpdated() const noexcept;
    
    cc7::ByteRange getInputData(KeyId key_id);
    
private:
    const std::shared_ptr<KeyProviderV4> _owner;

    // State variables
    cc7::U64 _instance_token;
    CreationMode _creation_mode = CM_BASIC;
    AccessLevel _access_level = AL_BASIC;
    int  _factors = FM_POSSESSION;
    bool _loaded = false;
    bool _has_activation = false;
    bool _has_biometry = false;
    bool _allow_knowledge = false;
    bool _knowledge_key_update = false;
    bool _biometry_key_update = false;

    // Keys
    common::SecretKeysPool _pool;
    cc7::crypto::PrivateKeyPtr _device_private;

    void setupCreationMode(CreationMode mode);
    void checkAccessLevel(int key_id, AccessLevel al, FactorMask fm = FM_NONE) const;
    
    void setupSessionData(const SessionData& session_data);
    void setupCredentials(const SessionData& session_data, const Credentials& credentials);
    void setupVaultKey(VaultKeyType key_type, const cc7::ByteRange& key_data);
    
    cc7::ByteRange deriveKdkUtility(int key_id, const common::KT::KDF& kdf);
    cc7::ByteRange deriveKdkVault(int key_id, const common::KT::KDF& kdf);
    void setupNewPassword(const cc7::ByteRange& password);
    
    // constants
    static const common::KT::INPUT any_input;
    static const common::KT::INPUT default_input;
    static const common::KT::INPUT input_16;
    static const common::KT::INPUT uke_plain;
    static const common::KT::INPUT uke_encrypted;
    static const common::KT::INPUT aead_generic_plain;
    static const common::KT::INPUT aead_generic_encrypted;
    
    static const common::KT::UKE   uke_encrypt;
    static const common::KT::UKE   uke_decrypt;
    
    // static functions
    
    static void throwNotSupported [[noreturn]] ();
    
    static std::string keyNameResolver(int key_id) noexcept;
};


} // namespace v4
} // namespace powerAuth
