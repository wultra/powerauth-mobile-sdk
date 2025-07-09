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
#include "HybridKeyPair.h"
#include "SecretKeysV4.h"
#include "../Context.h"

namespace powerAuth {
namespace v4 {

class KeyProviderV4 :
    public Service,
    public IKeyProvider,
    public std::enable_shared_from_this<KeyProviderV4>
{
public:
    KeyProviderV4(const ContextPtr& context);
    
    // IKeyProvider
    IServicePtr asService() override;
    ProtocolVersion protocolVersion() const noexcept override;
    
    cc7::crypto::ConstPublicKeyPtr getMasterServerPublicKeyPtr() override;
    cc7::crypto::ConstPublicKeyPtr getDevicePublicKeyPtr() override;
    cc7::crypto::ConstPublicKeyPtr getServerPublicKeyPtr() override;
    void clearActivationKeys() noexcept override;
    
    ISecretKeysPtr unlockInitialSecretKeys(const InitialCredentials &credentials, const cc7::ByteArray &shared_secret) override;
    ISecretKeysPtr unlockSecretKeys() override;
    ISecretKeysPtr unlockSecretKeys(const Credentials &credentials) override;
    ISecretKeysPtr unlockVaultAndSecretKeys(const Credentials &credentials,
                                            VaultKeyType vault_key_type,
                                            const cc7::ByteRange &vault_key) override;
    
    void lockSecretKeys(ISecretKeysPtr &secret_keys) override;

    // IService
    void clearSensitiveData() override;
    void restoreSensitiveData() override;
    
    // Custom methods

    void safeReleaseSecretKeys(const SecretKeysV4& secret_keys, cc7::U64 instance_token);
    
    const Configuration& configuration() const;
    const cc7::crypto::KeyPairFactory& signingKeyFactory();
    
protected:
    void doServiceDestroy() override;
    
private:

    const ConfigurationPtr _configuration;
    const SessionDataPtr _session_data;
    const cc7::crypto::KeyPairFactoryPtr _signing_key_factory;
    
    ConstPowerAuthSpecPtr _specification;
    
    bool     _sec_key_created;
    cc7::U64 _sec_key_token;
    
    cc7::ByteArray _local_data_key;
    cc7::crypto::PublicKeyPtr _master_server_public_key;
    cc7::crypto::PublicKeyPtr _device_public_key;
    cc7::crypto::PublicKeyPtr _server_public_key;
    
    std::shared_ptr<HybridKeyPairFactory> _key_pair_factory;
    
    HybridKeyPairFactory& getKeyPairFactory();
    
    std::unique_ptr<SecretKeysV4> createSecretKeys();
    std::unique_ptr<PersistentData> createPDFromSecretKeys(SecretKeysV4& secret_keys);
    void updateSessionData(SecretKeysV4& secret_keys);
    
    cc7::crypto::PublicKeyPtr decryptPublicKey(const cc7::ByteRange& key_data, const std::string& aead_kc);
    cc7::ByteArray encryptPublicKey(const cc7::crypto::PublicKey& public_key, const std::string& aead_kc, const std::string& activation_id);
    void updateKeyLocalData(SecretKeysV4 * secret_keys);
    
    cc7::crypto::SymmetricKeyPtr getKekForPublicKey(const std::string& key_context);
};

} // namespace v4
} // namespace powerAuth
