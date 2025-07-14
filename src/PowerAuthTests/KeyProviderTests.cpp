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

#include <cc7tests/CC7Tests.h>
#include <PowerAuth/KeyProvider.h>
#include "ConfigurationGenerator.h"
#include "../PowerAuth/Context.h"
#include "../PowerAuth/v4/SecretKeysV4.h"
#include "../PowerAuth/v4/HybridKeyPair.h"
#include "../PowerAuth/v4/PowerAuthKDF.h"
#include "../PowerAuth/v4/PowerAuthUKE.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

class KeyProviderTests : public UnitTest
{
public:
    
    KeyProviderTests()
    {
        CC7_REGISTER_TEST_METHOD(test_EC_P384)
        CC7_REGISTER_TEST_METHOD(test_EC_P384_Bio)
        CC7_REGISTER_TEST_METHOD(test_EC_P384_ML_L3)
        CC7_REGISTER_TEST_METHOD(test_EC_P384_ML_L3_Bio)
    }

    std::unique_ptr<ConfigurationGenerator> configGenerator;
    ContextPtr context;
    bool has_biometry = false;
    cc7::ByteArray kek_possession;
    
    cc7::ByteArray kek_biometry;
    cc7::ByteArray key_biometry;
    cc7::ByteArray kek_biometry_new;
    cc7::ByteArray key_biometry_new;
    
    cc7::ByteArray key_knowledge;
    cc7::ByteArray kek_knowledge;
    cc7::ByteArray kek_knowledge_bad;
    cc7::ByteArray kek_knowledge_new;
    cc7::ByteArray key_knowledge_new;
    
    cc7::ByteArray shared_secret;
    cc7::ByteArray device_key;
    
    cc7::crypto::PrivateKeyPtr master_server_hybrid;
    cc7::crypto::KeyPairPtr device_key_pair;
    cc7::crypto::PublicKeyPtr device_key1;
    cc7::crypto::PublicKeyPtr device_key2;

    cc7::crypto::KeyPairPtr server_key_pair;
    cc7::crypto::PublicKeyPtr server_key1;
    cc7::crypto::PublicKeyPtr server_key2;
    
    // keys important between test steps
    cc7::ByteArray keyAuthenticationCodePossession;
    cc7::ByteArray keyAuthenticationCodeKnowledge;
    cc7::ByteArray keyAuthenticationCodeBiometry;
    cc7::ByteArray kekDevicePrivate;
    cc7::ByteArray kdkAppVaultKnowledge;
    cc7::ByteArray kdkAppVault2FA;
    cc7::ByteArray kdkEncryption;
    cc7::ByteArray kdkUtility;
    
    void setUp(PowerAuthSpec::Algorithm algorithm, bool use_biometry)
    {        
        has_biometry = use_biometry;
        configGenerator = std::make_unique<ConfigurationGenerator>(algorithm);
        context = Context::getInstance(algorithm, configGenerator->configuration);

        shared_secret  = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);
        device_key     = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);

        kek_possession = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);
        kek_biometry   = use_biometry ? cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE) : ByteArray();
        kek_knowledge  = cc7::MakeRange("Hello World");
        
        kek_biometry_new  = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);
        key_biometry_new  = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);
        
        kek_knowledge_new = cc7::MakeRange("fifty.shadows.42");
        key_knowledge_new = cc7::crypto::GetRandomData(v4::FACTOR_KEY_SIZE);
        kek_knowledge_bad = cc7::MakeRange("nbusr123");
                
        key_knowledge  = V4_KDF(shared_secret, { "auth", "auth/knowledge" });
        key_biometry   = V4_KDF(shared_secret, { "auth", "auth/biometry" });

        device_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        device_key1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(device_key_pair->getPublicKey().getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
        device_key2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(device_key_pair->getPublicKey().getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
        
        server_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        server_key1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(server_key_pair->getPublicKey().getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
        server_key2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(server_key_pair->getPublicKey().getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
    }
    
    // getters
    
    const Configuration& configuration() const
    {
        return context->configuration();
    }
    
    IKeyProvider& keyProvider()
    {
        return context->keyProvider();
    }
    
    PowerAuthSpecPtr spec()
    {
        return context->specification();
    }
    
    SessionData& sessionData()
    {
        return context->sessionData();
    }
    
    bool hasActivation()
    {
        return context->sessionData().hasPersistentData();
    }
    
    bool hasPendingActivation()
    {
        return context->sessionData().hasRegistrationData();
    }
        
    void test_EC_P384_Bio()
    {
        setUp(PowerAuthSpec::EC_P384, true);
        testKeyProviderV4();
    }
    
    void test_EC_P384()
    {
        setUp(PowerAuthSpec::EC_P384, false);
        testKeyProviderV4();
    }
    
    void test_EC_P384_ML_L3_Bio()
    {
        setUp(PowerAuthSpec::EC_P384_ML_L3, true);
        testKeyProviderV4();
    }
    
    void test_EC_P384_ML_L3()
    {
        setUp(PowerAuthSpec::EC_P384_ML_L3, false);
        testKeyProviderV4();
    }

    void testKeyProviderV4()
    {
        testPublicKeysV4();
        testBasicUnlockedKeysV4();
        
        // pending activation
        createRegistrationDataV4();
        
        testPublicKeysV4();
        testBasicUnlockedKeysV4();
        
        // activation commit
        testInitialCredentialsV4();
        
        testPublicKeysV4();
        testBasicUnlockedKeysV4();
        testCredentialsV4();
        testChangeCredentialsV4();
        testCredentialsV4();
        
        // serialize and deserialize state
        auto serialized = context->sessionData().serialize();
        context->sessionData().resetSessionData();
        context->sessionData().deserialize(serialized);
        
        testCredentialsV4();
    }
    
    void testPublicKeysV4()
    {
        const auto& key = keyProvider().masterServerPublicKey();
        auto key1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
        auto signer1 = cc7::crypto::Signature::getInstance(spec()->getSignatureAlgorithms().first);
        testSigning(*signer1, *key1, configGenerator->ecdsaMasterKeyPair->getPrivateKey());
        if (spec()->isHybrid()) {
            auto key2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
            auto signer2 = cc7::crypto::Signature::getInstance(spec()->getSignatureAlgorithms().second);
            testSigning(*signer2, *key2, configGenerator->mldsaMasterKeyPair->getPrivateKey());
        }
        if (!hasActivation() && !hasPendingActivation()) {
            ccstMustThrow(powerAuth::Exception, keyProvider().getDevicePublicKeyPtr());
            ccstMustThrow(powerAuth::Exception, keyProvider().getServerPublicKeyPtr());
        }
        if (hasActivation() || hasPendingActivation()) {
            const auto& device_pubk = keyProvider().devicePublicKey();
            testHybridSigning(device_pubk, device_key_pair->getPrivateKey());
            const auto& server_pubk = keyProvider().serverPublicKey();
            testHybridSigning(server_pubk, server_key_pair->getPrivateKey());
        }
    }
    
    void createRegistrationDataV4()
    {
        auto rd = RegistrationData::create(Version_V4);
        rd->v4() = {
            cc7::crypto::GetRandomData(16).base64(),
            cc7::crypto::GetRandomData(v4::HASH_COUNTER_SIZE),  // hash counter
            server_key1->exportKey(),                                           // server ecdsa (direct key data)
            server_key2 != nullptr ? server_key2->exportKey() : ByteArray(),    // server mldsa (direct key data)
            device_key_pair,                                                    // device pair
            server_key_pair->getPublicKeyPtr()                                  // server public
        };
        rd->v4().calculatedSharedSecret = shared_secret;
        sessionData().setRegistrationData(rd);
    }
    
    void testBasicUnlockedKeysV4()
    {
        auto secrets = keyProvider().unlockSecretKeys();
        ccstAssertNotNull(secrets);
        {
            // always available keys
            verifyBasicKeysV4(secrets);
            
            if (hasActivation()) {
                // has activation. Access level is equal to possession only factor
                verifyFactorKeysV4(secrets, true, false, false);
                verifyUtilityKeysV4(secrets, true);
                verifyVaultKeysV4(secrets, false);

            } else if (hasPendingActivation()) {
                // has pending activation, factor keys unavailable, public utility keys unavailable
                verifyFactorKeysV4(secrets, false, false, false);
                verifyUtilityKeysV4(secrets, false);
                verifyVaultKeysV4(secrets, false);
                
                ccstMustThrow(Exception, secrets->updateKeyAuthenticationCodeBiometry(key_biometry_new, kek_biometry_new));
                ccstMustThrow(Exception, secrets->updateKeyAuthenticationCodeKnowledge(key_knowledge_new, kek_knowledge_new));
                ccstMustThrow(Exception, secrets->removeKeyAuthenticationCodeBiometry());
            } else {
                ccstMustThrow(Exception, secrets->updateKeyAuthenticationCodeBiometry(key_biometry_new, kek_biometry_new));
                ccstMustThrow(Exception, secrets->updateKeyAuthenticationCodeKnowledge(key_knowledge_new, kek_knowledge_new));
                ccstMustThrow(Exception, secrets->removeKeyAuthenticationCodeBiometry());
            }
        }
        // return keys back to provider
        keyProvider().lockSecretKeys(secrets);
        ccstAssertNull(secrets);
    }
    
    void testInitialCredentialsV4()
    {
        auto creds = has_biometry ? InitialCredentials::credentials(kek_knowledge, kek_biometry)
                                  : InitialCredentials::credentials(kek_knowledge);
        auto secrets = keyProvider().unlockInitialSecretKeys(*creds, shared_secret);
        {
            ccstAssertNotNull(secrets);
            auto typed_secrets = dynamic_cast<v4::SecretKeysV4*>(&(*secrets));
            ccstAssertNotNull(typed_secrets);
            
            // basic
            verifyBasicKeysV4(secrets);
            verifyUtilityKeysV4(secrets, true);
            verifyVaultKeysV4(secrets, true);
            verifyFactorKeysV4(secrets, true, true, has_biometry);
            
            // capture important keys
            keyAuthenticationCodePossession = secrets->keyAuthenticationCodePossession();
            keyAuthenticationCodeKnowledge = secrets->keyAuthenticationCodeKnowledge();
            keyAuthenticationCodeBiometry = has_biometry ? secrets->keyAuthenticationCodeBiometry() : ByteRange();
            
            kekDevicePrivate = secrets->kekDevicePrivate();
            kdkAppVaultKnowledge = secrets->kdkAppVaultKnowledge();
            kdkAppVault2FA = secrets->kdkAppVault2FA();
            kdkEncryption = typed_secrets->kdkEncryption();
            kdkUtility = typed_secrets->kdkUtility();
        }
        // return keys back to provider
        keyProvider().lockSecretKeys(secrets);
        ccstAssertNull(secrets);
    }
    
    void testCredentialsV4()
    {
        // possession
        auto secrets = keyProvider().unlockSecretKeys(*Credentials::possession());
        {
            verifyBasicKeysV4(secrets);
            verifyUtilityKeysV4(secrets, true);
            verifyVaultKeysV4(secrets, false);
            verifyFactorKeysV4(secrets, true, false, false);
            
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // knowledge (good)
        secrets = keyProvider().unlockSecretKeys(*Credentials::knowledge(kek_knowledge));
        {
            verifyBasicKeysV4(secrets);
            verifyUtilityKeysV4(secrets, true);
            verifyVaultKeysV4(secrets, false);
            verifyFactorKeysV4(secrets, true, true, false);
    
            ccstAssertEqual(V4_KDF(shared_secret, { "auth", "auth/possession" }), keyAuthenticationCodePossession);
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
            ccstAssertEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // knowledge (bad)
        secrets = keyProvider().unlockSecretKeys(*Credentials::knowledge(kek_knowledge_bad));
        {
            ccstAssertEqual(V4_KDF(shared_secret, { "auth", "auth/possession" }), keyAuthenticationCodePossession);
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
            ccstAssertNotEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // biometry (good)
        if (has_biometry) {
            secrets = keyProvider().unlockSecretKeys(*Credentials::biometry(kek_biometry));
            {
                verifyBasicKeysV4(secrets);
                verifyUtilityKeysV4(secrets, true);
                verifyVaultKeysV4(secrets, false);
                verifyFactorKeysV4(secrets, true, false, true);
                
                ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
                ccstAssertEqual(keyAuthenticationCodeBiometry, secrets->keyAuthenticationCodeBiometry());
            }
            keyProvider().lockSecretKeys(secrets);
        }
        
        // biometry (bad)
        if (has_biometry) {
            secrets = keyProvider().unlockSecretKeys(*Credentials::biometry(kek_possession));
            {
                ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
                ccstAssertNotEqual(keyAuthenticationCodeBiometry, secrets->keyAuthenticationCodeBiometry());
            }
            keyProvider().lockSecretKeys(secrets);
        }
    }
    
    void testChangeCredentialsV4()
    {
        // change password
        
        // clear dirty flag
        auto serialized_before = context->sessionData().serialize();
        ccstAssertFalse(serialized_before.empty());
        ccstAssertFalse(context->sessionData().isModified());
        
        auto secrets = keyProvider().unlockSecretKeys();
        {
            secrets->updateKeyAuthenticationCodeKnowledge(key_knowledge_new, kek_knowledge_new);
            key_knowledge = keyAuthenticationCodeKnowledge = key_knowledge_new;
            kek_knowledge = kek_knowledge_new;
            ccstAssertEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // test dirty flag
        ccstAssertTrue(context->sessionData().isModified());
    }

    
    void verifyBasicKeysV4(ISecretKeysPtr & secrets)
    {
        auto keyDeviceSpecific = algorithms().v4.sha3_256().digest(configGenerator->deviceSpecificData);
        ccstAssertEqual(keyDeviceSpecific, secrets->keyDeviceSpecific());
        ccstAssertEqual(V4_KDF(keyDeviceSpecific, { "enc/local" }), secrets->keyLocalData());
        ccstAssertEqual(V4_KDF(configuration().applicationSecretBytes(), { "util/mac/get-app-temp-key" }), secrets->keyMacGetAppTempKey());
        
        // Legacy must throw
        ccstMustThrow(Exception, secrets->legacyKeyTransport());
        ccstMustThrow(Exception, secrets->legacyKeyTransportIV());
    }
        
    void verifyUtilityKeysV4(ISecretKeysPtr& secrets, bool public_available)
    {
        ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/mac/ctr-data" }), secrets->keyMacCtrData());
        ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/mac/status" }), secrets->keyMacStatus());
        ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/mac/get-act-temp-key" }), secrets->keyMacGetActTempKey());
        ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/mac/personalized-data" }), secrets->keyMacPersonalizedData());
        ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/key-e2ee-sh2" }), secrets->keyE2EESharedInfo2());
        if (public_available) {
            // keys exposed to application. Those suppose to be unavailable in pending activation
            ccstAssertEqual(V4_KDF(shared_secret, { "util", "util/app" }), secrets->kdkAppUtility());
        } else {
            ccstMustThrow(Exception, secrets->kdkAppUtility());
        }
    }
    
    void verifyVaultKeysV4(ISecretKeysPtr& secrets, bool initial, VaultKeyType type = VaultKeyType::LEGACY)
    {
        if (initial || type == VaultKeyType::KEK_DEVICE_PRIVATE) {
            ccstAssertEqual(V4_KDF(shared_secret, { "vault", "vault/kek-device-private" }), secrets->kekDevicePrivate());
            // try to use device private key
            const auto& device_private = secrets->devicePrivateKey();
            const auto& device_public = device_key_pair->getPublicKey();
            testHybridSigning(device_public, device_private);
        } else {
            ccstMustThrow(Exception, secrets->kekDevicePrivate());
            ccstMustThrow(Exception, secrets->devicePrivateKey());
        }
        if (initial || type == VaultKeyType::KDK_APP_VAULT_KNOWLEDGE) {
            ccstAssertEqual(V4_KDF(shared_secret, { "vault", "vault/kdk-app-vault-knowledge" }), secrets->kdkAppVaultKnowledge());
        } else {
            ccstMustThrow(Exception, secrets->kdkAppVaultKnowledge());
        }
        if (initial || type == VaultKeyType::KDK_APP_VAULT_2FA) {
            ccstAssertEqual(V4_KDF(shared_secret, { "vault", "vault/kdk-app-vault-2fa" }), secrets->kdkAppVault2FA());
        } else {
            ccstMustThrow(Exception, secrets->kdkAppVault2FA());
        }
    }
        
    void verifyFactorKeysV4(ISecretKeysPtr& secrets, bool is_possession, bool is_knowledge, bool is_biometry)
    {
        if (is_possession) {
            ccstAssertEqual(V4_KDF(shared_secret, { "auth", "auth/possession" }), secrets->keyAuthenticationCodePossession());
        } else {
            ccstMustThrow(Exception, secrets->keyAuthenticationCodePossession());
        }
        if (is_knowledge) {
            ccstAssertEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        } else {
            ccstMustThrow(Exception, secrets->keyAuthenticationCodeKnowledge());
        }
        if (is_biometry) {
            ccstAssertEqual(key_biometry, secrets->keyAuthenticationCodeBiometry());
        } else {
            ccstMustThrow(Exception, secrets->keyAuthenticationCodeBiometry());
        }
    }
    
    void testHybridSigning(const cc7::crypto::PublicKey& pub_key, const cc7::crypto::PrivateKey& priv_key)
    {
        auto pub1 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(pub_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
        auto priv1 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(priv_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_1).asObject());
        auto signer1 = cc7::crypto::Signature::getInstance(spec()->getSignatureAlgorithms().first);
        ccstAssertNotNull(pub1);
        ccstAssertNotNull(priv1);
        ccstAssertNotNull(signer1);
        testSigning(*signer1, *pub1, *priv1);
        if (spec()->isHybrid()) {
            auto pub2 = std::dynamic_pointer_cast<cc7::crypto::PublicKey>(pub_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
            auto priv2 = std::dynamic_pointer_cast<cc7::crypto::PrivateKey>(priv_key.getKeyParameter(v4::KEY_PARAM_HYBRID_KEY_2).asObject());
            auto signer2 = cc7::crypto::Signature::getInstance(spec()->getSignatureAlgorithms().second);
            ccstAssertNotNull(pub2);
            ccstAssertNotNull(priv2);
            ccstAssertNotNull(signer2);
            testSigning(*signer2, *pub2, *priv2);
        }
    }
    
    void testSigning(const cc7::crypto::Signature& signer, const cc7::crypto::PublicKey& pub_key, const cc7::crypto::PrivateKey& priv_key)
    {
        auto data = cc7::crypto::GetRandomData(33);
        auto signature = signer.sign(priv_key, data);
        auto verified = signer.verify(pub_key, signature, data);
        if (!verified) {
            ccstAssertTrue(verified);
        }
    }
    
    cc7::ByteArray V4_KDF(const cc7::ByteRange& key, std::initializer_list<std::string> list)
    {
        const auto& kdf = algorithms().v4.kdf();
        ByteRange k = key;
        ByteArray derived;
        for (auto it = list.begin(); it != list.end(); ++it) {
            derived = kdf.derive(k, *it);
            k = derived;
        }
        return derived;
    }
};

CC7_CREATE_UNIT_TEST(KeyProviderTests, "pa2")
    
} // namespace powerAuthTests
