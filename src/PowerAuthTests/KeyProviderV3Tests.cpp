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
#include "../PowerAuth/v3/SecretKeysV3.h"
#include "../PowerAuth/v3/LegacyKDF.h"
#include "../PowerAuth/v3/LegacyUKE.h"

using namespace cc7;
using namespace cc7::tests;
using namespace powerAuth;

namespace powerAuthTests {

extern TestDirectory g_pa2Files;

class KeyProviderV3Tests : public UnitTest
{
public:
    
    KeyProviderV3Tests()
    {
        CC7_REGISTER_TEST_METHOD(test_LEGACY)
        CC7_REGISTER_TEST_METHOD(test_LEGACY_Bio)
        CC7_REGISTER_TEST_METHOD(test_DerivedKeysVectors)
        CC7_REGISTER_TEST_METHOD(test_SharedSecretVectors)
    }

    std::unique_ptr<ConfigurationGenerator> configGenerator;
    ContextPtr context;
    bool has_biometry = false;
    cc7::crypto::SignaturePtr signer;
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
    
    cc7::ByteArray key_possession;
    cc7::ByteArray key_transport;
    cc7::ByteArray key_encryption_vault;
    cc7::ByteArray ckey_encryption_vault;
    
    cc7::ByteArray shared_secret;
    cc7::ByteArray device_key;
    
    cc7::crypto::PrivateKeyPtr master_server_hybrid;
    cc7::crypto::KeyPairPtr device_key_pair;
    cc7::crypto::KeyPairPtr server_key_pair;
    
    // keys important between test steps
    cc7::ByteArray keyAuthenticationCodePossession;
    cc7::ByteArray keyAuthenticationCodeKnowledge;
    cc7::ByteArray keyAuthenticationCodeBiometry;
    cc7::ByteArray keyTransport;
    cc7::ByteArray kekDevicePrivate;
    
    void setUp(bool use_biometry)
    {        
        has_biometry = use_biometry;
        configGenerator = std::make_unique<ConfigurationGenerator>(PowerAuthSpec::LEGACY_P256);
        context = Context::getInstance(PowerAuthSpec::LEGACY_P256, configGenerator->configuration);
        
        signer         = cc7::crypto::Signature::getInstance(spec()->getSignatureAlgorithms().first);
        
        device_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        server_key_pair = context->getSigningKeyPairFactoryPtr()->generateKeyPair();
        auto ss1 = algorithms().v3.ecdhWithNullKdf().phase(device_key_pair->getPrivateKey(), server_key_pair->getPublicKey());
        shared_secret  = ReduceSharedSecret(ss1->getKeyData());
        
        device_key     = cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE);

        kek_possession = cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE);
        kek_biometry   = use_biometry ? cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE) : ByteArray();
        kek_knowledge  = cc7::MakeRange("Hello World");
        
        kek_biometry_new  = cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE);
        key_biometry_new  = cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE);
        
        kek_knowledge_new = cc7::MakeRange("fifty.shadows.33");
        key_knowledge_new = cc7::crypto::GetRandomData(v3::FACTOR_KEY_SIZE);
        kek_knowledge_bad = cc7::MakeRange("nbusr123");
              
        key_possession       = V3_KDF(shared_secret, { 1 });
        key_knowledge        = V3_KDF(shared_secret, { 2 });
        key_biometry         = V3_KDF(shared_secret, { 3 });
        key_transport        = V3_KDF(shared_secret, { 1000 });
        key_encryption_vault = V3_KDF(shared_secret, { 2000 });
        // vault key is obfuscated with transport key
        ckey_encryption_vault = algorithms().v3.aes128cbc().encrypt(key_transport, common::ZERO16_IV, key_encryption_vault);
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
        
    void test_LEGACY_Bio()
    {
        setUp(true);
        testKeyProvider();
    }
    
    void test_LEGACY()
    {
        setUp(false);
        testKeyProvider();
    }
    
    void testKeyProvider()
    {
        testPublicKeys();
        testBasicUnlockedKeys();
        
        // pending activation
        createRegistrationData();
        
        testPublicKeys();
        testBasicUnlockedKeys();
        
        // activation commit
        testInitialCredentials();
        
        testPublicKeys();
        testBasicUnlockedKeys();
        testCredentials();
        
        testChangeCredentials();
        testCredentials();
        
        testUpdateBiometry();
        
        testVaultKeyUnlock();
        
        keyProvider().asService()->clearSensitiveData();
        keyProvider().asService()->restoreSensitiveData();
        testCredentials();
        testUpdateBiometry();
        testVaultKeyUnlock();
        
        // serialize and deserialize state
        auto serialized = context->sessionData().serialize();
        context->sessionData().resetSessionData();
        context->sessionData().deserialize(serialized);
        
        testCredentials();
        testUpdateBiometry();
        testVaultKeyUnlock();
    }
    
    void testPublicKeys()
    {
        const auto& key = keyProvider().masterServerPublicKey();
        testSigning(key, configGenerator->legacyMasterKeyPair->getPrivateKey());
        if (!hasActivation() && !hasPendingActivation()) {
            ccstMustThrow(powerAuth::Exception, keyProvider().getDevicePublicKeyPtr());
            ccstMustThrow(powerAuth::Exception, keyProvider().getServerPublicKeyPtr());
        }
        if (hasActivation() || hasPendingActivation()) {
            testSigning(keyProvider().devicePublicKey(), device_key_pair->getPrivateKey());
            testSigning(keyProvider().serverPublicKey(), server_key_pair->getPrivateKey());
        }
    }
    
    void createRegistrationData()
    {
        auto rd = RegistrationData::create(Version_V3);
        rd->v3() = {
            cc7::crypto::GetRandomData(16).base64(),
            cc7::crypto::GetRandomData(v3::HASH_COUNTER_SIZE),                      // hash counter
            server_key_pair->getPublicKey().exportKey(cc7::crypto::KEY_FORMAT_RAW), // server public (direct key data)
            device_key_pair,                                                        // device pair
            server_key_pair->getPublicKeyPtr(),                                     // server public
            shared_secret
        };
        sessionData().setRegistrationData(rd);
    }
    
    void testBasicUnlockedKeys()
    {
        auto secrets = keyProvider().unlockSecretKeys();
        ccstAssertNotNull(secrets);
        {
            // always available keys
            verifyBasicKeys(secrets);
            
            if (hasActivation()) {
                // has activation. Access level is equal to possession only factor
                verifyFactorKeys(secrets, true, false, false);
                verifyUtilityKeys(secrets, true);
                verifyVaultKeys(secrets, false);

            } else if (hasPendingActivation()) {
                // has pending activation, factor keys unavailable, public utility keys unavailable
                verifyFactorKeys(secrets, false, false, false);
                verifyUtilityKeys(secrets, false);
                verifyVaultKeys(secrets, false);
                
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
    
    void testInitialCredentials()
    {
        auto creds = has_biometry ? InitialCredentials::credentials(kek_knowledge, kek_biometry)
                                  : InitialCredentials::credentials(kek_knowledge);
        auto secrets = keyProvider().unlockInitialSecretKeys(*creds, shared_secret);
        {
            ccstAssertNotNull(secrets);
            auto typed_secrets = dynamic_cast<v3::SecretKeysV3*>(&(*secrets));
            ccstAssertNotNull(typed_secrets);
            
            // basic
            verifyBasicKeys(secrets);
            verifyUtilityKeys(secrets, true);
            verifyVaultKeys(secrets, true);
            verifyFactorKeys(secrets, true, true, has_biometry);
            
            // capture important keys
            keyAuthenticationCodePossession = secrets->keyAuthenticationCodePossession();
            keyAuthenticationCodeKnowledge = secrets->keyAuthenticationCodeKnowledge();
            keyAuthenticationCodeBiometry = has_biometry ? secrets->keyAuthenticationCodeBiometry() : ByteRange();
            
            kekDevicePrivate = secrets->kekDevicePrivate();
            keyTransport = secrets->legacyKeyTransport();
        }
        // return keys back to provider
        keyProvider().lockSecretKeys(secrets);
        ccstAssertNull(secrets);
    }
    
    void testCredentials()
    {
        // possession
        auto secrets = keyProvider().unlockSecretKeys(*Credentials::possession());
        {
            verifyBasicKeys(secrets);
            verifyUtilityKeys(secrets, true);
            verifyVaultKeys(secrets, false);
            verifyFactorKeys(secrets, true, false, false);
            
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // knowledge (good)
        secrets = keyProvider().unlockSecretKeys(*Credentials::knowledge(kek_knowledge));
        {
            verifyBasicKeys(secrets);
            verifyUtilityKeys(secrets, true);
            verifyVaultKeys(secrets, false);
            verifyFactorKeys(secrets, true, true, false);
    
            ccstAssertEqual(V3_KDF(shared_secret, { 1 }), keyAuthenticationCodePossession);
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
            ccstAssertEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // knowledge (bad)
        secrets = keyProvider().unlockSecretKeys(*Credentials::knowledge(kek_knowledge_bad));
        {
            ccstAssertEqual(V3_KDF(shared_secret, { 1 }), keyAuthenticationCodePossession);
            ccstAssertEqual(keyAuthenticationCodePossession, secrets->keyAuthenticationCodePossession());
            ccstAssertNotEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // biometry (good)
        if (has_biometry) {
            secrets = keyProvider().unlockSecretKeys(*Credentials::biometry(kek_biometry));
            {
                verifyBasicKeys(secrets);
                verifyUtilityKeys(secrets, true);
                verifyVaultKeys(secrets, false);
                verifyFactorKeys(secrets, true, false, true);
                
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
    
    void testChangeCredentials()
    {
        // change password
        
        // clear dirty flag
        auto serialized_before = context->sessionData().serialize();
        ccstAssertFalse(serialized_before.empty());
        ccstAssertFalse(context->sessionData().isModified());
        
        auto secrets = keyProvider().unlockSecretKeys(*Credentials::knowledge(kek_knowledge));
        {
            secrets->updateKeyAuthenticationCodeKnowledge(key_knowledge_new, kek_knowledge_new);
            // V3 keeps the same knowledge key
            // key_knowledge = keyAuthenticationCodeKnowledge = key_knowledge_new;
            kek_knowledge = kek_knowledge_new;
            ccstAssertEqual(key_knowledge, secrets->keyAuthenticationCodeKnowledge());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // test dirty flag
        ccstAssertTrue(context->sessionData().isModified());
    }
    
    void testUpdateBiometry()
    {
        if (!has_biometry) {
            ccstAssertFalse(sessionData().persistentData().hasBiometricFactorKey());
            return;
        }
        
        ccstAssertTrue(sessionData().persistentData().hasBiometricFactorKey());
        
        // clear dirty flag
        auto serialized_before = sessionData().serialize();
        ccstAssertFalse(serialized_before.empty());
        ccstAssertFalse(sessionData().isModified());
        
        // remove biometry factor
        auto secrets = keyProvider().unlockSecretKeys();
        {
            secrets->removeKeyAuthenticationCodeBiometry();
        }
        keyProvider().lockSecretKeys(secrets);
        
        // test dirty flag
        ccstAssertTrue(sessionData().isModified());
        // clear dirty flag
        context->sessionData().serialize();
        ccstAssertFalse(sessionData().isModified());
        
        ccstAssertFalse(sessionData().persistentData().hasBiometricFactorKey());
        
        // try to use biometry
        ccstMustThrow(Exception, keyProvider().unlockSecretKeys(*Credentials::biometry(kek_biometry)));
        
        // add biometry factor
        secrets = keyProvider().unlockVaultKey(VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
        {
            secrets->updateKeyAuthenticationCodeBiometry(key_biometry_new, kek_biometry_new);
            // In V3, key remains the same
            // key_biometry = keyAuthenticationCodeBiometry = key_biometry_new;
            kek_biometry = kek_biometry_new;
            ccstAssertEqual(key_biometry, secrets->keyAuthenticationCodeBiometry());
        }
        keyProvider().lockSecretKeys(secrets);
        
        // test dirty flag
        ccstAssertTrue(sessionData().isModified());
        ccstAssertTrue(sessionData().persistentData().hasBiometricFactorKey());
        
        // test new biometry
        secrets = keyProvider().unlockSecretKeys(*Credentials::biometry(kek_biometry));
        {
            verifyFactorKeys(secrets, true, false, true);
        }
        keyProvider().lockSecretKeys(secrets);
    }

    void testVaultKeyUnlock()
    {
        // vault only
        auto secrets = keyProvider().unlockVaultKey(VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
        {
            verifyBasicKeys(secrets);
            verifyVaultKeys(secrets, false, VaultKeyType::KEK_DEVICE_PRIVATE);
        }
        keyProvider().lockSecretKeys(secrets);
        //
        ccstMustThrow(Exception, keyProvider().unlockVaultKey(VaultKeyType::KDK_APP_VAULT_KNOWLEDGE, ckey_encryption_vault));
        ccstMustThrow(Exception, keyProvider().unlockVaultKey(VaultKeyType::KDK_APP_VAULT_2FA, key_encryption_vault));

        // vault + credentials
        secrets = keyProvider().unlockVaultAndSecretKeys(*Credentials::possession(), VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
        {
            verifyBasicKeys(secrets);
            verifyVaultKeys(secrets, false, VaultKeyType::KEK_DEVICE_PRIVATE);
            verifyFactorKeys(secrets, true, false, false);
        }
        keyProvider().lockSecretKeys(secrets);
        secrets = keyProvider().unlockVaultAndSecretKeys(*Credentials::knowledge(kek_knowledge), VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
        {
            verifyBasicKeys(secrets);
            verifyVaultKeys(secrets, false, VaultKeyType::KEK_DEVICE_PRIVATE);
            verifyFactorKeys(secrets, true, true, false);
        }
        keyProvider().lockSecretKeys(secrets);
        if (has_biometry) {
            secrets = keyProvider().unlockVaultAndSecretKeys(*Credentials::biometry(kek_biometry), VaultKeyType::KEK_DEVICE_PRIVATE, ckey_encryption_vault);
            {
                verifyBasicKeys(secrets);
                verifyVaultKeys(secrets, false, VaultKeyType::KEK_DEVICE_PRIVATE);
                verifyFactorKeys(secrets, true, false, true);
            }
            keyProvider().lockSecretKeys(secrets);
        }
        //
        ccstMustThrow(Exception, keyProvider().unlockVaultAndSecretKeys(*Credentials::possession(), VaultKeyType::KDK_APP_VAULT_KNOWLEDGE, ckey_encryption_vault));
        ccstMustThrow(Exception, keyProvider().unlockVaultAndSecretKeys(*Credentials::possession(), VaultKeyType::KDK_APP_VAULT_2FA, ckey_encryption_vault));
    }

    
    void verifyBasicKeys(ISecretKeysPtr & secrets)
    {
        auto keyDeviceSpecific = algorithms().v3.sha256().digest(configGenerator->deviceSpecificData);
        keyDeviceSpecific.resize(v3::FACTOR_KEY_SIZE);
        ccstAssertEqual(keyDeviceSpecific, secrets->keyDeviceSpecific());
        ccstMustThrow(Exception, secrets->keyLocalData());
        ccstAssertEqual(configuration().applicationSecretBytes(), secrets->keyMacGetAppTempKey());        
    }
        
    void verifyUtilityKeys(ISecretKeysPtr& secrets, bool public_available)
    {
        if (public_available) {
            ccstAssertEqual(key_transport, secrets->legacyKeyTransport());
            ccstAssertEqual(V3_KDF(shared_secret, { 1000, 3000 }), secrets->legacyKeyTransportIV());
            ccstAssertEqual(V3_KDF(shared_secret, { 1000, 4000 }), secrets->keyMacCtrData());
            ccstAssertEqual(V3_KDF_Int(key_transport, configuration().applicationSecretBytes()), secrets->keyMacGetActTempKey());
        } else {
            ccstMustThrow(Exception, secrets->legacyKeyTransport());
            ccstMustThrow(Exception, secrets->legacyKeyTransportIV());
            ccstMustThrow(Exception, secrets->keyMacCtrData());
            ccstMustThrow(Exception, secrets->keyMacGetActTempKey());
        }
        
        ccstMustThrow(Exception, secrets->keyMacStatus());
        ccstMustThrow(Exception, secrets->keyMacPersonalizedData());
        ccstMustThrow(Exception, secrets->keyE2EESharedInfo2());
        ccstMustThrow(Exception, secrets->kdkAppUtility());
    }
    
    void verifyVaultKeys(ISecretKeysPtr& secrets, bool initial, std::optional<VaultKeyType> type = std::nullopt)
    {
        if (initial || type == VaultKeyType::KEK_DEVICE_PRIVATE) {
            ccstAssertEqual(key_encryption_vault, secrets->kekDevicePrivate());
            // try to use device private key
            const auto& device_private = secrets->devicePrivateKey();
            const auto& device_public = device_key_pair->getPublicKey();
            testSigning(device_public, device_private);
        } else {
            ccstMustThrow(Exception, secrets->kekDevicePrivate());
            ccstMustThrow(Exception, secrets->devicePrivateKey());
        }
        ccstMustThrow(Exception, secrets->kdkAppVaultKnowledge());
        ccstMustThrow(Exception, secrets->kdkAppVault2FA());
    }
        
    void verifyFactorKeys(ISecretKeysPtr& secrets, bool is_possession, bool is_knowledge, bool is_biometry)
    {
        if (is_possession) {
            ccstAssertEqual(V3_KDF(shared_secret, { 1 }), secrets->keyAuthenticationCodePossession());
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
        
    void testSigning(const cc7::crypto::PublicKey& pub_key, const cc7::crypto::PrivateKey& priv_key)
    {
        auto data = cc7::crypto::GetRandomData(33);
        auto signature = signer->sign(priv_key, data);
        auto verified = signer->verify(pub_key, signature, data);
        if (!verified) {
            ccstAssertTrue(verified);
        }
    }
    
    cc7::ByteArray V3_KDF(const cc7::ByteRange& key, std::initializer_list<int64_t> list)
    {
        const auto& kdf = algorithms().v3.kdf();
        ByteRange k = key;
        ByteArray derived;
        for (auto it = list.begin(); it != list.end(); ++it) {
            derived = kdf.derive(k, *it);
            k = derived;
        }
        return derived;
    }
    
    cc7::ByteArray V3_KDF_Int(const cc7::ByteRange& key, const cc7::ByteRange& index)
    {
        return algorithms().v3.kdfInternal().derive(key, index);
    }
    
    // V3 test vectors
    
    void test_DerivedKeysVectors()
    {
        setUp(true);

        auto& provider = keyProvider();
        auto& sd = sessionData();
        
        auto root = JSON_ParseFile(g_pa2Files, "pa2/compute-derived-keys-v3.json");
        auto&& data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto masterSecretKey = item.dataFromBase64StringAtPath("input.masterSecretKey");
            auto signaturePossessionKey = item.dataFromBase64StringAtPath("output.signaturePossessionKey");
            auto signatureKnowledgeKey = item.dataFromBase64StringAtPath("output.signatureKnowledgeKey");
            auto signatureBiometryKey = item.dataFromBase64StringAtPath("output.signatureBiometryKey");
            auto transportKey = item.dataFromBase64StringAtPath("output.transportKey");
            auto vaultEncryptionKey = item.dataFromBase64StringAtPath("output.vaultEncryptionKey");
            
            // this is a bit trickery, because we don't have simple method that derive all factors at once.
            provider.asService()->clearSensitiveData();
            sd.resetSessionData();
            createRegistrationData();
            //
            auto creds = InitialCredentials::credentials(kek_knowledge, kek_biometry);
            auto secrets = provider.unlockInitialSecretKeys(*creds, masterSecretKey);
            ccstAssertEqual(signaturePossessionKey, secrets->keyAuthenticationCodePossession());
            ccstAssertEqual(signatureKnowledgeKey, secrets->keyAuthenticationCodeKnowledge());
            ccstAssertEqual(signatureBiometryKey, secrets->keyAuthenticationCodeBiometry());
            ccstAssertEqual(transportKey, secrets->legacyKeyTransport());
            ccstAssertEqual(vaultEncryptionKey, secrets->kekDevicePrivate());
            provider.lockSecretKeys(secrets);
        }
    }
    
    void test_SharedSecretVectors()
    {
        setUp(true);

        auto& provider = keyProvider();
        auto& sd = sessionData();
        const auto& key_factory = algorithms().v3.p256();

        auto root = JSON_ParseFile(g_pa2Files, "pa2/compute-master-secret-key-v3.json");
        auto&& data = root.arrayAtPath("data");
        for (const auto & item : data) {
            auto devicePrivateKey = item.dataFromBase64StringAtPath("input.devicePrivateKey");
            auto devicePublicKey  = item.dataFromBase64StringAtPath("input.devicePublicKey");
            auto serverPrivateKey = item.dataFromBase64StringAtPath("input.serverPrivateKey");
            auto serverPublicKey  = item.dataFromBase64StringAtPath("input.serverPublicKey");
            auto masterSecretKey  = item.dataFromBase64StringAtPath("output.masterSecretKey");

            // this is also trickery to pretend that data comes from registration record.
            device_key_pair = std::make_shared<cc7::crypto::KeyPair>(key_factory.newPublicKey(devicePublicKey, cc7::crypto::KEY_FORMAT_RAW),
                                                                     key_factory.newPrivateKey(devicePrivateKey, cc7::crypto::KEY_FORMAT_RAW));
            server_key_pair = std::make_shared<cc7::crypto::KeyPair>(key_factory.newPublicKey(serverPublicKey, cc7::crypto::KEY_FORMAT_RAW),
                                                                     key_factory.newPrivateKey(serverPrivateKey, cc7::crypto::KEY_FORMAT_RAW));
            shared_secret.clear();
            provider.asService()->clearSensitiveData();
            sd.resetSessionData();
            createRegistrationData();
            
            auto creds = InitialCredentials::credentials(kek_knowledge, kek_biometry);
            auto secrets = provider.unlockInitialSecretKeys(*creds, ByteRange());
            auto& typed_secrets = dynamic_cast<v3::SecretKeysV3&>(*secrets);
            ccstAssertEqual(masterSecretKey, typed_secrets.keyActivationSecret());
            provider.lockSecretKeys(secrets);
        }
    }
    
    static cc7::ByteArray ReduceSharedSecret(const cc7::ByteRange & secret)
    {
        size_t s = secret.size();
        if (s != 32) {
            throw Exception(EC_InternalError, "Shared secret has unexpected size.");
        }
        s = s / 2;
        cc7::ByteArray reduced(s, 0);
        for (size_t i = 0; i < secret.size() / 2; i++) {
            reduced[i] = secret[i] ^ secret[i + 16];
        }
        return reduced;
    }

};

CC7_CREATE_UNIT_TEST(KeyProviderV3Tests, "pa2")
    
} // namespace powerAuthTests
