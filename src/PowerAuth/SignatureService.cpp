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

#include <PowerAuth/SignatureService.h>
#include "v4/HybridKeyPair.h"
#include "Context.h"
#include <cc7/crypto/X509.h>

#define LOCK_GUARD() std::lock_guard<std::recursive_mutex> _lock_guard(*_lock)

namespace powerAuth {

// MARK: - CustomJwsAlgorithmsProvider

class CustomJwsAlgorithmsProvider : public cc7::jwt::JwsAlgorithmProvider
{
public:
    cc7::jwt::JwsAlgorithmPtr getAlgorithm(const std::string &algorithm_name) const override
    {
        if (algorithm_name == "KMAC256") {
            return std::make_shared<KMACAlgorithm>();
        }
        return JwsAlgorithmProvider::getAlgorithm(algorithm_name);
    }
    
    class KMACAlgorithm : public cc7::jwt::JwsAlgorithm
    {
    public:
        KMACAlgorithm() : _params({
            { cc7::crypto::MAC_PARAM_CUSTOM_STRING, cc7::crypto::Parameter::ref("JOSE") },
            { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take((size_t)64) },
        }) {}
        
        cc7::ByteArray sign(const cc7::jwt::JwsKey &key, const cc7::ByteRange &data) const override
        {
            return algorithms().v4.kmac256().token(key.getSymmetricKey(), data, _params);
        }
        
        bool verify(const cc7::jwt::JwsKey &key, const cc7::ByteRange &data, const cc7::ByteRange &signature) const override
        {
            return algorithms().v4.kmac256().verifyToken(key.getSymmetricKey(), data, signature);
        }
    private:
        cc7::crypto::ParameterList _params;
    };
};

// MARK: - SignatureService

SignatureService::SignatureService(const ContextPtr& context) :
    ServiceWithContext("SignatureService", context),
    _session_data(context->getSessionDataPtr()),
    _vault_service(context->getVaultServicePtr()),
    _jws_provider(std::make_shared<CustomJwsAlgorithmsProvider>())
{
}

// MARK: Classic Signatures

void SignatureService::verifySignature(const cc7::ByteRange &signed_data, const cc7::ByteRange &signature, SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    auto context = lockContext();
    auto spec = SignatureKeySpec::specForKeyId(key_to_use);
    checkSignatureKeySpec(*context, spec, false, false);
    if (spec->keyToUse == SignatureKeySpec::MAC) {
        // Symmetric key
        auto mac_key = calculateSymmetricKey(*context);
        const auto& kmac = algorithms().v4.kmac256();
        auto result = kmac.verifyToken(mac_key, signed_data, signature, {
            { cc7::crypto::MAC_PARAM_CUSTOM_STRING, cc7::crypto::Parameter::ref("PA4MAC-QR") },
            { cc7::crypto::MAC_PARAM_DIGEST_LENGTH, cc7::crypto::Parameter::take((size_t)32) },
        });
        if (!result) {
            throw Exception(EC_WrongSignature, "Invalid MAC");
        }
    } else {
        // DSA
        auto key_with_verifier = populatePublicKeys(*context, spec, false).front();
        auto verifier = cc7::crypto::Signature::getInstance(key_with_verifier.second);
        auto result = verifier->verify(*key_with_verifier.first, signature, signed_data);
        if (!result) {
            throw Exception(EC_WrongSignature, "Invalid digital signature");
        }
    }
}

RequestPtr SignatureService::signData(const CredentialsPtr &credentials, const cc7::ByteRange &data_to_sign, SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    auto context = lockContext();
    auto spec = SignatureKeySpec::specForKeyId(key_to_use);
    checkSignatureKeySpec(*context, spec, false, true);
    
    auto self = shared_from_this();
    cc7::ByteArray bytes_to_sign = data_to_sign;
    return _vault_service->unlockVaultKey(credentials,
                                          VaultKeyType::KEK_DEVICE_PRIVATE,
                                          UnlockVaultKeyReason::SIGN_WITH_DEVICE_PRIVATE_KEY,
                                          [self, context, bytes_to_sign, spec](IKeyProvider& key_provider, ISecretKeys& secret_keys) -> ResponseObjectPtr {
        return self->doSignData(*context, bytes_to_sign, spec, secret_keys);
    });
}

ResponseObjectPtr SignatureService::doSignData(Context &context, const cc7::ByteRange &data_to_sign, SignatureKeySpecPtr spec, ISecretKeys& secrets) const
{
    LOCK_GUARD();
    auto key_with_signer = populatePrivateKeys(context, spec, secrets, false).front();
    auto signer = cc7::crypto::Signature::getInstance(key_with_signer.second);
    auto signature = signer->sign(*key_with_signer.first, data_to_sign);
    return std::make_shared<DataResponse>(signature);
}

// MARK: JWS

void SignatureService::jwsVerifySignature(const std::string &signed_data,
                                          SignatureKeyId key_to_use,
                                          bool is_compact_form,
                                          cc7::jwt::JwsVerifyMode verify_mode) const
{
    LOCK_GUARD();
    auto context = lockContext();
    auto spec = SignatureKeySpec::specForKeyId(key_to_use);
    auto allow_hybrid_keys = !is_compact_form || verify_mode == cc7::jwt::JwsVerifyMode::VERIFY_AT_LEAST_ONE;
    checkSignatureKeySpec(*context, spec, allow_hybrid_keys, false);
    
    cc7::jwt::JwsKeyList keys;
    if (spec->keyToUse == SignatureKeySpec::MAC) {
        throw Exception(EC_WrongParameter, "KEY_MAC_PERSONALIZED is not supported in JWS");
    } else {
        auto keys_and_verifiers = populatePublicKeys(*context, spec, true);
        for (auto& item : keys_and_verifiers) {
            keys.push_back(cc7::jwt::JwsKey::publicKey(item.second, item.first));
        }
    }
    bool in_verify = false;
    try {
        auto reader = is_compact_form
                            ? cc7::jwt::JwtReader::fromCompact(signed_data)
                            : cc7::jwt::JwtReader::fromJsonString(signed_data);
        in_verify = true;
        reader.verify(keys, verify_mode, *_jws_provider);
    } catch (cc7::jwt::JwtException & e) {
        if (in_verify) {
            throw Exception(EC_WrongSignature, e.cause());
        } else {
            throw Exception(EC_InvalidData, "Invalid input data", e.cause());
        }
    }
}

RequestPtr SignatureService::jwsSignData(const CredentialsPtr &credentials,
                                         const cc7::ByteRange &data_to_sign,
                                         const std::string& data_type,
                                         SignatureKeyId key_to_use,
                                         bool use_compact_form) const
{
    LOCK_GUARD();
    auto context = lockContext();
    auto spec = SignatureKeySpec::specForKeyId(key_to_use);
    checkSignatureKeySpec(*context, spec, !use_compact_form, true);
    
    auto self = shared_from_this();
    cc7::ByteArray bytes_to_sign = data_to_sign;
    return _vault_service->unlockVaultKey(credentials,
                                          VaultKeyType::KEK_DEVICE_PRIVATE,
                                          UnlockVaultKeyReason::SIGN_WITH_DEVICE_PRIVATE_KEY,
                                          [self, context, bytes_to_sign, data_type, spec, use_compact_form](IKeyProvider& key_provider, ISecretKeys& secret_keys) -> ResponseObjectPtr {
        return self->doJwsSignData(*context, bytes_to_sign, data_type, spec, use_compact_form, secret_keys);
    });
}

ResponseObjectPtr SignatureService::doJwsSignData(Context &context,
                                                  const cc7::ByteRange &data_to_sign,
                                                  const std::string& data_type,
                                                  SignatureKeySpecPtr spec,
                                                  bool use_compact_form,
                                                  ISecretKeys &secrets) const
{
    LOCK_GUARD();
    cc7::jwt::JwsKeyList keys;
    for (auto& item : populatePrivateKeys(context, spec, secrets, true)) {
        keys.push_back(cc7::jwt::JwsKey::privateKey(item.second, item.first));
    }
    try {
        auto writer = cc7::jwt::JwtWriter()
            .withPayload(data_to_sign, data_type)
            .sign(keys, *_jws_provider);
        auto result = use_compact_form ? writer.toCompact() : writer.toJsonString();
        return std::make_shared<StringResponse>(result);
    } catch (cc7::jwt::JwtException & e) {
        throw Exception(EC_Cryptography, "Failed to calculate JWS signature", std::current_exception());
    }
}

// MARK: CSR

RequestPtr SignatureService::createCSR(const CredentialsPtr& credentials,
                                       const std::map<std::string, std::string>& dn_items,
                                       const std::vector<std::string>& san_items,
                                       SignatureKeyId key_to_use) const
{
    LOCK_GUARD();
    if (dn_items.empty()) {
        throw Exception(EC_WrongParameter, "Distinguished Names map is empty");
    }
    auto context = lockContext();
    auto spec = SignatureKeySpec::specForKeyId(key_to_use);
    checkSignatureKeySpec(*context, spec, false, true);
    auto self = shared_from_this();
    return _vault_service->unlockVaultKey(credentials,
                                          VaultKeyType::KEK_DEVICE_PRIVATE,
                                          UnlockVaultKeyReason::SIGN_WITH_DEVICE_PRIVATE_KEY,
                                          [self, context, spec, dn_items, san_items](IKeyProvider& key_provider, ISecretKeys& secret_keys) -> ResponseObjectPtr {
        return self->doCreateCSR(*context, dn_items, san_items, spec, secret_keys);
    });
}

ResponseObjectPtr SignatureService::doCreateCSR(Context& context,
                                                const std::map<std::string, std::string>& dn_items,
                                                const std::vector<std::string>& san_items,
                                                SignatureKeySpecPtr spec,
                                                ISecretKeys& secrets) const
{
    LOCK_GUARD();
    auto private_key = populatePrivateKeys(context, spec, secrets, false)
                            .front()    // only first key matters
                            .first;     // from returned tuple, only the key is important
    auto csr = cc7::crypto::X509::createCSR(*private_key, dn_items, san_items);
    return std::make_shared<StringResponse>(csr);
}

// MARK: Private

cc7::ByteArray SignatureService::calculateSymmetricKey(Context& context) const
{
    auto secrets = context.keyProvider().unlockSecretKeys();
    cc7::ByteArray mac_key = secrets->keyMacPersonalizedData();
    context.keyProvider().lockSecretKeys(secrets);
    return mac_key;
}

SignatureService::PublicKeysWithVerifier SignatureService::populatePublicKeys(Context& context, SignatureKeySpecPtr spec, bool for_jws) const
{
    auto& key_provider = context.keyProvider();
    auto algorithms = for_jws ?
                        context.specification()->getJwsSignatureAlgorithms() :
                        context.specification()->getSignatureAlgorithms();
    cc7::crypto::ConstPublicKeyPtr key;
    switch (spec->keyToUse) {
        case SignatureKeySpec::MASTER:
            key = key_provider.getMasterServerPublicKeyPtr();
            break;
        case SignatureKeySpec::SERVER:
            key = key_provider.getServerPublicKeyPtr();
            break;
        case SignatureKeySpec::DEVICE:
            key = key_provider.getDevicePublicKeyPtr();
            break;
        default:
            throw Exception(EC_InternalError, "Unsupported key to use for signature verification");
    }
    PublicKeysWithVerifier result;
    auto protocol_spec = context.specification();
    if (!protocol_spec->isLegacy()) {
        auto key1 = v4::HybridKey_GetKey1Ptr(*key);
        if (spec->keyIsIncluded(key1->getKeyType())) {
            result.push_back({ key1, algorithms.first });
        }
        if (protocol_spec->isHybrid()) {
            auto key2 = v4::HybridKey_GetKey2Ptr(*key);
            if (spec->keyIsIncluded(key2->getKeyType())) {
                result.push_back({ key2, algorithms.second });
            }
        }
    } else {
        // legacy key, use the key as it is
        if (spec->keyIsIncluded(key->getKeyType())) {
            result.push_back({ key, algorithms.first });
        }
    }
    if (result.empty()) {
        throw Exception(EC_InternalError, "No public key populated");
    }
    return result;
}

SignatureService::PrivateKeysWithSigner SignatureService::populatePrivateKeys(Context &context, SignatureKeySpecPtr spec, ISecretKeys &secrets, bool for_jws) const
{
    cc7::crypto::ConstPrivateKeyPtr key;
    auto algorithms = for_jws ?
                        context.specification()->getJwsSignatureAlgorithms() :
                        context.specification()->getSignatureAlgorithms();
    if (spec->keyToUse == SignatureKeySpec::DEVICE) {
        key = secrets.getDevicePrivateKeyPtr();
    } else {
        throw Exception(EC_InternalError, "Unsupported key to use for signature calculation");
    }
    SignatureService::PrivateKeysWithSigner result;
    auto protocol_spec = context.specification();
    if (!protocol_spec->isLegacy()) {
        auto key1 = v4::HybridKey_GetKey1Ptr(*key);
        if (spec->keyIsIncluded(key1->getKeyType())) {
            result.push_back({ key1, algorithms.first });
        }
        if (protocol_spec->isHybrid()) {
            auto key2 = v4::HybridKey_GetKey2Ptr(*key);
            if (spec->keyIsIncluded(key2->getKeyType())) {
                result.push_back({ key2, algorithms.second });
            }
        }
    } else {
        // legacy key, use the key as it is
        if (spec->keyIsIncluded(key->getKeyType())) {
            result.push_back({ key, algorithms.first });
        }
    }
    if (result.empty()) {
        throw Exception(EC_InternalError, "No private key populated");
    }
    return result;
}

void SignatureService::checkSignatureKeySpec(Context& context, SignatureKeySpecPtr spec, bool allow_hybrid_keys, bool for_sign) const
{
    if (for_sign && !spec->sign) {
        throw Exception(EC_WrongParameter, "Selected key doesn't support signature calculation");
    }
    if (!for_sign && !spec->verify) {
        throw Exception(EC_WrongParameter, "Selected key doesn't support signature verification");
    }
    if (spec->requireActivation && !_session_data->hasActivationId()){
        throw Exception(EC_MissingActivation, "Selected key is available only when activation is present");
    }
    auto protocol_spec = context.specification();
    if (spec->keyToUse == SignatureKeySpec::MAC) {
        if (protocol_spec->isLegacy()) {
            throw Exception(EC_WrongParameter, "Selected key is not available for this protocol version");
        }
        // MAC key doesn't require additional key matching.
        return;
    }
    size_t matched_keys = 0;
    const auto& key_algorithms = protocol_spec->getSigningKeyPairAlgorithms();
    if (spec->keyIsIncluded(key_algorithms.first)) {
        matched_keys++;
    }
    if (protocol_spec->isHybrid() && spec->keyIsIncluded(key_algorithms.second)) {
        matched_keys++;
    }
    if (!matched_keys) {
        throw Exception(EC_WrongParameter, "Selected key is not available");
    }
    if (matched_keys > 1 && !allow_hybrid_keys) {
        throw Exception(EC_WrongParameter, "Hybrid signature is not supported");
    }
}

// MARK: - SignatureKeySpec

SignatureKeySpec const * const SignatureKeySpec::specForKeyId(SignatureKeyId key_id) noexcept
{
    //                                                    key to use                key type                  sign   verify  activation
    static const SignatureKeySpec KEY_MASTER            { SignatureKeySpec::MASTER, std::nullopt,             false,  true,  false };
    static const SignatureKeySpec KEY_MASTER_EC         { SignatureKeySpec::MASTER, SignatureKeyType::EC,     false,  true,  false };
    static const SignatureKeySpec KEY_MASTER_ML_DSA     { SignatureKeySpec::MASTER, SignatureKeyType::ML_DSA, false,  true,  false };
    static const SignatureKeySpec KEY_SERVER            { SignatureKeySpec::SERVER, std::nullopt,             false,  true,  true  };
    static const SignatureKeySpec KEY_SERVER_EC         { SignatureKeySpec::SERVER, SignatureKeyType::EC,     false,  true,  true  };
    static const SignatureKeySpec KEY_SERVER_ML_DSA     { SignatureKeySpec::SERVER, SignatureKeyType::ML_DSA, false,  true,  true  };
    static const SignatureKeySpec KEY_DEVICE            { SignatureKeySpec::DEVICE, std::nullopt,             true,   true,  true  };
    static const SignatureKeySpec KEY_DEVICE_EC         { SignatureKeySpec::DEVICE, SignatureKeyType::EC,     true,   true,  true  };
    static const SignatureKeySpec KEY_DEVICE_ML_DSA     { SignatureKeySpec::DEVICE, SignatureKeyType::ML_DSA, true,   true,  true  };
    static const SignatureKeySpec KEY_MAC_PERSONALIZED  { SignatureKeySpec::MAC,    std::nullopt,             false,  true,  true  };

    switch (key_id) {
        case SignatureKeyId::KEY_MASTER:            return &KEY_MASTER;
        case SignatureKeyId::KEY_MASTER_EC:         return &KEY_MASTER_EC;
        case SignatureKeyId::KEY_MASTER_ML_DSA:     return &KEY_MASTER_ML_DSA;
        case SignatureKeyId::KEY_SERVER:            return &KEY_SERVER;
        case SignatureKeyId::KEY_SERVER_EC:         return &KEY_SERVER_EC;
        case SignatureKeyId::KEY_SERVER_ML_DSA:     return &KEY_SERVER_ML_DSA;
        case SignatureKeyId::KEY_DEVICE:            return &KEY_DEVICE;
        case SignatureKeyId::KEY_DEVICE_EC:         return &KEY_DEVICE_EC;
        case SignatureKeyId::KEY_DEVICE_ML_DSA:     return &KEY_DEVICE_ML_DSA;
        case SignatureKeyId::KEY_MAC_PERSONALIZED:  return &KEY_MAC_PERSONALIZED;
    }
}

SignatureKeyType SignatureKeySpec::keyTypeForKeyAlgorithm(const std::string& key_algorithm)
{
    static const std::string P_256("P-256");
    static const std::string P_384("P-384");
    static const std::string ML_DSA_65("ML-DSA-65");
    static const std::string ML_DSA_87("ML-DSA-87");

    if (key_algorithm == ML_DSA_65 || key_algorithm == ML_DSA_87) {
        return SignatureKeyType::ML_DSA;
    }
    if (key_algorithm == P_256 || key_algorithm == P_384) {
        return SignatureKeyType::EC;
    }
    throw Exception(EC_WrongParameter, "Unsupported key algorithm " + key_algorithm);
}

bool SignatureKeySpec::keyIsIncluded(const std::string& key_type) const
{
    if (keyType) {
        // Exact key type is required. Convert
        return keyTypeForKeyAlgorithm(key_type) == keyType.value();
    }
    // Any key can be used
    return true;
}

} // namespace powerAuth
