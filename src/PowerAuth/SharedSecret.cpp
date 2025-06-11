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

#include "SharedSecret.h"

#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>
#include <cc7/utils/DataReader.h>
#include <cc7/utils/DataWriter.h>

#include "crypto/PowerAuthKDF.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {

// MARK: - ECDHE

class SharedSecretEc : public ISharedSecret
{
public:
    
    std::pair<SharedSecretRequest, SharedSecretContextPtr> generateRequestCryptogram() const override
    {
        auto ephemeral_key_pair = _ec_key_factory->generateKeyPair();
        SharedSecretRequest request = {
            _spec->algorithm,
            ephemeral_key_pair->getPublicKey().exportKeyToBase64(KEY_FORMAT_X963),
            ""
        };
        return std::make_pair(request, ephemeral_key_pair->getPrivateKeyPtr());
    }
    
    std::pair<SharedSecretResponse, ByteArray> generateResponseCryptogram(const SharedSecretRequest & request) const override
    {
        if (_spec->algorithm != request.algorithm) {
            throw std::invalid_argument("Unsupported algorithm in request");
        }
        if (request.ecdhe.empty()) {
            throw std::invalid_argument("Missing ecdhe public key");
        }
        auto peer_key = _ec_key_factory->newPublicKey(FromBase64String(request.ecdhe), KEY_FORMAT_X963);
        auto ephemeral_key_pair = _ec_key_factory->generateKeyPair();
        auto shared_secret = calculateSharedSecret(ephemeral_key_pair->getPrivateKey(), *peer_key);
        SharedSecretResponse response = {
            ephemeral_key_pair->getPublicKey().exportKeyToBase64(KEY_FORMAT_X963),
            ""
        };
        return std::make_pair(response, shared_secret);
    }
    
    ByteArray computeSharedSecret(const SharedSecretContextPtr & context, const SharedSecretResponse &response) const override
    {
        if (response.ecdhe.empty()) {
            throw std::invalid_argument("Missing ecdhe public key");
        }
        const auto& private_key = checkContext(context);
        auto peer_key = _ec_key_factory->newPublicKey(FromBase64String(response.ecdhe), KEY_FORMAT_X963);
        return calculateSharedSecret(private_key, *peer_key);
    }
    
    ByteArray serializeContext(const SharedSecretContextPtr &context) const override
    {
        const auto& private_key = checkContext(context);
        cc7::utils::DataWriter writer;
        writer.writeString(_spec->algorithm);
        writer.writeData(private_key.exportKey(KEY_FORMAT_RAW));
        return writer.serializedData();
    }
    
    SharedSecretContextPtr deserializeContext(const ByteRange &context_data) const override
    {
        cc7::utils::DataReader reader(context_data, false);
        std::string alg;
        ByteRange key_data;
        
        if (!(reader.readString(alg) &&
              reader.readRange(key_data))) {
            throw std::invalid_argument("Wrong serialized data");
        }
        if (alg != _spec->algorithm) {
            throw std::invalid_argument("Wrong context algorithm");
        }
        return _ec_key_factory->newPrivateKey(key_data, KEY_FORMAT_RAW);
    }
    
    SharedSecretContextPtr importContextForTest(const std::map<std::string, std::string> &test_data) const override
    {
#ifdef DEBUG
        auto key_data = test_data.find("ecdhe_client_private_key");
        if (key_data == test_data.end()) {
            throw std::invalid_argument("Missing ecdhe_client_private_key");
        }
        return _ec_key_factory->newPrivateKey(FromBase64String(key_data->second), KEY_FORMAT_RAW);
#else
        throw std::logic_error("Not implemented");
#endif
    }
    
    std::map<std::string, std::string> exportContextForTest(const SharedSecretContextPtr &context) const override
    {
#ifdef DEBUG
        const auto& private_key = checkContext(context);
        return {
            { "ecdhe_client_private_key",  private_key.exportKeyToBase64(KEY_FORMAT_RAW) }
        };
#else
        throw std::logic_error("Not implemented");
#endif
    }
    
    SharedSecretEc(SharedSecretSpecPtr spec,
                   const KeyPairFactoryPtr & ec_key_factory,
                   const KeyAgreementPtr & ecdh) :
        _spec(spec),
        _ec_key_factory(ec_key_factory),
        _ecdh(ecdh)
    {
    }

private:
    
    const PrivateKey& checkContext(const SharedSecretContextPtr & ctx) const
    {
        const auto private_key = std::dynamic_pointer_cast<PrivateKey>(ctx);
        if (private_key == nullptr || private_key->getKeyType() != _ec_key_factory->getAlgorithmName()) {
            throw std::invalid_argument("Wrong SharedSecretContext object provided");
        }
        return *private_key;
    }
    
    ByteArray calculateSharedSecret(const PrivateKey & private_key, const PublicKey & peer_key) const
    {
        auto raw_key = _ecdh->phase(private_key, peer_key);
        return algorithms().v4.kdf().derive(raw_key->getKeyData(), _spec->derivationLabel);
    }
    
    SharedSecretSpecPtr _spec;
    const KeyPairFactoryPtr _ec_key_factory;
    const KeyAgreementPtr _ecdh;
};

// MARK: - Hybrid, ECDHE + KEM

class SharedSecretEcKem : public ISharedSecret
{
public:
    
    std::pair<SharedSecretRequest, SharedSecretContextPtr> generateRequestCryptogram() const override
    {
        auto ec_key_pair = _ec_key_factory->generateKeyPair();
        auto kem_key_pair = _kem_key_factory->generateKeyPair();
        auto context = std::make_shared<HybridContext>(_spec->algorithm,
                                                       ec_key_pair->getPrivateKeyPtr(),
                                                       kem_key_pair->getPrivateKeyPtr());
        SharedSecretRequest request {
            _spec->algorithm,
            ec_key_pair->getPublicKey().exportKeyToBase64(KEY_FORMAT_X963),
            kem_key_pair->getPublicKey().exportKeyToBase64(KEY_FORMAT_SPKI)
        };
        return std::make_pair(request, context);
    }
    
    std::pair<SharedSecretResponse, ByteArray> generateResponseCryptogram(const SharedSecretRequest &request) const override
    {
        if (_spec->algorithm != request.algorithm) {
            throw std::invalid_argument("Unsupported algorithm in request");
        }
        if (request.ecdhe.empty()) {
            throw std::invalid_argument("Missing ecdhe public key");
        }
        if (request.mlkem.empty()) {
            throw std::invalid_argument("Missing mlkem encapsulation key");
        }
        // Decode keys
        auto ec_peer_key = _ec_key_factory->newPublicKey(FromBase64String(request.ecdhe), KEY_FORMAT_X963);
        auto encap_key   = _kem_key_factory->newPublicKey(FromBase64String(request.mlkem), KEY_FORMAT_SPKI);
        // Generate response and shared secret
        auto ec_ephemeral_key = _ec_key_factory->generateKeyPair();
        auto s1 = _ecdh->phase(ec_ephemeral_key->getPrivateKey(), *ec_peer_key);
        auto wrapped_with_secret = _kem->encapsulate(*encap_key);
        SharedSecretResponse response {
            ec_ephemeral_key->getPublicKey().exportKeyToBase64(KEY_FORMAT_X963),
            wrapped_with_secret.first.base64String()
        };
        return std::make_pair(response, calculateSharedSecret(*s1, *wrapped_with_secret.second));
    }
    
    ByteArray computeSharedSecret(const SharedSecretContextPtr &context, const SharedSecretResponse &response) const override
    {
        if (response.ecdhe.empty()) {
            throw std::invalid_argument("Missing ecdhe public key");
        }
        if (response.mlkem.empty()) {
            throw std::invalid_argument("Missing mlkem wrapped key");
        }
        const auto& ctx = checkContext(context);
        // Decode keys
        auto ec_peer_key = _ec_key_factory->newPublicKey(FromBase64String(response.ecdhe), KEY_FORMAT_X963);
        auto wrapped_key = FromBase64String(response.mlkem);
        // Generate shared secret
        auto s1 = _ecdh->phase(*ctx.ec_private_key, *ec_peer_key);
        auto s2 = _kem->decapsulate(*ctx.kem_private_key, wrapped_key);
        return calculateSharedSecret(*s1, *s2);
    }
    
    ByteArray serializeContext(const SharedSecretContextPtr &context) const override
    {
        const auto& ctx = checkContext(context);
        cc7::utils::DataWriter writer;
        writer.writeString(_spec->algorithm);
        writer.writeData(ctx.ec_private_key->exportKey(KEY_FORMAT_RAW));
        writer.writeData(ctx.kem_private_key->exportKey(KEY_FORMAT_RAW));
        return writer.serializedData();
    }
    
    SharedSecretContextPtr deserializeContext(const ByteRange &context_data) const override
    {
        cc7::utils::DataReader reader(context_data, false);
        
        std::string alg;
        ByteRange ec_key, kem_key;
        if (!(reader.readString(alg) &&
              reader.readRange(ec_key) &&
              reader.readRange(kem_key))) {
            throw std::invalid_argument("Wrong context data");
        }
        if (alg != _spec->algorithm) {
            throw std::invalid_argument("Wrong context algorithm");
        }
        return std::make_shared<HybridContext>(_spec->algorithm,
                                               _ec_key_factory->newPrivateKey(ec_key, KEY_FORMAT_RAW),
                                               _kem_key_factory->newPrivateKey(kem_key, KEY_FORMAT_RAW));
    }
    
    SharedSecretContextPtr importContextForTest(const std::map<std::string, std::string> &test_data) const override
    {
#ifdef DEBUG
        auto ec_key_data = test_data.find("ecdhe_client_private_key");
        auto kem_key_data = test_data.find("kem_client_private_key");
        if (ec_key_data == test_data.end() || kem_key_data == test_data.end()) {
            throw std::invalid_argument("Missing ecdhe_client_private_key or kem_client_private_key parameter");
        }
        return std::make_shared<HybridContext>(_spec->algorithm,
                                               _ec_key_factory->newPrivateKey(FromBase64String(ec_key_data->second), KEY_FORMAT_RAW),
                                               _kem_key_factory->newPrivateKey(FromBase64String(kem_key_data->second), KEY_FORMAT_PKCS8));
#else
        throw std::logic_error("Not implemented");
#endif
    }
    
    std::map<std::string, std::string> exportContextForTest(const SharedSecretContextPtr &context) const override
    {
#ifdef DEBUG
        const auto& ctx = checkContext(context);
        return {
            { "ecdhe_client_private_key", ctx.ec_private_key->exportKeyToBase64(KEY_FORMAT_RAW) },
            { "kem_client_private_key",   ctx.kem_private_key->exportKeyToBase64(KEY_FORMAT_PKCS8) }
        };
#else
        throw std::logic_error("Not implemented");
#endif
    }
    
    SharedSecretEcKem(SharedSecretSpecPtr spec,
                      const KeyPairFactoryPtr & ec_key_factory,
                      const KeyPairFactoryPtr & kem_key_factory,
                      const KeyAgreementPtr & ecdh,
                      const KeyEncapsulationPtr & kem) :
        _spec(spec),
        _ec_key_factory(ec_key_factory),
        _kem_key_factory(kem_key_factory),
        _ecdh(ecdh),
        _kem(kem)
    {
    }
    
private:
    friend class SharedSecretTests;
    
    class HybridContext : public cc7::BaseObject
    {
    public:
        HybridContext(const std::string & alg, PrivateKeyPtr ec_private, PrivateKeyPtr kem_private) :
            algorithm(alg),
            ec_private_key(ec_private),
            kem_private_key(kem_private)
        {
        }
        const std::string algorithm;
        const PrivateKeyPtr ec_private_key;
        const PrivateKeyPtr kem_private_key;
    };

    const HybridContext& checkContext(const SharedSecretContextPtr & context) const
    {
        const auto ctx = std::dynamic_pointer_cast<HybridContext>(context);
        if (ctx == nullptr || ctx->algorithm != _spec->algorithm) {
            throw std::invalid_argument("Wrong SharedSecretContext object provided");
        }
        return *ctx;
    }
    
    ByteArray calculateSharedSecret(const SymmetricKey & s1, const SymmetricKey & s2) const
    {
        auto hybrid_secret = cc7::ConcatByteRanges({ s1.getKeyData(), s2.getKeyData() });
        return algorithms().v4.kdf().derive(hybrid_secret, _spec->derivationLabel);
    }
        
    SharedSecretSpecPtr _spec;
    const KeyPairFactoryPtr _ec_key_factory;
    const KeyPairFactoryPtr _kem_key_factory;
    const KeyAgreementPtr _ecdh;
    const KeyEncapsulationPtr _kem;
};



// MARK: - SharedSecret implementation

static const SharedSecret::Specification spec_EC_P384 {
    SharedSecret::EC_P384, 
    "EC_P384",
    "shared-secret/ec-p384"
};
static const SharedSecret::Specification spec_EC_P384_ML_L3 {
    SharedSecret::EC_P384_ML_L3,
    "EC_P384_ML_L3",
    "shared-secret/ec-p384-ml-l3"
};

cc7::byte SharedSecret::Specification::numericIdentifier() const noexcept
{
    return static_cast<cc7::byte>(identifier);
}

SharedSecretSpecPtr SharedSecret::specForAlgorithm(Algorithm algorithm)
{
    switch (algorithm) {
        case EC_P384:           return &spec_EC_P384;
        case EC_P384_ML_L3:     return &spec_EC_P384_ML_L3;
        default:                return nullptr;
    }
}

SharedSecretSpecPtr SharedSecret::specForAlgorithm(const std::string &algorithm)
{
    if (algorithm == spec_EC_P384.algorithm) {
        return &spec_EC_P384;
    }
    if (algorithm == spec_EC_P384_ML_L3.algorithm) {
        return &spec_EC_P384_ML_L3;
    }
    return nullptr;
}

SharedSecretSpecPtr SharedSecret::specForAlgorithmId(cc7::byte algorithm_id)
{
    switch (algorithm_id) {
        case EC_P384:           return &spec_EC_P384;
        case EC_P384_ML_L3:     return &spec_EC_P384_ML_L3;
        default:                return nullptr;
    }
}

ISharedSecretPtr SharedSecret::getInstance(Algorithm algorithm)
{
    auto spec = specForAlgorithm(algorithm);
    if (spec) {
        const auto& algs = algorithms().v4.pointers;
        switch (algorithm) {
            case EC_P384:
                return std::make_shared<SharedSecretEc>(spec, algs.key_P384, algs.kagree_ECDH_NULLKDF);
            case EC_P384_ML_L3:
                return std::make_shared<SharedSecretEcKem>(spec, algs.key_P384, algs.key_MLKEM_768, algs.kagree_ECDH_NULLKDF, algs.kencap_MLKEM_768);
            default:
                break;
        }
    }
    throw std::logic_error("Unsupported algorithm");
}

} // powerAuth
