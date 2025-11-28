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

#include <PowerAuth/SharedSecret.h>
#include <PowerAuth/Algorithms.h>
#include <PowerAuth/ByteUtils.h>
#include <cc7/utils/DataReader.h>
#include <cc7/utils/DataWriter.h>
#include "model/Constants.h"
#include "v4/PowerAuthKDF.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {

// MARK: - Common SharedSecret implementation

class SharedSecret : public ISharedSecret
{
public:
    
    struct KFWithKEM
    {
        KeyPairFactoryPtr factory;
        KeyEncapsulationPtr kem;
    };
    
    typedef ConstPowerAuthSpecPtr SPEC;
    typedef std::vector<KFWithKEM> KEMs;
    
    SharedSecret(SPEC spec, const KEMs& kems) :
        _kems(kems),
        _algorithm(spec->algorithmName())
    {}
    
    struct SSContext : public cc7::BaseObject
    {
        std::string algorithm;
        std::vector<PrivateKeyPtr> decapsulationKeys;
        
        SSContext(const std::string& algorithm, const std::vector<PrivateKeyPtr>& decapsulation_keys) :
            algorithm(algorithm),
            decapsulationKeys(decapsulation_keys)
        {}
    };
    
    std::pair<SharedSecretRequest, SharedSecretContextPtr> generateRequestCryptogram() const override
    {
        std::vector<cc7::crypto::PrivateKeyPtr> decapsulation_keys;
        std::vector<std::string> encapsulation_keys;
        encapsulation_keys.reserve(_kems.size());
        for (auto& kem : _kems) {
            auto key_pair = kem.kem->generate();
            decapsulation_keys.push_back(key_pair->getPrivateKeyPtr());
            encapsulation_keys.push_back(key_pair->getPublicKey().exportKeyToBase64(KEY_FORMAT_DEFAULT));
        }
        return std::make_pair(SharedSecretRequest { _algorithm, encapsulation_keys },
                              std::make_shared<SSContext>(_algorithm, decapsulation_keys));
    }
    
    std::pair<SharedSecretResponse, cc7::ByteArray> generateResponseCryptogram(const SharedSecretRequest &request) const override
    {
        if (request.algorithm != _algorithm) {
            throw Exception(EC_InvalidData, "Unsupported algorithm in request");
        }
        if (request.encapsulationKeys.size() != _kems.size()) {
            throw Exception(EC_InvalidData, "Wrong number of encapsulation keys in request");
        }
        
        std::vector<std::string> encapsulated_keys;
        encapsulated_keys.reserve(_kems.size());
        
        std::vector<SymmetricKeyPtr> secret_keys;
        secret_keys.reserve(_kems.size());

        for (size_t i = 0; i < _kems.size(); ++i) {
            const auto& kem = _kems[i];
            PublicKeyPtr encapsulation_key;
            try {
                encapsulation_key = kem.factory->newPublicKey(request.encapsulationKeys[i], KEY_FORMAT_DEFAULT);
            } catch (...) {
                Exception::reThrowWrapped(EC_InvalidData, "Failed to import encapsulation key #" + std::to_string(i));
            }
            try {
                auto encapsulated_with_secret = kem.kem->encapsulate(*encapsulation_key);
                secret_keys.push_back(encapsulated_with_secret.second);
                encapsulated_keys.push_back(encapsulated_with_secret.first.base64());
            } catch (...) {
                Exception::reThrowWrapped(EC_Cryptography, "Failed to encapsulate key #" + std::to_string(i));
            }
        }
        auto salt = GetRandomData(v4::SHARED_SECRET_SALT_SIZE);
        return std::make_pair(SharedSecretResponse { salt.base64(), encapsulated_keys },
                              calculateSharedSecret(secret_keys, salt));
    }
    
    cc7::ByteArray computeSharedSecret(const SharedSecretContextPtr &context, const SharedSecretResponse &response) const override
    {
        const auto& ctx = checkContext(context);
        
        if (response.encapsulatedKeys.size() != _kems.size()) {
            throw Exception(EC_InvalidData, "Wrong number of encapsulated keys in response");
        }
        auto salt = Base64::decode(response.salt);
        if (salt.size() != v4::SHARED_SECRET_SALT_SIZE) {
            throw Exception(EC_InvalidData, "Wrong size of salt in response");
        }
        std::vector<SymmetricKeyPtr> secret_keys;
        secret_keys.reserve(_kems.size());
        
        for (size_t i = 0; i < _kems.size(); ++i) {
            const auto& kem = _kems[i];
            try {
                auto secret = kem.kem->decapsulate(*ctx.decapsulationKeys[i], Base64::decode(response.encapsulatedKeys[i]));
                secret_keys.push_back(secret);
            } catch (...) {
                Exception::reThrowWrapped(EC_Cryptography, "Failed to decapsulate key #" + std::to_string(i));
            }
        }
        return calculateSharedSecret(secret_keys, salt);
    }
    
    cc7::ByteArray serializeContext(const SharedSecretContextPtr &context) const override
    {
        const auto& ctx = checkContext(context);
        cc7::utils::DataWriter writer;
        writer.writeString(_algorithm);
        writer.writeCount(_kems.size());
        for (const auto& key : ctx.decapsulationKeys) {
            writer.writeData(key->exportKey());
        }
        return writer.serializedData();
    }
    
    SharedSecretContextPtr deserializeContext(const cc7::ByteRange &context_data) const override
    {
        cc7::utils::DataReader reader(context_data, false);
        
        std::string algorithm;
        size_t count = 0;
        if (!(reader.readString(algorithm) && reader.readCount(count))) {
            throw Exception(EC_InvalidData, "Wrong SharedSecret context data");
        }
        if (algorithm != _algorithm) {
            throw Exception(EC_InvalidData, "Unsupported algorithm in SharedSecret context data");
        }
        if (count != _kems.size()) {
            throw Exception(EC_InvalidData, "Unexpected number of decapsulation keys in SharedSecret context data");
        }
        
        std::vector<PrivateKeyPtr> decapsulation_keys;
        decapsulation_keys.reserve(count);
        
        for (const auto& kem : _kems) {
            ByteRange key_data;
            if (reader.readRange(key_data)) {
                decapsulation_keys.push_back(kem.factory->newPrivateKey(key_data));
            } else {
                throw Exception(EC_InvalidData, "Failed to read key data");
            }
        }
        return std::make_shared<SSContext>(algorithm, decapsulation_keys);
    }
    
        SharedSecretContextPtr importContextForTest(const std::map<std::string, std::string> &test_data) const override
        {
    #ifdef DEBUG
            std::vector<PrivateKeyPtr> decapsulation_keys;
            for (size_t i = 0; i < _kems.size(); i++) {
                auto key_name = std::to_string(i);
                auto key_data = test_data.find(key_name);
                if (key_data == test_data.end()) {
                    throw std::invalid_argument("Missing key #" + key_name);
                }
                decapsulation_keys.push_back(_kems[i].factory->newPrivateKey(Base64::decode(key_data->second)));
            }
            return std::make_shared<SSContext>(_algorithm, decapsulation_keys);
    #else
            throw Exception(EC_InternalError, "Not implemented in RELEASE build");
    #endif
        }
    
        std::map<std::string, std::string> exportContextForTest(const SharedSecretContextPtr &context) const override
        {
    #ifdef DEBUG
            const auto& ctx = checkContext(context);
            std::map<std::string, std::string> out;
            for (size_t i = 0; i < _kems.size(); i++) {
                auto key_name = std::to_string(i);
                out.insert({ key_name, ctx.decapsulationKeys[i]->exportKeyToBase64() });
            }
            return out;
    #else
            throw Exception(EC_InternalError, "Not implemented in RELEASE build");
    #endif
        }
    
private:
    
    const KEMs _kems;
    const std::string _algorithm;
    
    const SSContext& checkContext(const SharedSecretContextPtr& context) const
    {
        auto typed = std::dynamic_pointer_cast<SSContext>(context);
        if (!typed) {
            throw Exception(EC_WrongParameter, "Invalid SharedSecret context");
        }
        if (typed->algorithm != _algorithm) {
            throw Exception(EC_WrongParameter, "Unsupported algorithm in SharedSecret context");
        }
        if (typed->decapsulationKeys.size() != _kems.size()) {
            throw Exception(EC_InternalError, "Unexpected number of decapsulation keys in SharedSecret context");
        }
        return *typed;
    }
    
    ByteArray calculateSharedSecret(const std::vector<SymmetricKeyPtr>& secret_keys, const ByteRange& salt) const
    {
        ByteArray concatenated_secrets;
        concatenated_secrets.reserve(64 * secret_keys.size());
        for (auto& key : secret_keys) {
            const auto& key_data = key->getKeyData();
            auto size = ToBigEndian(cc7::U32(key_data.size()));
            concatenated_secrets.append(MakeRange(size));
            concatenated_secrets.append(key_data);
        }
        auto fixed_info = utils::ByteUtils_ConcatWithSizes({
            "shared-secret/" + _algorithm,
            v4::PA_VERSION_STRING
        });
        auto X = cc7::ConcatByteRanges({
            MakeRange(ToBigEndian((U32)1)),
            concatenated_secrets,
            fixed_info
        });
        // KMAC-256(key: salt, message: X, size: 32, S: "KDF")
        // - Note that size is already set in v4.kmac256() algorithm configuration.
        return algorithms().v4.kmac256().token(salt, X, {
            { crypto::MAC_PARAM_CUSTOM_STRING, crypto::Parameter::ref("KDF") }
        });
    }
};

ISharedSecretPtr ISharedSecret::getInstance(PowerAuthSpec::Algorithm algorithm)
{
    auto spec = PowerAuthSpec::specForAlgorithm(algorithm);
    if (spec) {
        const auto& algs = algorithms().v4.pointers;
        switch (algorithm) {
            case PowerAuthSpec::EC_P384:
                return std::make_shared<SharedSecret>(spec, SharedSecret::KEMs {
                    { algs.key_DHKEM_P384_HKDF_SHA384, algs.kencap_DHKEM_P384_HKDF_SHA384 }
                });
            case PowerAuthSpec::EC_P384_ML_L3:
                return std::make_shared<SharedSecret>(spec, SharedSecret::KEMs {
                    { algs.key_DHKEM_P384_HKDF_SHA384, algs.kencap_DHKEM_P384_HKDF_SHA384 },
                    { algs.key_MLKEM_768,              algs.kencap_MLKEM_768 }
                });
            case PowerAuthSpec::EC_P384_ML_L5:
                return std::make_shared<SharedSecret>(spec, SharedSecret::KEMs {
                    { algs.key_DHKEM_P384_HKDF_SHA384, algs.kencap_DHKEM_P384_HKDF_SHA384 },
                    { algs.key_MLKEM_1024,             algs.kencap_MLKEM_1024 }
                });
            case PowerAuthSpec::ML_L3:
                return std::make_shared<SharedSecret>(spec, SharedSecret::KEMs {
                    { algs.key_MLKEM_768,              algs.kencap_MLKEM_768 }
                });
            case PowerAuthSpec::ML_L5:
                return std::make_shared<SharedSecret>(spec, SharedSecret::KEMs {
                    { algs.key_MLKEM_1024,             algs.kencap_MLKEM_1024 }
                });
            case PowerAuthSpec::LEGACY_P256:
                throw Exception(EC_InternalError, "ISharedSecret is unavailable for LEGACY_P256");
                
            default:
                break;
        }
    }
    throw Exception(EC_InternalError, "Unknown PowerAuth algorithm");
}

// MARK: - SharedSecretRequest

cc7::json::JsonValue SharedSecretRequest::toJson() const
{
    auto keys = json::JsonValue::array();
    for (const auto& keyData : encapsulationKeys) {
        keys.pushBack(json::JsonValue(keyData));
    }
    auto object = json::JsonValue::object();
    object.insert("algorithm", json::JsonValue(algorithm));
    object.insert("encapsulationKeys", keys);
    return object;
}

SharedSecretRequest SharedSecretRequest::fromJson(const cc7::json::JsonValue& value)
{
    std::vector<std::string> keys;
    for (const auto& key : value.arrayAtPath("encapsulationKeys")) {
        keys.push_back(key.asString());
    }
    return { value["algorithm"].asString(), keys };
}

// MARK: - SharedSecretResponse

cc7::json::JsonValue SharedSecretResponse::toJson() const
{
    auto keys = json::JsonValue::array();
    for (const auto& keyData : encapsulatedKeys) {
        keys.pushBack(json::JsonValue(keyData));
    }
    return json::JsonValue::object({
        { "salt", json::JsonValue(salt) },
        { "encapsulatedKeys", keys }
    });
}

SharedSecretResponse SharedSecretResponse::fromJson(const cc7::json::JsonValue& value)
{
    std::vector<std::string> keys;
    for (const auto& key : value["encapsulatedKeys"].asArray()) {
        keys.push_back(key.asString());
    }
    return {
        value["salt"].asString(),
        keys
    };
}

} // powerAuth
