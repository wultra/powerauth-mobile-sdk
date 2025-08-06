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

#include "HybridKeyPair.h"
#include <cc7/utils/DataReader.h>
#include <cc7/utils/DataWriter.h>

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {
namespace v4 {

// MARK: - Low level data serialization

static ByteArray ExportHybridKeys(const KeyPtr& key1, const KeyPtr& key2)
{
    const auto is_hybrid = key2 != nullptr;
    
    cc7::utils::DataWriter writer;
    writer.openVersion('H', '1');
    writer.writeByte(is_hybrid);
    writer.writeString(key1->getKeyType());
    writer.writeData(key1->exportKey());
    if (is_hybrid) {
        writer.writeString(key2->getKeyType());
        writer.writeData(key2->exportKey());
    }
    writer.closeVersion();
    
    return writer.serializedData();
}

static void ImportHybridKeys(const KeyPtr& key1, const KeyPtr& key2, const ByteRange & serialized_key)
{
    const auto is_hybrid = key2 != nullptr;
    
    cc7::byte hybrid_marker = is_hybrid ? 0 : 1;
    std::string t1, t2;
    ByteRange data1, data2;

    cc7::utils::DataReader reader(serialized_key, false);
    auto result = reader.openVersion('H', '1', '1');
    result = result && reader.readByte(hybrid_marker);
    if (result && (bool)hybrid_marker != is_hybrid) {
        throw Exception(EC_InvalidData, "Expected number of stored keys doesn't match");
    }
    result = result && reader.readString(t1);
    result = result && reader.readRange(data1);
    if (is_hybrid) {
        result = result && reader.readString(t2);
        result = result && reader.readRange(data2);
    }
    result = result && reader.closeVersion();
    
    if (!result) {
        throw Exception(EC_InvalidData, "Invalid hybrid key data");
    }
    
    if (t1 != key1->getKeyType()) {
        throw Exception(EC_InvalidData, "Key1 has unsupported type");
    }
    if (is_hybrid && t2 != key2->getKeyType()) {
        throw Exception(EC_InvalidData, "Key2 has unsupported type");
    }
    try {
        key1->importKey(data1);
        if (is_hybrid) {
            key2->importKey(data2);
        }
    } catch (...) {
        Exception::reThrowWrapped(EC_InvalidData, "Key import failed");
    }
}

static std::string MakeAlgName(const std::string& a1, const std::string& a2)
{
    std::string an = "HYBRID:" + a1;
    if (!a2.empty()) {
        an += "+" + a2;
    }
    return an;
}


static std::string MakeKeyType(const KeyPtr& key1, const KeyPtr& key2)
{
    return MakeAlgName(key1->getKeyType(), key2 != nullptr ? key2->getKeyType() : "");
}

// MARK: - HybridPublicKey

class HybridPublicKey : public cc7::crypto::PublicKey
{
public:
    HybridPublicKey(PublicKeyPtr key1, PublicKeyPtr key2) :
        _key1(key1),
        _key2(key2),
        _key_type(MakeKeyType(key1, key2))
    {
    }
    
    HybridPublicKey(KeyPairPtr pair1, KeyPairPtr pair2) :
        _key1(pair1->getPublicKeyPtr()),
        _key2(pair2 != nullptr ? pair2->getPublicKeyPtr() : nullptr),
        _key_type(MakeKeyType(_key1, _key2))
    {
    }
    
    const std::string & getKeyType() const override
    {
        return _key_type;
    }
    
    void importKey(const ByteRange & keyData, KeyFormat format) override
    {
        if (format != KEY_FORMAT_RAW && format != KEY_FORMAT_DEFAULT) {
            throw std::invalid_argument("Key " + _key_type + " doesn't support format " + KeyFormat_ToString(format));
        }
        ImportHybridKeys(_key1, _key2, keyData);
    }
    
    ByteArray exportKey(KeyFormat format) const override
    {
        if (format != KEY_FORMAT_RAW && format != KEY_FORMAT_DEFAULT) {
            throw std::invalid_argument("Key " + _key_type + " doesn't support format " + KeyFormat_ToString(format));
        }
        return ExportHybridKeys(_key1, _key2);
    }
    
    Parameter getKeyParameter(int param_id) const override
    {
        switch (param_id) {
            case KEY_PARAM_HYBRID_KEY_1:
                return Parameter::take(_key1);
            case KEY_PARAM_HYBRID_KEY_2:
                return Parameter::take(_key2);

            default:
                throw std::invalid_argument("Unsupported parameter");
        }
    }
    
    void setKeyParameter(int param_id, const Parameter & value) override
    {
        throw std::invalid_argument("Unsupported parameter");
    }
    
    std::shared_ptr<Key> duplicate() const override
    {
        return std::make_shared<HybridPublicKey>(_key1, _key2);
    }
    
    const PublicKeyPtr& getKey1() const noexcept
    {
        return _key1;
    }

    const PublicKeyPtr& getKey2() const noexcept
    {
        return _key2;
    }
    
private:
    PublicKeyPtr _key1;
    PublicKeyPtr _key2;
    const std::string _key_type;
};

// MARK: - HybridPrivateKey

class HybridPrivateKey : public cc7::crypto::PrivateKey
{
public:
    HybridPrivateKey(PrivateKeyPtr key1, PrivateKeyPtr key2) :
        _key1(key1),
        _key2(key2),
        _key_type(MakeKeyType(key1, key2))
    {
    }
    
    HybridPrivateKey(KeyPairPtr pair1, KeyPairPtr pair2) :
        _key1(pair1->getPrivateKeyPtr()),
        _key2(pair2 != nullptr ? pair2->getPrivateKeyPtr() : nullptr),
        _key_type(MakeKeyType(_key1, _key2))
    {
    }
    
    const std::string & getKeyType() const override
    {
        return _key_type;
    }
    
    void importKey(const ByteRange & keyData, KeyFormat format) override
    {
        if (format != KEY_FORMAT_RAW && format != KEY_FORMAT_DEFAULT) {
            throw std::invalid_argument("Key " + _key_type + " doesn't support format " + KeyFormat_ToString(format));
        }
        ImportHybridKeys(_key1, _key2, keyData);
    }
    
    ByteArray exportKey(KeyFormat format) const override
    {
        if (format != KEY_FORMAT_RAW && format != KEY_FORMAT_DEFAULT) {
            throw std::invalid_argument("Key " + _key_type + " doesn't support format " + KeyFormat_ToString(format));
        }
        return ExportHybridKeys(_key1, _key2);
    }
    
    Parameter getKeyParameter(int param_id) const override
    {
        switch (param_id) {
            case KEY_PARAM_HYBRID_KEY_1:
                return Parameter::take(_key1);
            case KEY_PARAM_HYBRID_KEY_2:
                return Parameter::take(_key2);

            default:
                throw std::invalid_argument("Unsupported parameter");
        }
    }
    
    void setKeyParameter(int param_id, const Parameter & value) override
    {
        throw std::invalid_argument("Unsupported parameter");
    }
    
    std::shared_ptr<Key> duplicate() const override
    {
        return std::make_shared<HybridPrivateKey>(_key1, _key2);
    }
    
    const PrivateKeyPtr& getKey1() const noexcept
    {
        return _key1;
    }

    const PrivateKeyPtr& getKey2() const noexcept
    {
        return _key2;
    }


private:
    PrivateKeyPtr _key1;
    PrivateKeyPtr _key2;
    const std::string _key_type;
};


// MARK: - HybridKeyPairFactory


std::shared_ptr<HybridKeyPairFactory> HybridKeyPairFactory::getInstance(const std::string & key1_type, const std::string & key2_type)
{
    return std::make_shared<HybridKeyPairFactory>(HybridKeySpec {key1_type, key2_type});
}

HybridKeyPairFactory::HybridKeyPairFactory(const HybridKeySpec& spec) :
    _alg_name(MakeAlgName(spec.key1_type, spec.key2_type))
{
    _key1Factory = KeyPairFactory::getInstance(spec.key1_type);
    _key2Factory = spec.isHybrid() ? KeyPairFactory::getInstance(spec.key2_type) : nullptr;
}

PublicKeyPtr HybridKeyPairFactory::newPublicKey() const
{
    return std::make_shared<HybridPublicKey>(newPublicKey1(), newPublicKey2());
}

PrivateKeyPtr HybridKeyPairFactory::newPrivateKey() const
{
    return std::make_shared<HybridPrivateKey>(newPrivateKey1(), newPrivateKey2());
}

KeyPairPtr HybridKeyPairFactory::generateKeyPair() const
{
    auto pair1 = newKeyPair1();
    auto pair2 = newKeyPair2();
    auto pubKey = std::make_shared<HybridPublicKey>(pair1, pair2);
    auto privKey = std::make_shared<HybridPrivateKey>(pair1, pair2);
    return std::make_shared<KeyPair>(pubKey, privKey);
}

PublicKeyPtr HybridKeyPairFactory::newPublicKeyFromData(const cc7::ByteRange& key1_data,
                                                        cc7::crypto::KeyFormat key1_format,
                                                        const cc7::ByteRange& key2_data,
                                                        cc7::crypto::KeyFormat key2_format) const
{
    auto key1 = newPublicKey1();
    auto key2 = newPublicKey2();
    key1->importKey(key1_data, key1_format);
    if (key2 != nullptr) {
        key2->importKey(key2_data, key2_format);
    }
    return std::make_shared<HybridPublicKey>(key1, key2);
}

const std::string & HybridKeyPairFactory::getAlgorithmName() const
{
    return _alg_name;
}

void HybridKeyPairFactory::setParameter(int param_id, const cc7::crypto::Parameter & value)
{
    throw std::invalid_argument("Unsupported parameter ID=" + std::to_string(param_id));
}

cc7::crypto::Parameter HybridKeyPairFactory::getParameter(int param_id) const
{
    throw std::invalid_argument("Unsupported parameter ID=" + std::to_string(param_id));
}

bool HybridKeyPairFactory::isHybrid() const noexcept
{
    return _key2Factory != nullptr;
}

// MARK: - Helper functions

const crypto::PublicKey& HybridKey_GetKey1(const crypto::PublicKey& hybrid_key)
{
    auto hybrid = dynamic_cast<const HybridPublicKey*>(&hybrid_key);
    if (!hybrid) {
        throw Exception(EC_InternalError, "Key is not HybridPublicKey");
    }
    return *hybrid->getKey1();
}

const crypto::PublicKey& HybridKey_GetKey2(const crypto::PublicKey& hybrid_key)
{
    auto hybrid = dynamic_cast<const HybridPublicKey*>(&hybrid_key);
    if (!hybrid) {
        throw Exception(EC_InternalError, "Key is not HybridPublicKey");
    }
    const auto& key_ptr = hybrid->getKey2();
    if (!key_ptr) {
        throw Exception(EC_InternalError, "Hybrid key doesn't contain key #2");
    }
    return *key_ptr;
}

const crypto::PrivateKey& HybridKey_GetKey1(const crypto::PrivateKey& hybrid_key)
{
    auto hybrid = dynamic_cast<const HybridPrivateKey*>(&hybrid_key);
    if (!hybrid) {
        throw Exception(EC_InternalError, "Key is not HybridPrivateKey");
    }
    return *hybrid->getKey1();
}

const crypto::PrivateKey& HybridKey_GetKey2(const crypto::PrivateKey& hybrid_key)
{
    auto hybrid = dynamic_cast<const HybridPrivateKey*>(&hybrid_key);
    if (!hybrid) {
        throw Exception(EC_InternalError, "Key is not HybridPrivateKey");
    }
    const auto& key_ptr = hybrid->getKey2();
    if (!key_ptr) {
        throw Exception(EC_InternalError, "Hybrid key doesn't contain key #2");
    }
    return *key_ptr;
}

json::JsonValue HybridKey_ToJson(const crypto::PublicKey& hybrid_key, PowerAuthSpecPtr specification)
{
    auto result = cc7::json::JsonValue::object();
    result["ecdsa"] = cc7::json::JsonValue::base64(HybridKey_GetKey1(hybrid_key).exportKey(KEY_FORMAT_X963));
    if (specification->isHybrid()) {
        result["mldsa"] = cc7::json::JsonValue::base64(HybridKey_GetKey2(hybrid_key).exportKey(KEY_FORMAT_SPKI));
    }
    return result;
}

cc7::crypto::PublicKeyPtr HybridKey_FromJson(const cc7::json::JsonValue& key_data, const crypto::KeyPairFactory& key_pair_factory)
{
    auto hybrid_factory = dynamic_cast<const HybridKeyPairFactory*>(&key_pair_factory);
    if (!hybrid_factory) {
        throw Exception(EC_InternalError, "Factory is not HybridKeyPairFactory");
    }
    auto key1_data = key_data["ecdsa"].asBase64();
    auto key2_data = hybrid_factory->isHybrid() ? key_data["mldsa"].asBase64() : ByteArray();
    return hybrid_factory->newPublicKeyFromData(key1_data, KEY_FORMAT_X963, key2_data, KEY_FORMAT_SPKI);
}

} // namespace v4
} // namespace powerAuth
