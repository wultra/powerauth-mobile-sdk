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

#pragma once

#include <PowerAuth/PowerAuthSpec.h>
#include <cc7/crypto/KeyPair.h>

namespace powerAuth {
namespace v4 {

enum CustomKeyParamIdentifier
{
    /// Getting instance of key #1 from the hybrid key.
    KEY_PARAM_HYBRID_KEY_1 = cc7::crypto::KEY_PARAM_APP_CUSTOM,
    /// Setting instance of key #2 from the hybrid key.
    KEY_PARAM_HYBRID_KEY_2
};

struct HybridKeySpec
{
    std::string key1_type;
    std::string key2_type;
    
    bool isHybrid() const { return !key2_type.empty(); }
};

class HybridKeyPairFactory : public cc7::crypto::KeyPairFactory
{
public:
    
    using cc7::crypto::KeyPairFactory::newPublicKey;
    using cc7::crypto::KeyPairFactory::newPrivateKey;
    
    static std::shared_ptr<HybridKeyPairFactory> getInstance(const std::string & key1_type, const std::string & key2_type);
    
    cc7::crypto::PublicKeyPtr newPublicKey() const override;
    cc7::crypto::PrivateKeyPtr newPrivateKey() const override;
    cc7::crypto::KeyPairPtr generateKeyPair() const override;
    
    const std::string & getAlgorithmName() const override;
    void setParameter(int param_id, const cc7::crypto::Parameter & value) override;
    cc7::crypto::Parameter getParameter(int param_id) const override;
    
    HybridKeyPairFactory(const HybridKeySpec& spec);
    
    // Custom interface
    
    cc7::crypto::PublicKeyPtr newPublicKeyFromData(const cc7::ByteRange& key1_data,
                                                   cc7::crypto::KeyFormat key1_format,
                                                   const cc7::ByteRange& key2_data,
                                                   cc7::crypto::KeyFormat key2_format) const;
    
    bool isHybrid() const noexcept;
    
private:
    
    cc7::crypto::PublicKeyPtr newPublicKey1() const
    {
        return _key1Factory->newPublicKey();
    }
    
    cc7::crypto::PublicKeyPtr newPublicKey2() const
    {
        return _key2Factory != nullptr ? _key2Factory->newPublicKey() : nullptr;
    }
    
    cc7::crypto::PrivateKeyPtr newPrivateKey1() const
    {
        return _key1Factory->newPrivateKey();
    }
    
    cc7::crypto::PrivateKeyPtr newPrivateKey2() const
    {
        return _key2Factory != nullptr ? _key2Factory->newPrivateKey() : nullptr;
    }
    
    cc7::crypto::KeyPairPtr newKeyPair1() const
    {
        return _key1Factory->generateKeyPair();
    }
    
    cc7::crypto::KeyPairPtr newKeyPair2() const
    {
        return _key2Factory != nullptr ? _key2Factory->generateKeyPair() : nullptr;
    }

    const std::string _alg_name;
    cc7::crypto::KeyPairFactoryPtr _key1Factory;
    cc7::crypto::KeyPairFactoryPtr _key2Factory;
};

// Helper functions
const cc7::crypto::PublicKey& HybridKey_GetKey1(const cc7::crypto::PublicKey& hybrid_key);
const cc7::crypto::PublicKey& HybridKey_GetKey2(const cc7::crypto::PublicKey& hybrid_key);
const cc7::crypto::PublicKeyPtr& HybridKey_GetKey1Ptr(const cc7::crypto::PublicKey& hybrid_key);
const cc7::crypto::PublicKeyPtr& HybridKey_GetKey2Ptr(const cc7::crypto::PublicKey& hybrid_key);

cc7::json::JsonValue      HybridKey_ToJson(const cc7::crypto::PublicKey& hybrid_key, PowerAuthSpecPtr specification);
cc7::crypto::PublicKeyPtr HybridKey_FromJson(const cc7::json::JsonValue& key_data, const cc7::crypto::KeyPairFactory& key_pair_factory);

const cc7::crypto::PrivateKey& HybridKey_GetKey1(const cc7::crypto::PrivateKey& hybrid_key);
const cc7::crypto::PrivateKey& HybridKey_GetKey2(const cc7::crypto::PrivateKey& hybrid_key);
const cc7::crypto::PrivateKeyPtr& HybridKey_GetKey1Ptr(const cc7::crypto::PrivateKey& hybrid_key);
const cc7::crypto::PrivateKeyPtr& HybridKey_GetKey2Ptr(const cc7::crypto::PrivateKey& hybrid_key);

} // namespace v4
} // namespace powerAuth
