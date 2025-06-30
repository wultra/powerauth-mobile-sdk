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

#include <PowerAuth/Types.h>
#include <PowerAuth/Algorithms.h>

namespace powerAuth {
namespace common {

/// Key transformation
struct KT
{
    enum Mode
    {
        ENCRYPT,
        DECRYPT
    };
    
    typedef cc7::ByteRange KeyRef;
    typedef cc7::ByteArray Key;
    

    struct INPUT
    {
        size_t keySize;
        bool allowEmpty = false;
    };
    
    struct CUSTOM
    {
        size_t keySize;
        bool allowEmpty = false;
    };
    
    struct KDF
    {
        std::string label;
        size_t keySize;
    };
    
    struct PKDF
    {
        size_t keySize;
    };
    
    struct PKDFKeys
    {
        KeyRef password;
        KeyRef salt;
    };
    
    struct AEAD
    {
        Mode mode;
        std::string keyContext;
    };
    
    struct AEADKeys
    {
        KeyRef kek;
        KeyRef data;
        KeyRef aad;
    };
    
    struct UKE
    {
        Mode mode;
    };
    
    struct UKEKeys
    {
        KeyRef kek;
        KeyRef data;
    };

    typedef std::function<Key()> CustomKeyProvider;
    typedef std::function<KeyRef()> KeyProvider;
    typedef std::function<PKDFKeys()> PKDFProvider;
    typedef std::function<AEADKeys()> AEADProvider;
    typedef std::function<UKEKeys()> UKEProvider;
    
    KT() = delete;
};

class SecretKeysPool
{
public:

    struct Config
    {
        int input_keys_end;
        int input_output_keys_end;
        int all_keys_count;
        
        size_t default_key_size;
        size_t heap_size = 1024;
        
        std::string (*key_name_resolver)(int key_id) = nullptr;
    };

    // TR::INPUT
    
    void setKey(int key_id, const KT::INPUT& tr, const cc7::ByteRange& key_material);
    cc7::ByteRange getKey(int key_id, const KT::INPUT& tr);
    
    // TR::KDF, PKDF
    
    cc7::ByteRange getKey(int key_id, const KT::KDF& tr, const KT::KeyProvider& source_key);
    cc7::ByteRange getKey(int key_id, const KT::PKDF& tr, const KT::PKDFProvider& keys_provider);
    
    // TR::AEAD
    
    cc7::ByteRange getKey(int key_id, const KT::AEAD& tr, const KT::AEADProvider& keys_provider);
    
    // TR::UKE
    
    cc7::ByteRange getKey(int key_id, const KT::UKE& tr, const KT::UKEProvider& keys_provider);
    
    // TR::CUSTOM
    
    cc7::ByteRange getKey(int key_id, const KT::CUSTOM& tr, const KT::CustomKeyProvider& derived_key);
    
    
    bool isSet(int key_id) const;
    void clearKey(int key_id);
    
    SecretKeysPool(const Config& config);
    
private:
    
    const Config _conf;
    std::vector<std::unique_ptr<cc7::ByteArray>> _heap;
    std::vector<std::unique_ptr<cc7::ByteArray>> _to_destroy;
    std::unique_ptr<cc7::ByteRange[]> _keys;

    void validateKeyId(int key_id, bool for_write) const;
    bool validateSize(size_t expected_size, bool allow_empty, size_t actual_size) const noexcept;
    
    cc7::ByteRange& keyRange(int key_id);
    const cc7::ByteRange& keyRange(int key_id) const;
        
    const cc7::ByteRange& allocateKey(int key_id, const cc7::ByteRange& key_material);
    
    std::string keyName(int key_id) const noexcept;
    
    static void throwError [[noreturn]] (ErrorCode ec, const std::string & message);
};


} // namespace common
} // namespace powerAuth
