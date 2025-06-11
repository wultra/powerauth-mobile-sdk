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

#include <cc7/CC7.h>

namespace powerAuth {

// Forward declaration of private types
namespace crypto
{
    class PowerAuthKDF;
    class PowerAuthPassKDF;
    class PowerAuthAEAD;
    class HybridKeyPairFactory;
    class HybridSignature;
}

class Algorithms
{
public:
    
    class V4
    {
    public:
                
        const cc7::crypto::Cipher& aes256Ctr()
        {
            return *pointers.cipher_AES_256_CTR;
        }
        
        const cc7::crypto::AEAD& aeadAes256Gcm()
        {
            return *pointers.aead_AES_256_GCM;
        }
        
        const cc7::crypto::KeyPairFactory& p384() const
        {
            return *pointers.key_P384;
        }
        
        const cc7::crypto::Signature& ecdsaWithSha3_256() const
        {
            return *pointers.sign_ECDSA_SHA3_256;
        }
        
        const cc7::crypto::Signature& ecdsaWithSha2_256() const
        {
            return *pointers.sign_ECDSA_SHA2_256;
        }
        
        const cc7::crypto::Signature& ecdsaWithSha2_384() const
        {
            return *pointers.sign_ECDSA_SHA2_384;
        }
        
        const cc7::crypto::Signature& mldsa65() const
        {
            return *pointers.sign_MLDSA_65;
        }
        
        const cc7::crypto::KeyEncapsulation& mlkem768() const
        {
            return *pointers.kencap_MLKEM_768;
        }
        
        const cc7::crypto::KeyPairFactory& mldsa65key() const
        {
            return *pointers.key_MLDSA_65;
        }
        
        const cc7::crypto::KeyPairFactory& mlkem768key() const
        {
            return *pointers.key_MLKEM_768;
        }
        
        const cc7::crypto::KeyAgreement& ecdhWithNullKdf() const
        {
            return *pointers.kagree_ECDH_NULLKDF;
        }
        
        const cc7::crypto::MessageDigest& sha3_256() const
        {
            return *pointers.hash_SHA3_256;
        }
        
        const cc7::crypto::MAC& kmac256() const
        {
            return *pointers.mac_KMAC_256;
        }
        
        
        // Protocol specific
        
        const crypto::PowerAuthKDF & kdf() const
        {
            return *pointers.powerAuth_KDF;
        }
        
        const crypto::PowerAuthPassKDF & pbkdf() const
        {
            return *pointers.powerAuth_PBKDF;
        }
        
        const cc7::crypto::AEAD & aead() const
        {
            return *pointers.powerAuth_AEAD;
        }
        
        struct Pointers
        {
            cc7::crypto::CipherPtr cipher_AES_256_CTR;
            cc7::crypto::AEADPtr aead_AES_256_GCM;
            
            cc7::crypto::KeyPairFactoryPtr key_P384;
            cc7::crypto::KeyPairFactoryPtr key_MLKEM_768;
            cc7::crypto::KeyPairFactoryPtr key_MLDSA_65;
            
            
            cc7::crypto::SignaturePtr sign_ECDSA_SHA2_256;
            cc7::crypto::SignaturePtr sign_ECDSA_SHA2_384;
            cc7::crypto::SignaturePtr sign_ECDSA_SHA3_256;
            cc7::crypto::SignaturePtr sign_MLDSA_65;
            
            cc7::crypto::KeyEncapsulationPtr kencap_MLKEM_768;
            cc7::crypto::KeyAgreementPtr kagree_ECDH_NULLKDF;
            
            cc7::crypto::MessageDigestPtr hash_SHA3_256;
            cc7::crypto::MACPtr mac_KMAC_256;
            
            std::shared_ptr<crypto::PowerAuthKDF> powerAuth_KDF;
            std::shared_ptr<crypto::PowerAuthPassKDF> powerAuth_PBKDF;
            cc7::crypto::AEADPtr powerAuth_AEAD;
        };
        
        const Pointers pointers;
        
    private:
        friend class Algorithms;
        V4() : pointers(build()) {}
        static Pointers build();
    };
    
    class V3
    {
    public:
        const cc7::crypto::Cipher & aes128cbc() const
        {
            return *_aes128_cbc;
        }
        
        const cc7::crypto::Cipher & aes128cbcNoPad() const
        {
            return *_aes128_cbc_no_pad;
        }
        
        /// ECB mode is used only as simple KDF function.
        const cc7::crypto::Cipher & aes128ecb() const
        {
            return *_aes128_ecb;
        }
        
        const cc7::crypto::Signature & ecdsaWithSha256() const
        {
            return *_ecdsaWithSha256;
        }
        
        const cc7::crypto::MAC & hmacWithSha256() const
        {
            return *_hmacWithSha256;
        }
        
        const cc7::crypto::MessageDigest & sha256() const
        {
            return *_sha256;
        }
        
        const cc7::crypto::KeyPairFactory & p256() const
        {
            return *_p256;
        }
        
        const cc7::crypto::KeyDerivation & kdfX963() const
        {
            return *_kdf_x963;
        }
        
        const cc7::crypto::KeyDerivation & pbkdf2WithSha1() const
        {
            return *_pbkdf2_sha1;
        }
        
        const cc7::crypto::KeyAgreement & ecdhWithNullKdf() const
        {
            return *_ecdhWithNullKdf;
        }
        
    private:
        friend class Algorithms;
        V3();
        
        const cc7::crypto::CipherPtr _aes128_cbc;
        const cc7::crypto::CipherPtr _aes128_cbc_no_pad;
        const cc7::crypto::CipherPtr _aes128_ecb;
        
        const cc7::crypto::SignaturePtr _ecdsaWithSha256;
        const cc7::crypto::KeyAgreementPtr _ecdhWithNullKdf;
        const cc7::crypto::KeyPairFactoryPtr _p256;
        
        const cc7::crypto::MessageDigestPtr _sha256;
        
        const cc7::crypto::MACPtr _hmacWithSha256;
        
        const cc7::crypto::KeyDerivationPtr _kdf_x963;
        const cc7::crypto::KeyDerivationPtr _pbkdf2_sha1;
    };
    
public:
    
    const V4 v4;
    const V3 v3;

    static const Algorithms & shared();
    
private:
    
    Algorithms();
};

static inline const Algorithms & algorithms()
{
    return Algorithms::shared();
}

} // namespace powerAuth
