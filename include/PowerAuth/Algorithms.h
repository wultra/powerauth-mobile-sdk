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
namespace v4
{
    class PowerAuthKDF;
    class PowerAuthPassKDF;
    class PowerAuthAEAD;
    class PowerAuthUKE;
    class HybridKeyPairFactory;
    class HybridSignature;
}
namespace v3
{
    class LegacyKDF;
    class LegacyKDFInternal;
    class LegacyUKE;
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
        
        const cc7::crypto::KeyEncapsulation& mlkem1024() const
        {
            return *pointers.kencap_MLKEM_1024;
        }
        
        const cc7::crypto::KeyPairFactory& mldsa65key() const
        {
            return *pointers.key_MLDSA_65;
        }
        
        const cc7::crypto::KeyPairFactory& mldsa87key() const
        {
            return *pointers.key_MLDSA_87;
        }
        
        const cc7::crypto::KeyPairFactory& mlkem768key() const
        {
            return *pointers.key_MLKEM_768;
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
        
        const v4::PowerAuthKDF & kdf() const
        {
            return *pointers.powerAuth_KDF;
        }
        
        const v4::PowerAuthPassKDF & pbkdf() const
        {
            return *pointers.powerAuth_PBKDF;
        }
        
        const v4::PowerAuthUKE & uke() const
        {
            return *pointers.powerAuth_UKE;
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
            cc7::crypto::KeyPairFactoryPtr key_MLKEM_1024;
            cc7::crypto::KeyPairFactoryPtr key_DHKEM_P384_HKDF_SHA384;
            cc7::crypto::KeyPairFactoryPtr key_MLDSA_65;
            cc7::crypto::KeyPairFactoryPtr key_MLDSA_87;
            
            cc7::crypto::SignaturePtr sign_ECDSA_SHA2_256;
            cc7::crypto::SignaturePtr sign_ECDSA_SHA2_384;
            cc7::crypto::SignaturePtr sign_ECDSA_SHA3_256;
            cc7::crypto::SignaturePtr sign_MLDSA_65;
            cc7::crypto::SignaturePtr sign_MLDSA_87;
            
            cc7::crypto::KeyEncapsulationPtr kencap_MLKEM_768;
            cc7::crypto::KeyEncapsulationPtr kencap_MLKEM_1024;
            cc7::crypto::KeyEncapsulationPtr kencap_DHKEM_P384_HKDF_SHA384;
            
            cc7::crypto::MessageDigestPtr hash_SHA3_256;
            cc7::crypto::MACPtr mac_KMAC_256;
            
            std::shared_ptr<v4::PowerAuthKDF> powerAuth_KDF;
            std::shared_ptr<v4::PowerAuthPassKDF> powerAuth_PBKDF;
            std::shared_ptr<v4::PowerAuthUKE> powerAuth_UKE;
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
            return *pointers.aes128_cbc;
        }
        
        const cc7::crypto::Cipher & aes128cbcNoPad() const
        {
            return *pointers.aes128_cbc_no_pad;
        }
        
        /// ECB mode is used only as simple KDF function.
        const cc7::crypto::Cipher & aes128ecb() const
        {
            return *pointers.aes128_ecb;
        }
        
        const cc7::crypto::Signature & ecdsaWithSha256() const
        {
            return *pointers.ecdsaWithSha256;
        }
        
        const cc7::crypto::MAC & hmacWithSha256() const
        {
            return *pointers.hmacWithSha256;
        }
        
        const cc7::crypto::MessageDigest & sha256() const
        {
            return *pointers.sha256;
        }
                
        const cc7::crypto::KeyPairFactory & p256() const
        {
            return *pointers.p256;
        }
        
        const cc7::crypto::KeyDerivation & kdfX963() const
        {
            return *pointers.kdf_x963;
        }
        
        const cc7::crypto::KeyDerivation & pbkdf2WithSha1() const
        {
            return *pointers.pbkdf2_sha1;
        }
        
        const cc7::crypto::KeyAgreement & ecdhWithNullKdf() const
        {
            return *pointers.ecdhWithNullKdf;
        }
        
        const v3::LegacyUKE& uke() const
        {
            return *pointers.powerAuth_UKE;
        }
        
        const v3::LegacyKDF& kdf() const
        {
            return *pointers.powerAuth_KDF;
        }
        
        const v3::LegacyKDFInternal& kdfInternal() const
        {
            return *pointers.powerAuth_KDF_Internal;
        }
        
        struct Pointers
        {
            const cc7::crypto::CipherPtr aes128_cbc;
            const cc7::crypto::CipherPtr aes128_cbc_no_pad;
            const cc7::crypto::CipherPtr aes128_ecb;
            
            const cc7::crypto::SignaturePtr ecdsaWithSha256;
            const cc7::crypto::KeyAgreementPtr ecdhWithNullKdf;
            const cc7::crypto::KeyPairFactoryPtr p256;
            
            const cc7::crypto::MessageDigestPtr sha256;
            
            const cc7::crypto::MACPtr hmacWithSha256;
            
            const cc7::crypto::KeyDerivationPtr kdf_x963;
            const cc7::crypto::KeyDerivationPtr pbkdf2_sha1;
            
            const std::shared_ptr<v3::LegacyKDF> powerAuth_KDF;
            const std::shared_ptr<v3::LegacyKDFInternal> powerAuth_KDF_Internal;
            const std::shared_ptr<v3::LegacyUKE> powerAuth_UKE;
            
        };

        const Pointers pointers;
        
    private:
        friend class Algorithms;
        friend class Algorithms;
        V3() : pointers(build()) {}
        static Pointers build();
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
