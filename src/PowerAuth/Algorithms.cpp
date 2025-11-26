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

#include <PowerAuth/Algorithms.h>

#include "v4/PowerAuthKDF.h"
#include "v4/PowerAuthAEAD.h"
#include "v4/PowerAuthUKE.h"

#include "v3/LegacyKDF.h"
#include "v3/LegacyUKE.h"

using namespace cc7;
using namespace cc7::crypto;

namespace powerAuth {

Algorithms::V4::Pointers Algorithms::V4::build()
{
    // Cipher
    auto cipher_AES_256_CTR  = Cipher::getInstance("AES-256-CTR");
    auto aead_AES_256_GCM    = AEAD::getInstance("AES-256-GCM#I12T16D");
    // KeyFactory
    auto key_P384            = KeyPairFactory::getInstance("P-384");
    auto key_MLKEM_768       = KeyPairFactory::getInstance("ML-KEM-768");
    auto key_MLKEM_1024      = KeyPairFactory::getInstance("ML-KEM-1024");
    auto key_MLDSA_65        = KeyPairFactory::getInstance("ML-DSA-65");
    auto key_MLDSA_87        = KeyPairFactory::getInstance("ML-DSA-87");
    auto key_DHKEM_P384      = KeyPairFactory::getInstance("DHKEM-P384-HKDF-SHA384");
    // Signature
    auto sign_ECDSA_SHA2_256 = Signature::getInstance("ECDSA-SHA-256");
    auto sign_ECDSA_SHA2_384 = Signature::getInstance("ECDSA-SHA-384");
    auto sign_ECDSA_SHA3_256 = Signature::getInstance("ECDSA-SHA3-256");
    auto sign_MLDSA_65       = Signature::getInstance("ML-DSA-65");
    auto sign_MLDSA_87       = Signature::getInstance("ML-DSA-87");
    // KeyEncapsulation
    auto kencap_MLKEM_768    = KeyEncapsulation::getInstance("ML-KEM-768");
    auto kencap_MLKEM_1024   = KeyEncapsulation::getInstance("ML-KEM-1024");
    auto kencap_DHKEM_P384   = KeyEncapsulation::getInstance("DHKEM-P384-HKDF-SHA384");
    kencap_DHKEM_P384->setParameter(KEY_ENCAPSULATION_PARAM_INFO1, Parameter::ref(MakeRange("DHKEM-P384")));
    kencap_DHKEM_P384->setParameter(KEY_ENCAPSULATION_PARAM_INFO2, Parameter::ref(MakeRange("DHKEM-P384")));
    
    // MessageDigest
    auto hash_SHA3_256       = MessageDigest::getInstance("SHA3-256");
    // MAC
    auto mac_KMAC_256        = MAC::getInstance("KMAC-256");
    // Custom
    auto powerAuth_KDF       = std::make_shared<v4::PowerAuthKDF>(mac_KMAC_256);
    auto powerAuth_PBKDF     = std::make_shared<v4::PowerAuthPassKDF>(mac_KMAC_256);
    auto powerAuth_UKE       = std::make_shared<v4::PowerAuthUKE>(cipher_AES_256_CTR);
    auto powerAuth_AEAD      = std::make_shared<v4::PowerAuthAEAD>(powerAuth_KDF, cipher_AES_256_CTR, mac_KMAC_256);

    // Configure
    
    // Set default KMAC_256 output size to 32 bytes
    mac_KMAC_256->setParameter(MAC_PARAM_DIGEST_LENGTH, Parameter::take((size_t)32));
                               
    // Set P-384 public key encoding to compressed
    key_P384->setParameter(KEY_PARAM_EC_POINT_CONVERSION, Parameter::ref(EC_PUBLIC_KEY_CONVERSION_COMPRESSED));
    // Seal
    return {
        // Ciphers
        cipher_AES_256_CTR,
        aead_AES_256_GCM,
        // KeyFactory
        key_P384,
        key_MLKEM_768,
        key_MLKEM_1024,
        key_DHKEM_P384,
        key_MLDSA_65,
        key_MLDSA_87,
        // Signature
        sign_ECDSA_SHA2_256,
        sign_ECDSA_SHA2_384,
        sign_ECDSA_SHA3_256,
        sign_MLDSA_65,
        sign_MLDSA_87,
        // KeyEncapsulation
        kencap_MLKEM_768,
        kencap_MLKEM_1024,
        kencap_DHKEM_P384,
        // MessageDigest
        hash_SHA3_256,
        // MAC
        mac_KMAC_256,
        // Custom
        powerAuth_KDF,
        powerAuth_PBKDF,
        powerAuth_UKE,
        powerAuth_AEAD
    };

}

Algorithms::V3::Pointers Algorithms::V3::build()
{
    // Basic algorithms
    
    auto aes128_cbc         = Cipher::getInstance("AES-128-CBC");
    auto aes128_cbc_no_pad  = Cipher::getInstance("AES-128-CBC");
    auto aes128_ecb         = Cipher::getInstance("AES-128-ECB");
    auto ecdsaWithSha256    = Signature::getInstance("ECDSA-SHA-256");
    auto ecdhWithNullKdf    = KeyAgreement::getInstance("ECDH");
    auto p256               = KeyPairFactory::getInstance("P-256");
    auto sha256             = MessageDigest::getInstance("SHA-256");
    auto hmacWithSha256     = MAC::getInstance("HMAC-SHA-256");
    auto kdf_x963           = KeyDerivation::getInstance("X963KDF-SHA-256");
    auto pbkdf2_sha1        = KeyDerivation::getInstance("PBKDF2-HMAC-SHA-1");
    
    // Configure
    aes128_cbc_no_pad->setParameter(CIPHER_PARAM_USE_PADDING, Parameter::take(false));
    // set P-256 public key encoding to compressed
    p256->setParameter(KEY_PARAM_EC_POINT_CONVERSION, Parameter::ref(EC_PUBLIC_KEY_CONVERSION_COMPRESSED));
    // Alter PBKDF2-SHA1 KDF's output size to 16 bytes (signature key size)
    pbkdf2_sha1->setParameter(KDF_PARAM_KEY_SIZE, Parameter::take((size_t)16));

    // Build additional algorithms
    
    auto kdf                = std::make_shared<v3::LegacyKDF>(aes128_cbc_no_pad);
    auto kdf_internal       = std::make_shared<v3::LegacyKDFInternal>(hmacWithSha256);
    auto uke                = std::make_shared<v3::LegacyUKE>(aes128_cbc_no_pad);

    return {
        aes128_cbc,
        aes128_cbc_no_pad,
        aes128_ecb,
        ecdsaWithSha256,
        ecdhWithNullKdf,
        p256,
        sha256,
        hmacWithSha256,
        kdf_x963,
        pbkdf2_sha1,
        kdf,
        kdf_internal,
        uke
    };
}

Algorithms::Algorithms() : v3(), v4()
{
}

const Algorithms& Algorithms::shared()
{
    // Thread safe since C++11
    static Algorithms shared;
    return shared;
}

} // namespace powerAuth
