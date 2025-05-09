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

#include <cc7/crypto/Crypto.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{

class Algorithms
{
public:

    static const Algorithms & shared()
    {
        // Thread safe since C++11
        static Algorithms shared;
        return shared;
    }

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
    
    Algorithms();
    
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

static inline const Algorithms & algorithms()
{
    return Algorithms::shared();
}

} // io::getlime::powerAuth
} // io::getlime
} // io
