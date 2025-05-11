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
#include <PowerAuth/ECIES.h>
#include "protocol/Constants.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{

Algorithms::Algorithms() :
    _aes128_cbc(cc7::crypto::Cipher::getInstance("AES-128-CBC")),
    _aes128_cbc_no_pad(cc7::crypto::Cipher::getInstance("AES-128-CBC")),
    _aes128_ecb(cc7::crypto::Cipher::getInstance("AES-128-ECB")),
    _ecdsaWithSha256(cc7::crypto::Signature::getInstance("ECDSA-SHA-256")),
    _ecdhWithNullKdf(cc7::crypto::KeyAgreement::getInstance("ECDH")),
    _p256(cc7::crypto::KeyPairFactory::getInstance("P-256")),
    _sha256(cc7::crypto::MessageDigest::getInstance("SHA-256")),
    _hmacWithSha256(cc7::crypto::MAC::getInstance("HMAC-SHA-256")),
    _kdf_x963(cc7::crypto::KeyDerivation::getInstance("X963KDF-SHA-256")),
    _pbkdf2_sha1(cc7::crypto::KeyDerivation::getInstance("PBKDF2-HMAC-SHA-256"))
{
    _aes128_cbc_no_pad->setParameter(cc7::crypto::CIPHER_PARAM_USE_PADDING, cc7::crypto::Parameter::take(false));
    // set P-256 public key encoding to compressed
    _p256->setParameter(cc7::crypto::KEY_PARAM_EC_POINT_CONVERSION, cc7::crypto::Parameter::ref(cc7::crypto::EC_PUBLIC_KEY_CONVERSION_COMPRESSED));
    // Alter X9.63 KDF's output size to 48 bytes
    _kdf_x963->setParameter(cc7::crypto::KDF_PARAM_KEY_SIZE, cc7::crypto::Parameter::take(ECIESEnvelopeKey::EnvelopeKeySize));
    // Alter PBKDF2-SHA1 KDF's output size to 16 bytes (signature key size)
    _pbkdf2_sha1->setParameter(cc7::crypto::KDF_PARAM_KEY_SIZE, cc7::crypto::Parameter::take(protocol::SIGNATURE_KEY_SIZE));
}

} // io::getlime::powerAuth
} // io::getlime
} // io
