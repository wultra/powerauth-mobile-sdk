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

#include <cc7/ByteArray.h>

#include "LLObject.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
    /// The `BigNum` is wrapper for `BIGNUM`.
    typedef TLLObject<BIGNUM, BN_new, BN_free> BigNum;

    cc7::ByteArray BigNum_ToArray(const BigNum & bn);
    BigNum BigNum_FromArray(const cc7::ByteArray & array);

    /// The `BNContext` is wrapper for `BN_CTX`.
    typedef TLLObject<BN_CTX, BN_CTX_new, BN_CTX_free> BNContext;

    extern void EVPKeyPairRefUp(EVP_PKEY * pkey);

    /// The `EVPKeyPair` is wrapper for `EVP_PKEY`.
    typedef TLLRefObject<EVP_PKEY, EVP_PKEY_new, EVPKeyPairRefUp, EVP_PKEY_free> EVPKeyPair;

    /// The `EVPKeyPairCtx` is wrapper for `EVP_PKEY_CTX`.
    typedef TLLObject<EVP_PKEY_CTX, nullptr, EVP_PKEY_CTX_free> EVPKeyPairContext;

    /// The `OSSLParamBuilder` is wrapper for `OSSL_PARAM_BLD`.
    typedef TLLObject<OSSL_PARAM_BLD, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_free> OSSLParamBuilder;

    /// The `OSSLParam` is wrapper for `OSSL_PARAM`.
    typedef TLLObject<OSSL_PARAM, nullptr, OSSL_PARAM_free> OSSLParam;

    /// The `EVPMDContext` is wrapper for `EVP_MD_CTX`.
    typedef TLLObject<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free> EVPMDContext;

    /// The `EVPCipherContext` is wrapper for `EVP_CIPHER_CTX`.
    typedef TLLObject<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free> EVPCipherContext;

#if DEBUG
    #define OSSL_print_errors() ERR_print_errors_fp(stderr)
#else
    #define OSSL_print_errors()
#endif

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
