/*
 * Copyright 2021 Wultra s.r.o.
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

#include "KDF.h"
#include "Hash.h"
#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <cc7/Endian.h>
#include "OSSLObjects.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

    // -------------------------------------------------------------------------------------------
    // MARK: - PBKDF2 -
    //
    
    cc7::ByteArray PBKDF2_HMAC_SHA1(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t output_bytes)
    {
        cc7::ByteArray result(output_bytes, 0);
        if (1 != PKCS5_PBKDF2_HMAC((const char*)pass.data(), (int)pass.size(), salt.data(), (int)salt.size(), (int)iterations, EVP_sha1(), (int)output_bytes, result.data())) {
            CC7_LOG("PKCS5_PBKDF2_HMAC has failed!");
            result.clear();
        }
        return result;
    }

    cc7::ByteArray PBKDF2_HMAC_SHA256(const cc7::ByteRange & pass, const cc7::ByteRange & salt, cc7::U32 iterations, size_t output_bytes)
    {
        cc7::ByteArray result(output_bytes, 0);
        if (1 != PKCS5_PBKDF2_HMAC((const char*)pass.data(), (int)pass.size(), salt.data(), (int)salt.size(), (int)iterations, EVP_sha256(), (int)output_bytes, result.data())) {
            CC7_LOG("PKCS5_PBKDF2_HMAC has failed!");
            result.clear();
        }
        return result;
    }
    
    
    // -------------------------------------------------------------------------------------------
    // MARK: - ECDH ANSI X9.63 -
    //

    /// Key derivation function from X9.63/SECG
    /// (copied from OpenSSL sources)
    static int ecdh_kdf_X9_63(unsigned char *out, size_t outlen,
                              const unsigned char *Z, size_t Zlen,
                              const unsigned char *sinfo, size_t sinfolen,
                              const EVP_MD *md)
    {
        int ret = 0;
        EVP_KDF_CTX *kctx = NULL;
        OSSL_PARAM params[4], *p = params;
        const char *mdname = EVP_MD_get0_name(md);
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_X963KDF, NULL);

        if ((kctx = EVP_KDF_CTX_new(kdf)) != NULL) {
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                    (char *)mdname, 0);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                     (void *)Z, Zlen);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                     (void *)sinfo, sinfolen);
            *p = OSSL_PARAM_construct_end();

            ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
            EVP_KDF_CTX_free(kctx);
        }
        EVP_KDF_free(kdf);
        return ret;
    }
    
    cc7::ByteArray ECDH_KDF_X9_63_SHA256(const cc7::ByteRange & secret, const cc7::ByteRange & info1, size_t output_bytes)
    {
        cc7::ByteArray result(output_bytes, 0);
        if (1 != ecdh_kdf_X9_63(result.data(), (int)output_bytes, secret.data(), (int)secret.size(), info1.data(), (int)info1.size(), EVP_sha256())) {
            CC7_LOG("ECDH_KDF_X9_62 has failed!");
            result.clear();
        }
        return result;
    }
    
/*
    // Reference implementation with using just SHA256 block
 
    cc7::ByteArray ref_ECDH_KDF_X9_63_SHA256(const cc7::ByteRange & secret, const cc7::ByteRange & info1, size_t outputBytes)
    {
        cc7::ByteArray result;
        cc7::ByteArray round, temp;
        round.reserve(secret.size() + info.size() + 4);

        cc7::byte counter[4];
        cc7::U32 i = 1;
        while (result.size() < outputBytes) {
            // Counter must be in Big Endian format
            cc7::U32 be_i = cc7::ToBigEndian(i);
            // Data for sha256: secret || i || info1
            round.assign(secret);
            round.append(cc7::MakeRange(be_i));
            round.append(info1);
            temp = SHA256(round);
            if (temp.size() == 0) {
                result.clear();
                break;
            }
            result.append(temp);
            ++i;
        }
        if (result.size() > outputBytes) {
            result.resize(outputBytes);
        }
        return result;
    }
*/
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io

