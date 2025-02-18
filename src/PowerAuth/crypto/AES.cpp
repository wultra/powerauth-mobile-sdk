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

#include "AES.h"
#include "PKCS7Padding.h"
#include "OSSLObjects.h"


namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
    const EVP_CIPHER * CipherCBCFromKey(const cc7::ByteRange & key)
    {
        switch (key.size()) {
            case 16:
                return EVP_aes_128_cbc();
            case 24:
                return EVP_aes_192_cbc();
            case 32:
                return EVP_aes_256_cbc();
            default:
                return nullptr;
        }
    }
    
    cc7::ByteArray AES_CBC_Encrypt(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
    {
        cc7::ByteArray out(data.size(), 0);
        cc7::ByteArray ivec = iv;
        
        auto ctx = EVPCipherContext::empty();
        if (EVP_EncryptInit(ctx, CipherCBCFromKey(key), key.data(), iv.data()) != 1) {
            out.clear();
            return out;
        }
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
            out.clear();
            return out;
        }
        int out_length = 0;
        if (EVP_EncryptUpdate(ctx, out.data(), &out_length, data.data(), (int)data.size()) != 1) {
            out.clear();
            return out;
        }
        if (out_length != data.length()) {
            out.clear();
        }
        return out;
    }
    
    
    cc7::ByteArray AES_CBC_Decrypt(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
    {
        cc7::ByteArray out(data.size(), 0);
        cc7::ByteArray ivec(iv);
        
        auto ctx = EVPCipherContext::empty();
        if (EVP_DecryptInit(ctx, CipherCBCFromKey(key), key.data(), iv.data()) != 1) {
            out.clear();
            return out;
        }
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
            out.clear();
            return out;
        }
        int out_length = 0;
        if (EVP_DecryptUpdate(ctx, out.data(), &out_length, data.data(), (int)data.size()) != 1) {
            out.clear();
            return out;
        }
        if (out_length != data.length()) {
            out.clear();
        }        
        return out;
    }
    
    
    cc7::ByteArray AES_CBC_Decrypt_Padding(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data, bool * error)
    {
        cc7::ByteArray paddedData = AES_CBC_Decrypt(key, iv, data);
        bool failure = !PKCS7_ValidateAndUpdateData(paddedData, AES_BLOCK_SIZE);
        if (failure) {
            paddedData.clear();
        }
        if (error) {
            *error = failure;
        }
        return paddedData;
    }
    
    
    cc7::ByteArray AES_CBC_Encrypt_Padding(const cc7::ByteRange & key, const cc7::ByteRange & iv, const cc7::ByteRange & data)
    {
        cc7::ByteArray paddedData = PKCS7_GetPaddedData(data, AES_BLOCK_SIZE);
        return AES_CBC_Encrypt(key, iv, paddedData);
    }
    

} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
