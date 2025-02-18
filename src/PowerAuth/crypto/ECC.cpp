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

#include "CryptoUtils.h"

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>

#include <cc7/Base64.h>

#include "../utils/DataReader.h"
#include "../utils/DataWriter.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{
    using namespace io::getlime::powerAuth;

    // -------------------------------------------------------------------------------------------
    // MARK: - Private functions -

    static inline bool IsECKey(const EVPKeyPair & key)
    {
        return key.isValid() && EVP_PKEY_get_id(key) == EVP_PKEY_EC;
    }

    static const char * CurveToName(EllipticCurve curve)
    {
        switch (curve) {
            case EllipticCurve::P256:
                return "P-256";
            case EllipticCurve::P384:
                return "P-384";
            default:
                return nullptr;
        }
    }

    static std::string GetGroupName(const EVPKeyPair & key)
    {
        std::string out;
        size_t name_len = 0;
        if (EVP_PKEY_get_group_name(key, NULL, 0, &name_len) == 1) {
            cc7::ByteArray data;
            data.resize(name_len);
            if (EVP_PKEY_get_group_name(key, (char*)data.data(), data.size(), &name_len) != 1) {
                out.assign((const char*)data.data(), data.size());
            }
        }
        return out;
    }

    static cc7::ByteArray GetKeyParameter(const EVPKeyPair & key, const char * param_name)
    {
        cc7::ByteArray out;
        size_t data_len = 0;
        if (EVP_PKEY_get_octet_string_param(key, param_name, nullptr, 0, &data_len)) {
            out.resize(data_len);
            if (!EVP_PKEY_get_octet_string_param(key, param_name, out.data(), out.size(), &data_len)) {
                out.clear();
                OSSL_print_errors();
            }
            out.resize(data_len);
        }
        return out;
    }


    static bool ValidatePublicKey(const EVPKeyPair & key)
    {
        BIGNUM * coord_x = nullptr;
        BIGNUM * coord_y = nullptr;
        // Extract X
        if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &coord_x)) {
            return false;
        }
        auto x = BigNum::take(coord_x);
        // Extract Y
        if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &coord_y)) {
            return false;
        }
        auto y = BigNum::take(coord_y);
        // Check infinity
        if (BN_is_zero(x) || BN_is_zero(y)) {
            return false;
        }
        return true;
    }


    // -------------------------------------------------------------------------------------------
    // MARK: - ECC routines -
    //

    EVPKeyPair ECC_ImportPublicKey(EllipticCurve curve, const cc7::ByteRange & publicKey)
    {
        while (true) {
            auto builder = OSSLParamBuilder::empty();
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, CurveToName(curve), 0);
            OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, publicKey.data(), publicKey.size());
            
            auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
            auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
            if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
                break;
            }
            EVP_PKEY * pkey = nullptr;
            if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
                break;
            }
            auto result = EVPKeyPair::take(pkey);
            if (!ValidatePublicKey(result)) {
                break;
            }
            return result;
        }
        OSSL_print_errors();
        return EVPKeyPair::invalid();
    }
    
    
    EVPKeyPair ECC_ImportPublicKeyFromB64(EllipticCurve curve, const std::string & publicKey)
    {
        cc7::ByteArray keyData = cc7::FromBase64String(publicKey);
        if (keyData.empty()) {
            return EVPKeyPair::invalid();
        }
        return ECC_ImportPublicKey(curve, keyData);
    }
    
    
    cc7::ByteArray ECC_ExportPublicKey(const EVPKeyPair & key, bool compressed)
    {
        cc7::ByteArray out;
        if (IsECKey(key)) {
            auto key_format = compressed ? OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED : OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
            if (EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, key_format)) {
                out = GetKeyParameter(key, OSSL_PKEY_PARAM_PUB_KEY);
            }
        }
        return out;
    }
    
    
    std::string ECC_ExportPublicKeyToB64(const EVPKeyPair & key, bool compressed)
    {
        auto keyData = ECC_ExportPublicKey(key, compressed);
        return cc7::ToBase64String(keyData);
    }
    
    
    cc7::ByteArray ECC_ExportPublicKeyToNormalizedForm(const EVPKeyPair & key)
    {
        cc7::ByteArray out;
        if (IsECKey(key)) {
            BIGNUM * coord_x = nullptr;
            if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &coord_x)) {
                out = BigNum_ToArray(BigNum::take(coord_x));
            }
        }
        return out;
    }
    
    
    EVPKeyPair ECC_ImportPrivateKey(EllipticCurve curve, const cc7::ByteRange & privateKeyData)
    {
        while (true) {
            auto builder = OSSLParamBuilder::empty();
            auto privateKeyBN = BigNum_FromArray(privateKeyData);
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, CurveToName(curve), 0);
            OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, privateKeyBN);
            
            auto params = OSSLParam::take(OSSL_PARAM_BLD_to_param(builder));
            auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
            if (!ctx.isValid() || EVP_PKEY_fromdata_init(ctx) <= 0) {
                break;
            }
            EVP_PKEY * pkey = nullptr;
            if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) <= 0) {
                break;
            }
            return EVPKeyPair::take(pkey);
        }
        OSSL_print_errors();
        return EVPKeyPair::invalid();
    }


    cc7::ByteArray ECC_ExportPrivateKey(const EVPKeyPair & key )
    {
        cc7::ByteArray out;
        if (IsECKey(key)) {
            BIGNUM * private_key = nullptr;
            if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &private_key)) {
                out = BigNum_ToArray(BigNum::take(private_key));
            }
        }
        return out;
    }
    
    
    EVPKeyPair ECC_GenerateKeyPair(EllipticCurve curve)
    {
        while (true) {
            auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL));
            if (!ctx.isValid()) {
                break;
            }
            // Initialize keygen
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                break;
            }
            // Set the curve
            if (EVP_PKEY_CTX_set_group_name(ctx, CurveToName(curve)) <= 0) {
                break;
            }
            EVP_PKEY * pkey = nullptr;
            if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
                break;
            }
            return EVPKeyPair::take(pkey);
        }
        OSSL_print_errors();
        return EVPKeyPair::invalid();
    }
    
    // -------------------------------------------------------------------------------------------
    // MARK: - ECDSA -
    //
    
    bool ECDSA_ValidateSignature(const cc7::ByteRange & signedData, const cc7::ByteRange & signature, const EVPKeyPair & publicKey)
    {
        bool result = false;
        do {
            if (!IsECKey(publicKey)) {
                break;
            }
            auto ctx = EVPMDContext::empty();
            if (!ctx.isValid()) {
                break;
            }
            if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) != 1) {
                break;
            }
            if (EVP_DigestVerifyUpdate(ctx, signedData.data(), signedData.size()) != 1) {
                break;
            }
            auto r = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
            result = r == 1;

        } while (false);
        
        if (!result) {
            OSSL_print_errors();
        }
        
        return result == 1;
    }
    
    bool ECDSA_ComputeSignature(const cc7::ByteRange & data, const EVPKeyPair & privateKey, cc7::ByteArray & signature)
    {
        bool result = false;
        do {
            if (!IsECKey(privateKey) || !EVP_PKEY_can_sign(privateKey)) {
                break;
            }
            auto ctx = EVPMDContext::empty();
            if (!ctx.isValid()) {
                break;
            }
            if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey) != 1) {
                break;
            }
            if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
                break;
            }
            size_t sig_length = 0;
            if (EVP_DigestSignFinal(ctx, nullptr, &sig_length) != 1) {
                break;
            }
            signature.resize(sig_length);
            if (EVP_DigestSignFinal(ctx, signature.data(), &sig_length) != 1) {
                break;
            }
            signature.resize(sig_length);
            result = true;
        } while (false);
        
        if (!result) {
            OSSL_print_errors();
        }
        
        return result;
    }

    // -------------------------------------------------------------------------------------------
    // MARK: - ECDSA Format -
    //
    
    static bool _DecodeAsn1ByteSequence(utils::DataReader & reader, cc7::ByteRange & out_data, size_t & out_size)
    {
        cc7::byte tmp;
        if (!reader.readByte(tmp) || tmp != 0x02) {
            // Invalid sequence header
            return false;
        }
        if (!reader.readAsn1Count(out_size)) {
            // Invalid size
            return false;
        }
        if (out_size > 33) {
            // Too big
            return false;
        }
        return reader.readMemoryRange(out_data, out_size);
    }

    cc7::ByteArray ECDSA_DERtoJOSE(const cc7::ByteRange & der_signature)
    {
        cc7::ByteArray out;
        auto reader = utils::DataReader(der_signature);
        
        cc7::byte tmp;
        // Read first byte (sequence)
        if (!reader.readByte(tmp) || tmp != 0x30) {
            return out;
        }
        size_t sign_length, r_length, s_length;
        cc7::ByteRange R, S;
        if (!reader.readAsn1Count(sign_length)) {
            return out;
        }
        // Overall length should match DER length - offset
        if (sign_length != der_signature.size() - reader.currentOffset()) {
            return out;
        }
        // Read R. 
        if (!_DecodeAsn1ByteSequence(reader, R, r_length)) {
            return out;
        }
        // Read S.
        if (!_DecodeAsn1ByteSequence(reader, S, s_length)) {
            return out;
        }
        
        // Everything looks fine. Now construct JOSE signature.
        out.reserve(64);
        
        // Append R
        if (r_length > 32) {
            out.append(R.subRangeFrom(r_length - 32));
        } else {
            if (r_length < 32) {
                out.append(32 - r_length, 0);
            }
            out.append(R);
        }
        // Append S
        if (s_length > 32) {
            out.append(S.subRangeFrom(s_length - 32));
        } else {
            if (s_length < 32) {
                out.append(32 - s_length, 0);
            }
            out.append(S);
        }
        return out;
    }

    static cc7::ByteArray _SkipPaddingBytes(const cc7::ByteRange & r)
    {
        cc7::ByteArray out;
        size_t offset = 0, size = r.size();
        while (offset != size) {
            if (r[offset] != 0) {
                break;
            }
            ++offset;
        }
        // If the encoded number is negative, then keep zero byte as prefix.
        if (r[offset] > 0x7F) {
            if (offset == 0) {
                // We're already at the beginning of range, so prepend zero before the sequence
                out.push_back(0);
            } else {
                // Offset is greater than 0, so we can copy zero from the padding
                offset--;
            }
        }
        out.append(r.subRangeFrom(offset));
        return out;
    }

    static cc7::ByteArray _EncodeAsn1ByteSequence(utils::DataWriter & writer, const cc7::ByteRange & bytes)
    {
        writer.reset();
        writer.writeByte(0x02);
        writer.writeAsn1Count(bytes.size());
        writer.writeMemory(bytes);
        return writer.serializedData();
    }

    cc7::ByteArray ECDSA_JOSEtoDER(const cc7::ByteRange & jose_signature)
    {
        if (jose_signature.size() != 64) {
            return cc7::ByteArray();
        }
        // Split input data into half and skip zero leading bytes for each parameter.
        auto R = _SkipPaddingBytes(jose_signature.subRangeTo(32));
        auto S = _SkipPaddingBytes(jose_signature.subRangeFrom(32));
        
        auto writer = utils::DataWriter();
        auto encoded_R = _EncodeAsn1ByteSequence(writer, R);
        auto encoded_S = _EncodeAsn1ByteSequence(writer, S);
        // Encode the whole sequence
        writer.reset();
        writer.writeByte(0x30);
        writer.writeAsn1Count(encoded_R.size() + encoded_S.size());
        writer.writeMemory(encoded_R);
        writer.writeMemory(encoded_S);
        return writer.serializedData();
    }

    // -------------------------------------------------------------------------------------------
    // MARK: - ECDH -
    //
    
    cc7::ByteArray ECDH_SharedSecret(const EVPKeyPair & publicKey, const EVPKeyPair & privateKey)
    {
        cc7::ByteArray out;
        do {
            if (!IsECKey(publicKey) || !IsECKey(privateKey)) {
                break;
            }
            if (GetGroupName(publicKey) != GetGroupName(privateKey)) {
                break;
            }
            auto ctx = EVPKeyPairContext::take(EVP_PKEY_CTX_new_from_pkey(NULL, privateKey, NULL));
            if (!ctx.isValid() || EVP_PKEY_derive_init(ctx) <= 0) {
                break;
            }
            
            if (EVP_PKEY_derive_set_peer_ex(ctx, publicKey, 1) <= 0) {
                break;
            }
            size_t key_size = 0;
            if (EVP_PKEY_derive(ctx, NULL, &key_size) <= 0) {
                break;
            }
            out.resize(key_size);
            if (EVP_PKEY_derive(ctx, out.data(), &key_size) <= 0) {
                out.clear();
                break;
            }
        } while (false);
        if (out.empty()) {
            OSSL_print_errors();
        }
        return out;
    }
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
