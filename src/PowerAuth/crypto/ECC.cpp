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
    // MARK: - ECC routines -
    //
    const int ECC_CURVE = NID_X9_62_prime256v1;
    
    EC_KEY * ECC_ImportPublicKey(EC_KEY * key, const cc7::ByteRange & publicKey, BN_CTX * c)
    {
        bool result = false;
        
        BNContext ctx(c);
        
        if (!key) {
            // Create a new key if key object is null.
            key = EC_KEY_new_by_curve_name(ECC_CURVE);
        }
        const EC_GROUP * group = key ? EC_KEY_get0_group(key) : nullptr;
        EC_POINT *       point = key ? EC_POINT_new(group)    : nullptr;
        
        // If point is valid, then key & group is valid. Try to convert bytes to key and set it to
        // the key structure.
        if (point && (1 == EC_POINT_oct2point(group, point, publicKey.data(), publicKey.size(), ctx))) {
            // Set makes copy of key and therefore we have to cleanup point later
            result = (1 == EC_KEY_set_public_key(key, point));
            // Validate imported public key.
            result = result && (1 == EC_KEY_check_key(key));
        }
        
        if (point) {
            EC_POINT_free(point);
        }
        if (!result) {
            if (key) {
                // we don't care if key was created outside.
                // error typically means that whole structure is wrong
                // and useless.
                EC_KEY_free(key);
                key = nullptr;
            }
        }
        return key;
    }
    
    
    EC_KEY * ECC_ImportPublicKeyFromB64(EC_KEY * key, const std::string & publicKey, BN_CTX * c)
    {
        cc7::ByteArray keyData = cc7::FromBase64String(publicKey);
        if (keyData.empty()) {
            if (key) {
                // we don't care if key was created outside.
                // error typically means that whole structure is wrong
                // and useless.
                EC_KEY_free(key);
            }
            return nullptr;
        }
        return ECC_ImportPublicKey(key, keyData, c);
    }
    
    
    cc7::ByteArray ECC_ExportPublicKey(EC_KEY * key, BN_CTX * c)
    {
        BNContext ctx(c);
        if (!key) {
            return cc7::ByteArray();
        }
        const EC_POINT * publicKey = EC_KEY_get0_public_key(key);
        size_t expected_len = EC_POINT_point2oct(EC_KEY_get0_group(key), publicKey, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
        if (expected_len == 0) {
            return cc7::ByteArray();
        }
        cc7::ByteArray out(expected_len, 0);
        size_t written_len  = EC_POINT_point2oct(EC_KEY_get0_group(key), publicKey, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), ctx);
        if (expected_len != written_len) {
            out.clear();
        }
        return out;
        
    }
    
    
    std::string ECC_ExportPublicKeyToB64(EC_KEY * key, BN_CTX * c)
    {
        auto keyData = ECC_ExportPublicKey(key, c);
        return cc7::ToBase64String(keyData);
    }
    
    
    cc7::ByteArray ECC_ExportPublicKeyToNormalizedForm(EC_KEY * key, BN_CTX * c)
    {
        cc7::ByteArray out;
        do {
            if (!key) {
                break;
            }
            BNContext ctx(c);
            const EC_POINT * point = EC_KEY_get0_public_key(key);
            BIGNUM * x = BN_CTX_get(ctx);
            BIGNUM * y = BN_CTX_get(ctx);
            if (!x || !y || !point) {
                break;
            }
            const EC_GROUP * group = EC_KEY_get0_group(key);
            if (EC_POINT_is_at_infinity(group, point)) {
                break;
            }
            if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
                break;
            }
            // Export X to bytes...
            out.resize(BN_num_bytes(x));
            BN_bn2bin(x, out.data());
            
        } while (false);
        return out;
    }
    
    
    EC_KEY * ECC_ImportPrivateKey(EC_KEY * key, const cc7::ByteRange & privateKeyData, BN_CTX * c)
    {
        bool result = false;
        BNContext ctx(c);
        if (!key) {
            key = EC_KEY_new_by_curve_name(ECC_CURVE);
        }
        BIGNUM * s = BN_CTX_get(ctx);
        if (s && nullptr != BN_bin2bn(privateKeyData.data(), (int)privateKeyData.size(), s)) {
            result = (1 == EC_KEY_set_private_key(key, s));
        }
        if (!result) {
            EC_KEY_free(key);
            key = nullptr;
        }
        return key;
    }
    
    cc7::ByteArray ECC_ExportPrivateKey(EC_KEY * key, BN_CTX * c)
    {
        cc7::ByteArray keyData;
        const BIGNUM * private_key = EC_KEY_get0_private_key(key);
        keyData.resize(BN_num_bytes(private_key));
        BN_bn2bin(private_key, keyData.data());
        return keyData;
    }
    
    
    EC_KEY * ECC_GenerateKeyPair()
    {
        EC_KEY * key = EC_KEY_new_by_curve_name(ECC_CURVE);
        if (key) {
            if (1 != EC_KEY_generate_key(key)) {
                EC_KEY_free(key);
                key = nullptr;
            }
        }
        return key;
    }
    
    // -------------------------------------------------------------------------------------------
    // MARK: - ECDSA -
    //
    
    bool ECDSA_ValidateSignature(const cc7::ByteRange & signedData, const cc7::ByteRange & signature, EC_KEY * publicKey)
    {
        if (!publicKey) {
            CC7_ASSERT(false, "Missing public key");
            return false;
        }
        cc7::ByteArray signedDataHash = SHA256(signedData);
        if (signedDataHash.size() == 0) {
            return false;
        }
        int result = ECDSA_verify(0,
                                  signedDataHash.data(), (int)signedDataHash.size(),
                                  signature.data(),      (int)signature.size(),
                                  publicKey);
        return result == 1;
    }
    
    bool ECDSA_ComputeSignature(const cc7::ByteRange & data, EC_KEY * privateKey, cc7::ByteArray & signature)
    {
        if (!privateKey) {
            CC7_ASSERT(false, "Missing private key");
            return false;
        }
        cc7::ByteArray dataHash = SHA256(data);
        if (dataHash.size() == 0) {
            return false;
        }
        int expectedSize = ECDSA_size(privateKey);
        if (expectedSize <= 0) {
            return false;
        }
        signature.resize(expectedSize);
        unsigned int signatureSize = expectedSize;
        int result = ECDSA_sign(0,
                                dataHash.data(), (int)dataHash.size(),
                                signature.data(), &signatureSize,
                                privateKey);
        if (result != 1) {
            return false;
        }
        signature.resize(signatureSize);
        return true;
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
    
    cc7::ByteArray ECDH_SharedSecret(EC_KEY * pubKey, EC_KEY * priKey)
    {
        if (!pubKey || !priKey) {
            return cc7::ByteArray();
        }
        const EC_POINT * pubPoint =  EC_KEY_get0_public_key(pubKey);
        if (!pubPoint) {
            // You have provided key without public point
            return cc7::ByteArray();
        }
        // Calculate an expected size for shared secret.
        //  (check https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman for details)
        
        const EC_GROUP * group = EC_KEY_get0_group(priKey);
        size_t expectedSize = (EC_GROUP_get_degree(group) + 7) / 8;
        
        cc7::ByteArray secret(expectedSize, 0);
        int returnedSize = ECDH_compute_key(secret.data(), secret.size(), pubPoint, priKey, nullptr);
        if (returnedSize < 0 || (expectedSize != (size_t)returnedSize)) {
#ifdef DEBUG
            ERR_print_errors_fp(stderr);
#endif
            return cc7::ByteArray();
        }
        return secret;
    }
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
