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
#include "OSSLObjects.h"

/*
 Note that all functionality provided by this header will
 be replaced with a similar cc7 implementation.
 */

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

    // -------------------------------------------------------------------------------------------
    // MARK: - ECC key routines -
    //
    
    enum EllipticCurve {
        P256,
        P384
    };

    /**
     Creates a new EVPKeyPair from given public key.
     */
    EVPKeyPair      ECC_ImportPublicKey(EllipticCurve curve, const cc7::ByteRange & publicKeyData);
    /**
     Creates a new EVPKeyPair from given key encoded in B64 format.
     */
    EVPKeyPair      ECC_ImportPublicKeyFromB64(EllipticCurve curve, const std::string & publicKeyBase64);
    /**
     Exports public key into compressed format.
     */
    cc7::ByteArray  ECC_ExportPublicKey(const EVPKeyPair & key, bool compressed = true);
    /**
     Exports public key into compressed format, encoded into B64 string.
     */
    std::string     ECC_ExportPublicKeyToB64(const EVPKeyPair & key, bool compressed = true);
    /**
     Exports public key into normalized form, suitable for decimalization.
     This is equivalent operation to Java's: eccPublicKey.getW().getAffineX().toByteArray();
     */
    cc7::ByteArray  ECC_ExportPublicKeyToNormalizedForm(const EVPKeyPair & key);
    /**
     Imports private key from given data.
     */
    EVPKeyPair      ECC_ImportPrivateKey(EllipticCurve curve, const cc7::ByteRange & privateKeyData);
    /**
     Exports private key into sequence of bytes.
     */
    cc7::ByteArray  ECC_ExportPrivateKey(const EVPKeyPair & key);
    /**
     Generates a new key pair.
     */
    EVPKeyPair      ECC_GenerateKeyPair(EllipticCurve curve);
    
    
    // -------------------------------------------------------------------------------------------
    // MARK: - ECDSA routines -
    //
    
    /**
     Validates signature for signedData with given EC publicKey.
     */
    bool            ECDSA_ValidateSignature(const cc7::ByteRange & signedData, const cc7::ByteRange & signature, const EVPKeyPair & publicKey);
    /**
     Computes signature for data with given private key.
     */
    bool            ECDSA_ComputeSignature(const cc7::ByteRange & data, const EVPKeyPair & privateKey, cc7::ByteArray & signature);

    /**
     Convert ECDSA signature from DER format to JOSE. If operation fails, then returned array is empty.
     */
    cc7::ByteArray  ECDSA_DERtoJOSE(const cc7::ByteRange & der_signature);
    /**
     Convert ECDSA signature from JOSE to DER format. If operation fails, then returned array is empty.
     */
    cc7::ByteArray  ECDSA_JOSEtoDER(const cc7::ByteRange & jose_signature);
    
    // -------------------------------------------------------------------------------------------
    // MARK: - ECDH -
    
    /**
     Calculates shared secret from public key and our private key. If the operation fails, then returns empty data.
     */
    cc7::ByteArray  ECDH_SharedSecret(const EVPKeyPair & publicKey, const EVPKeyPair & privateKey);
        
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
