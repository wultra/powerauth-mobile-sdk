/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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
#include <openssl/ec.h>

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
	
	/**
	 Creates a new EC_KEY structure from given public key.
	 If key parameter is null then creates a new key.
	 If key parameter is not null and import fails then deletes key automatically.
	 */
	EC_KEY *		ECC_ImportPublicKey(EC_KEY * key, const cc7::ByteRange & publicKey, BN_CTX * c = nullptr);
	/**
	 Creates a new EC_KEY structure from given key encoded in B64 format.
	 If key parameter is null then creates a new key.
	 If key parameter is not null and import fails then deletes key automatically.
	 */
	EC_KEY *		ECC_ImportPublicKeyFromB64(EC_KEY * key, const std::string & publicKey, BN_CTX * c = nullptr);
	/**
	 Exports public key into compressed format.
	 */
	cc7::ByteArray	ECC_ExportPublicKey(EC_KEY * key, BN_CTX * c = nullptr);
	/**
	 Exports public key into compressed format, encoded into B64 string.
	 */
	std::string		ECC_ExportPublicKeyToB64(EC_KEY * key, BN_CTX * c = nullptr);
	/**
	 Exports public key into normalized form, suitable for decimalization.
	 This is equivalent operation to Java's: eccPublicKey.getW().getAffineX().toByteArray();
	 */
	cc7::ByteArray	ECC_ExportPublicKeyToNormalizedForm(EC_KEY * key, BN_CTX * c = nullptr);
	/**
	 Imports private key from given data.
	 If key parameter is null then creates a new key.
	 If key parameter is not null and import fails, then deletes provided key automatically.
	 */
	EC_KEY *		ECC_ImportPrivateKey(EC_KEY * key, const cc7::ByteRange & privateKeyData, BN_CTX * c = nullptr);
	/**
	 Exports private key into sequence of bytes.
	 */
	cc7::ByteArray	ECC_ExportPrivateKey(EC_KEY * key, BN_CTX * c = nullptr);
	/**
	 Generates a new ECC key pair.
	 */
	EC_KEY *		ECC_GenerateKeyPair();
	
	
	// -------------------------------------------------------------------------------------------
	// MARK: - ECDSA routines -
	//
	
	/**
	 Validates signature for signedData with given EC publicKey.
	 */
	bool			ECDSA_ValidateSignature(const cc7::ByteRange & signedData, const cc7::ByteRange & signature, EC_KEY * publicKey);
	/**
	 Computes signature for data with given private key.
	 */
	bool			ECDSA_ComputeSignature(const cc7::ByteRange & data, EC_KEY * privateKey, cc7::ByteArray & signature);
	
	// -------------------------------------------------------------------------------------------
	// MARK: - ECDH -
	
	/**
	 Calculates shared secret from public key and our private key. If the operation fails, then returns empty data.
	 */
	cc7::ByteArray	ECDH_SharedSecret(EC_KEY * pubKey, EC_KEY * priKey);
		
	
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io
