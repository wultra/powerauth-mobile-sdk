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

#include "PrivateTypes.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
	//
	// MARK: - Helpers and utilities related to PA2 -
	//

	/**
	 Validates "shortId-OTP" sequence with provided master key and signature
	 */
	bool ValidateShortIdAndOtpSignature(const std::string & sid, const std::string & otp, const std::string & sig, EC_KEY * mk);
	
	/**
	 Validates "activationId&cServerPublicKeyB64" sequence with provided master key and signature.
	 */
	bool ValidateActivationDataSignature(const std::string & activationId, const std::string & cServerPublicKeyB64, const cc7::ByteRange & sig, EC_KEY * mk);
	
	/**
	 Expands activationId & otp into bigger key, with using PBKDF2 derivation.
	 */
	cc7::ByteArray ExpandOTPKey(const std::string & activationIdShort, const std::string & otp);
	
	/**
	 Encrypts device public key with key, derived from activationIdShort and otp. The function
	 reads key from ActivationData structure and writes expandedOtp into the same structure.
	 */
	cc7::ByteArray EncryptDevicePublicKey(ActivationData & ad, const std::string & activationIdShort, const std::string & otp);
	
	/**
	 Decrypts encryptedPk with our private key & ephemeralKey. The function requires several
	 attributes available in the ActivationData structure and stores result there.
	 */
	bool DecryptServerPublicKey(ActivationData & ad, const cc7::ByteRange & ephemeral, const cc7::ByteRange & encryptedPk, const cc7::ByteRange & nonce);
	
	/**
	 Reduces size of shared secret produced in ECDH.
	 */
	cc7::ByteArray ReduceSharedSecret(const cc7::ByteRange & secret);
	
	/**
	 Derives indexed secret key based on secret.
	 */
	cc7::ByteArray DeriveSecretKey(const cc7::ByteRange & secret, cc7::U64 index);
	
	/**
	 Calculates all secret keys and vaultKey, all based on master secret.
	 */
	bool DeriveAllSecretKeys(SignatureKeys & keys, cc7::ByteArray & vaultKey, const cc7::ByteRange & masterSecret);
	
	/**
	 Derives unlock key from password. The PBKDF2 derivation function is used.
	 */
	cc7::ByteArray DeriveSecretKeyFromPassword(const cc7::ByteRange & password, const cc7::ByteRange & salt, cc7::U32 iterations);
	
	/**
	 Derives a 16 bytes long key from given master key and index. Both masterKey and index parameters must point to
	 16 bytes long arrays of bytes. The function is equal to KDF_INTERNAL described in PA2 documentation.
	 */
	cc7::ByteArray DeriveSecretKeyFromIndex(const cc7::ByteRange & masterKey, const cc7::ByteRange & index);
	
	//
	// MARK: - Signatures -
	//
	
	/**
	 Encrypts |plain| signature keys with using information from |request| and stores encrypted keys into |secret| structure.
	 */
	bool LockSignatureKeys(SignatureKeys & secret, const SignatureKeys & plain, const SignatureUnlockKeysReq & request);
	
	/**
	 Decrypts |secret| signature keys with using unlock information from |request| and stores plain keys into |plain| structure.
	 */
	bool UnlockSignatureKeys(SignatureKeys & plain, const SignatureKeys & secret, const SignatureUnlockKeysReq & request);
	
	/**
	 Adds or removes additional EEK protection to SignatureKeys structure. If |protect| is true, then the protection
	 is added and vice versa.
	 */
	bool ProtectSignatureKeysWithEEK(SignatureKeys & secret, const cc7::ByteRange & eek, bool protect);
	
	/**
	 Calculates multi-factor signature from given |data|, for using |counter| and |keys|.
	 */
	std::string CalculateSignature(const SignatureKeys & sk,
								   SignatureFactor factor,
								   cc7::U64 ctr,
								   const cc7::ByteRange & data);
	
	/**
	 Prepares exact data for signature calculation:
	 REQ = ${method}&${B64(uri)}&${nonceB64}&${B64(body)}&${secret}
	 */
	cc7::ByteArray NormalizeDataForSignature(const std::string & method,
											 const std::string & uri,
											 const std::string & nonce_b64,
											 const cc7::ByteRange & body,
											 const std::string & app_secret);
	
	/**
	 Returns string representing given signature factor.
	 */
	std::string ConvertSignatureFactorToString(SignatureFactor factor);

	/**
	 Calculates application signature from given data. Nonce, encrypted key, application key and
	 application secret should be in Base64 format. The method doesn't validate if strings are
	 in correct format.
	 */
	std::string CalculateApplicationSignature(const std::string & activationIdShort,
											  const std::string & activationNonce,
											  const std::string & cDevicePublicKey,
											  const std::string & applicationKey,
											  const std::string & applicationSecret);
	
	/**
	 Calculates decimalized signature from given data. The size of provided data object
	 must be greater or equal 4.
	 */
	std::string CalculateDecimalizedSignature(const cc7::ByteRange & signature);
	
	
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
