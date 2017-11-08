/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#include <PowerAuth/PublicTypes.h>

/*
 The ECIES.h header file contains a set of interfaces prepared for ECIES data
 encryption & decryption. The PowerAuth implementation is using following
 configuration:
 
 Curve:	NID_X9_62_prime256v1 (just like rest of PA)
 KDF:	ANSI X9.63:2001 with SHA256
 MAC:   HMAC_SHA256
 ENC:	AES_CBC with PKCS7 padding, 128 bit key
 
 -----------------------------------------------------------
 1.a Request Encryption (on client's side)
 -----------------------------------------------------------
 Input:
 	PUBLIC_KEY - server's public key
 	TEXT - data to be encrypted
	SH2 - shared info 2, (or param#2 in some papers)
 Output:
	C - cryptogram structure with KEY, BODY & MAC
 
 Process:
 	// Generate a new ephemeral key and calculate shared secret
 	let EPHEMERAL_KEY = ECC_GenerateKeypair()
 	let SHARED_SECRET = ECDH_SharedSecret(EPHEMERAL_KEY, PUBLIC_KEY)
 
 	// Export public key to cryptogram C
 	C.KEY  = ECC_ExportPublicKey(EPHEMERAL_KEY)
 
 	// Derive key matherial from SHARED_SECRET and exported public key.
 	// We're using public key's data as optional parameter to KDF function.
	let ENVELOPE_KEY  = KDF(key: SHARED_SECRET, info: C.KEY, length: 32)
 	let K_ENC = ENVELOPE_KEY[ 0...15]
 	let K_MAC = ENVELOPE_KEY[16...31]
 
 	// Encrypt data & calculate MAC
	C.BODY = AES_CBC_PKCS7_Encrypt(key: K_ENC, iv: ZERO[16], data: TEXT)
	C.MAC  = HMAC_SHA256(key: K_MAC, data: C.BODY || SH2)
 
 -----------------------------------------------------------
 1.b Response Decryption (on client's side)
 -----------------------------------------------------------
 Input:
 	ENVELOPE_KEY - a key calculated in 1.a
 	C - cryptogram structure with body & mac (produced in 2.b)
	SH2 - shared info 2, (or param#2 in some papers)
 Output:
	TEXT - decrypted data
 
 Process:
 	// Prepare keys...
 	let K_ENC = ENVELOPE_KEY[ 0...15]
 	let K_MAC = ENVELOPE_KEY[16...31]
 
 	// Verify MAC
 	let MAC = HMAC_SHA256(key: K_MAC, data: C.BODY || SH2)
 	if MAC != C.MAC then failure
 	// Decrypt data
	TEXT = AES_CBC_PKCS7_Decrypt(key: K_ENC, iv: ZERO[16], data: C.BODY)

 -----------------------------------------------------------
 2.a Request Decryption (on server's side)
 -----------------------------------------------------------
 Input:
 	PRIVATE_KEY - server's private key
 	C - cryptogram, produced in 1.a
 	HS2 - shared info 2
 Output:
 	TEXT - data
 
 Process:
 	// Calculate shared secret from ephemeral key and private key
 	let SHARED_SECRET = ECDH_SharedSecret(PRIVATE_KEY, C.KEY)
	let ENVELOPE_KEY  = KDF(key: SHARED_SECRET, info: C.KEY, length: 32)
 	let K_ENC = ENVELOPE_KEY[ 0...15]
 	let K_MAC = ENVELOPE_KEY[16...31]
 
 	// Verify MAC
 	let MAC = HMAC_SHA256(key: K_MAC, data: C.BODY || SH2)
 	if MAC != C.MAC then failure
 	// Decrypt data
 	TEXT = AES_CBC_PKCS7_Decrypt(key: K_ENC, iv: ZERO[16], data: C.BODY)
 
 -----------------------------------------------------------
 2.b Response Encryption (on server's side)
 -----------------------------------------------------------
 Input:
 	ENVELOPE_KEY - a key calculated in 2.a
 	TEXT - data to be encrypted
	SH2 - shared info 2, (or param#2 in some papers)
 Output:
 	TEXT - data

 Process:
 	// Prepare keys
  	let K_ENC = ENVELOPE_KEY[ 0...15]
 	let K_MAC = ENVELOPE_KEY[16...31]
 
 	// Encrypt data & calculate MAC
	C.BODY = AES_CBC_PKCS7_Encrypt(key: K_ENC, iv: ZERO[16], data: TEXT)
	C.MAC  = HMAC_SHA256(key: K_MAC, data: C.BODY || SH2)
 */

namespace io
{
namespace getlime
{
namespace powerAuth
{
	/// The ECIESCryptogram structure represents cryptogram transmitted
	/// over the network.
	struct ECIESCryptogram
	{
		/// An ephemeral EC public key. The value is optional for response data.
		cc7::ByteArray	key;
		
		/// A MAC computed for key & data
		cc7::ByteArray	mac;
		
		/// Encrypted data
		cc7::ByteArray	body;
	};
	
	/// The ECIESEnvelopeKey represents a temporary key for ECIES encryption and decryption
	/// process. The key is derived from shared secret, produced in ECDH key agreement.
	class ECIESEnvelopeKey {
	public:
		
		// Default constructors & copy-move operators
		
		ECIESEnvelopeKey() = default;
		ECIESEnvelopeKey(const ECIESEnvelopeKey &)  = default;
		ECIESEnvelopeKey(ECIESEnvelopeKey &&)  = default;
		ECIESEnvelopeKey & operator=(const ECIESEnvelopeKey & t) = default;
		ECIESEnvelopeKey & operator=(ECIESEnvelopeKey && t) = default;
		
		/// Returns true if key stored in this object can be used for encryption & decryption.
		bool isValid() const;
		
		/// Returns key for encryption or decryption.
		const cc7::ByteRange encKey() const;
		
		/// Returns key for HMAC calculation.
		const cc7::ByteRange macKey() const;
		
		/// Creates a new instance of ECIESEnvelopeKey from EC |publiKey|. The method also stores a newly created
		/// ephemeral public key to the |out_ephemeralKey| reference.
		static ECIESEnvelopeKey fromPublicKey(const cc7::ByteRange & public_key, cc7::ByteArray & out_ephemeral_key);
		
		/// Creates a new instance of ECIESEnvelopeKey from EC |privateKey| and |ephemeralKey| key-pair.
		static ECIESEnvelopeKey fromPrivateKey(const cc7::ByteArray & private_key, const cc7::ByteRange & ephemeral_key);
		
	private:

		/// Expected length of a whole envelope key.
		static const size_t EnvelopeKeySize = 32;
		
		/// Envelope key's data
		cc7::ByteArray key;
	};

	
	/// The ECIESEncryptor class implements a request encryption and response decryption for our custom ECIES scheme.
	class ECIESEncryptor
	{
	public:
		/// Constructs an ecnryptor with public key. This instance can be used for both encryption and decryption
		/// operations.
		ECIESEncryptor(const cc7::ByteRange & public_key);
		
		/// Constructs an encryptor with envelope key. This instance can be used only for decryption process.
		ECIESEncryptor(const ECIESEnvelopeKey & envelope_key);
		
		/// Returns a reference to internal envelope key.
		const ECIESEnvelopeKey & envelopeKey() const;

		/// Returns true if this instance can encrypt request data.
		/// This is met only when the encryptor is constructed with public key.
		bool canEncryptRequest() const;
		/// Returns true if this instance can decrypt response data.
		/// This is met only when the envelope key is valid.
		bool canDecryptResponse() const;
		
		/// Encrypts an input |data| into |out_cryptogram|. The |shared_info2| parameter is an optional parameter which affects
		/// how |out_cryptogram.mac| is calculated. You can provide an empty ByteRange, when you have no such information available.
		/// Note that each call for this method will regenerate an internal envelope key, so you should use the method only in pair
		/// with following call to decryptResponse()
		///
		/// Returns
		///		EC_Ok 			- when everything's OK and cryptogram's is valid
		///		EC_WrongState	- if instance can't encrypt data (e.g. public key is not present)
		///		EC_Encryption	- if some cryptographic operation did fail
		ErrorCode encryptRequest(const cc7::ByteRange & data, const cc7::ByteRange & shared_info2, ECIESCryptogram & out_cryptogram);
		
		/// Decrypts a |cryptogram| received from the server and stores the result into |out_data| reference. The |shared_info2| parameter
		/// is an optional parameter which affects how |cryptogram.mac| is validated. You can provide an empty ByteRange, when you have
		/// no such information available.
		///
		/// Returns
		///		EC_Ok 			- when everything's OK and |out_data| contains a valid data.
		///		EC_WrongState	- if instance can't decrypt data (e.g. envelope key is not valid)
		///		EC_Encryption	- if some cryptographic operation did fail
		ErrorCode decryptResponse(const ECIESCryptogram & cryptogram, const cc7::ByteRange & shared_info2, cc7::ByteArray & out_data);
		
	private:
		
		/// A data for public key.
		cc7::ByteArray	 _public_key;
		/// Last calculated envelope key.
		ECIESEnvelopeKey _envelope_key;
	};
	
	
	/// The ECIESDecryptor class implements a request decryption and response encryption for our custom ECIES scheme.
	/// In most cases, you don't need to use this object in the client software, because a similar implementation is running
	/// on the server. The PowerAuth library is using this object only for unit testing purposes.
	class ECIESDecryptor
	{
	public:
		/// Constructs a decryptor with private key. This instance can be used for both decryption & encryption
		/// operations.
		ECIESDecryptor(const cc7::ByteArray & private_key);
	
		/// Constructs a decryptor with envelope key. This instance can be used only for encryption process.
		ECIESDecryptor(const ECIESEnvelopeKey & envelope_key);
		
		/// Returns a reference to internal envelope key.
		const ECIESEnvelopeKey & envelopeKey() const;
		
		/// Returns true if this instance can decrypt request data.
		bool canDecryptRequest() const;
		/// Returns true if this instance can encrypt response data.
		bool canEncryptResponse() const;
		
		/// Decrypts a |cryptogram| received from the client and stores the result into |out_data| reference. The |shared_info2| parameter
		/// is an optional parameter which affects how |cryptogram.mac| is validated. You can provide an empty ByteRange, when you have
		/// no such information available.
		/// Note that each call for this method will regenerate an internal envelope key, so you should use the method only in pair
		/// with following call to encryptResponse().
		///
		/// Returns
		///		EC_Ok 			- when everything's OK and |out_data| contains a valid data.
		///		EC_WrongState	- if instance can't decrypt data (e.g. private key is not valid)
		///		EC_Encryption	- if some cryptographic operation did fail
		ErrorCode decryptRequest(const ECIESCryptogram & cryptogram, const cc7::ByteRange & shared_info2, cc7::ByteArray & out_data);
		
		/// Encrypts an input |data| into |out_cryptogram|. The |shared_info2| parameter is an optional parameter which affects
		/// how |out_cryptogram.mac| is calculated. You can provide an empty ByteRange, when you have no such information available.
		///
		/// Returns
		///		EC_Ok 			- when everything's OK and cryptogram's is valid
		///		EC_WrongState	- if instance can't encrypt data (e.g. public key is not present)
		///		EC_Encryption	- if some cryptographic operation did fail
		ErrorCode encryptResponse(const cc7::ByteRange & data, const cc7::ByteRange & shared_info2, ECIESCryptogram & out_cryptogram);
		
	private:
		/// A data for private key.
		cc7::ByteArray _private_key;
		/// Last calculated envelope key.
		ECIESEnvelopeKey _envelope_key;
	};
	
	
	
} // io::getlime::powerAuth
} // io::getlime
} // io

