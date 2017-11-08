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

#include <PowerAuth/ECIES.h>
#include "crypto/CryptoUtils.h"
#include "protocol/Constants.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{
	// ----------------------------------------------------------------------------------------------
	// MARK: - Envelope key -
	//
		
	bool ECIESEnvelopeKey::isValid() const
	{
		return key.size() == EnvelopeKeySize;
	}
	
	const cc7::ByteRange ECIESEnvelopeKey::encKey() const {
		if (isValid()) {
			return key.byteRange().subRange(0, EnvelopeKeySize/2);
		}
		return cc7::ByteRange();
	}
	
	const cc7::ByteRange ECIESEnvelopeKey::macKey() const {
		if (isValid()) {
			return key.byteRange().subRange(EnvelopeKeySize/2, EnvelopeKeySize/2);
		}
		return cc7::ByteRange();
	}
	
	ECIESEnvelopeKey ECIESEnvelopeKey::fromPublicKey(const cc7::ByteRange & public_key, cc7::ByteArray & out_ephemeral_key)
	{
		crypto::BNContext ctx;
		EC_KEY *pubk = nullptr, *ephemeral = nullptr;
		ECIESEnvelopeKey ek;
		do {
			pubk = crypto::ECC_ImportPublicKey(nullptr, public_key, ctx);
			if (!pubk) {
				break;
			}
			ephemeral = crypto::ECC_GenerateKeyPair();
			if (!ephemeral) {
				break;
			}
			auto sharedSecret = crypto::ECDH_SharedSecret(pubk, ephemeral);
			if (sharedSecret.empty()) {
				break;
			}
			out_ephemeral_key = crypto::ECC_ExportPublicKey(ephemeral, ctx);
			if (out_ephemeral_key.empty()) {
				break;
			}
			ek.key = crypto::ECDH_KDF_X9_63_SHA256(sharedSecret, out_ephemeral_key, EnvelopeKeySize);
			
		} while (false);
		
		// Releace OpenSSL resources
		EC_KEY_free(pubk);
		EC_KEY_free(ephemeral);
		
		return ek;
	}
	
	ECIESEnvelopeKey ECIESEnvelopeKey::fromPrivateKey(const cc7::ByteArray & private_key, const cc7::ByteRange & ephemeral_key)
	{
		crypto::BNContext ctx;
		EC_KEY *privk = nullptr, *ephemeral = nullptr;
		ECIESEnvelopeKey ek;
		
		do {
			privk = crypto::ECC_ImportPrivateKey(nullptr, private_key);
			if (!privk) {
				break;
			}
			ephemeral = crypto::ECC_ImportPublicKey(nullptr, ephemeral_key);
			if (!ephemeral) {
				break;
			}
			auto sharedSecret = crypto::ECDH_SharedSecret(ephemeral, privk);
			if (sharedSecret.empty()) {
				break;
			}
			ek.key = crypto::ECDH_KDF_X9_63_SHA256(sharedSecret, ephemeral_key, EnvelopeKeySize);
			
		} while (false);
		
		// Releace OpenSSL resources
		EC_KEY_free(privk);
		EC_KEY_free(ephemeral);
		
		return ek;
	}

	// ----------------------------------------------------------------------------------------------
	// MARK: - Private encryption / decryption -
	//
	
	static ErrorCode _Encrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const cc7::ByteRange & data, ECIESCryptogram & out_cryptogram)
	{
		out_cryptogram.body = crypto::AES_CBC_Encrypt_Padding(ek.encKey(), protocol::ZERO_IV, data);
		if (out_cryptogram.body.empty()) {
			return EC_Encryption;
		}
		// Keep size of encrypted data
		const size_t encryptedDataSize = out_cryptogram.body.size();
		// mac = MAC(body || S2)
		out_cryptogram.body.append(info2);
		out_cryptogram.mac = crypto::HMAC_SHA256(out_cryptogram.body, ek.macKey(), 0);
		if (out_cryptogram.mac.empty()) {
			return EC_Encryption;
		}
		// set encrypted data size back to original value
		out_cryptogram.body.resize(encryptedDataSize);
		return EC_Ok;
	}
	
	static ErrorCode _Decrypt(const ECIESEnvelopeKey & ek, const cc7::ByteRange & info2, const ECIESCryptogram & cryptogram, cc7::ByteArray & out_data)
	{
		// Prepare data for HMAC calculation
		auto data_for_mac = cryptogram.body;
		data_for_mac.append(info2);
		auto mac = crypto::HMAC_SHA256(data_for_mac, ek.macKey(), 0);
		// Verify calculated mac
		if (mac.empty() || mac != cryptogram.mac) {
			return EC_Encryption;
		}
		// Decrypt data
		out_data = crypto::AES_CBC_Decrypt_Padding(ek.encKey(), protocol::ZERO_IV, cryptogram.body);
		return out_data.empty() ? EC_Encryption : EC_Ok;
	}
	
	// ----------------------------------------------------------------------------------------------
	// MARK: - Encryptor class -
	//
	
	ECIESEncryptor::ECIESEncryptor(const cc7::ByteRange & public_key) :
		_public_key(public_key)
	{
	}
	
	ECIESEncryptor::ECIESEncryptor(const ECIESEnvelopeKey & envelope_key) :
		_envelope_key(envelope_key)
	{
	}
	
	const ECIESEnvelopeKey & ECIESEncryptor::envelopeKey() const
	{
		return _envelope_key;
	}
	
	bool ECIESEncryptor::canEncryptRequest() const
	{
		return !_public_key.empty();
	}
	
	bool ECIESEncryptor::canDecryptResponse() const
	{
		return _envelope_key.isValid();
	}
	
	
	// MARK: - Encryption & Decryption
	
	ErrorCode ECIESEncryptor::encryptRequest(const cc7::ByteRange & data, const cc7::ByteRange & shared_info2, ECIESCryptogram & out_cryptogram)
	{
		if (canEncryptRequest()) {
			_envelope_key = ECIESEnvelopeKey::fromPublicKey(_public_key, out_cryptogram.key);
			if (_envelope_key.isValid()) {
				return _Encrypt(_envelope_key, shared_info2, data, out_cryptogram);
			}
			return EC_Encryption;
		}
		return EC_WrongState;
	}
	
	ErrorCode ECIESEncryptor::decryptResponse(const ECIESCryptogram & cryptogram, const cc7::ByteRange & shared_info2, cc7::ByteArray & out_data)
	{
		if (canDecryptResponse()) {
			return _Decrypt(_envelope_key, shared_info2, cryptogram, out_data);
		}
		return EC_WrongState;
	}
	
	
	// ----------------------------------------------------------------------------------------------
	// MARK: - Decryptor class -
	//
	
	ECIESDecryptor::ECIESDecryptor(const cc7::ByteArray & private_key) :
		_private_key(private_key)
	{
	}
	
	ECIESDecryptor::ECIESDecryptor(const ECIESEnvelopeKey & envelope_key) :
		_envelope_key(envelope_key)
	{
	}
	
	const ECIESEnvelopeKey & ECIESDecryptor::envelopeKey() const
	{
		return _envelope_key;
	}
	
	bool ECIESDecryptor::canEncryptResponse() const
	{
		return _envelope_key.isValid();
	}
	
	bool ECIESDecryptor::canDecryptRequest() const
	{
		return !_private_key.empty();
	}
	
	
	// MARK: - Encryption & Decryption
	
	ErrorCode ECIESDecryptor::decryptRequest(const ECIESCryptogram & cryptogram, const cc7::ByteRange & shared_info2, cc7::ByteArray & out_data)
	{
		if (canDecryptRequest()) {
			_envelope_key = ECIESEnvelopeKey::fromPrivateKey(_private_key, cryptogram.key);
			if (_envelope_key.isValid()) {
				return _Decrypt(_envelope_key, shared_info2, cryptogram, out_data);
			}
			return EC_Encryption;
		}
		return EC_WrongState;
	}
	
	ErrorCode ECIESDecryptor::encryptResponse(const cc7::ByteRange & data, const cc7::ByteRange & shared_info2, ECIESCryptogram & out_cryptogram)
	{
		if (canEncryptResponse()) {
			return _Encrypt(_envelope_key, shared_info2, data, out_cryptogram);
		}
		return EC_WrongState;
	}
	
} // io::getlime::powerAuth
} // io::getlime
} // io
