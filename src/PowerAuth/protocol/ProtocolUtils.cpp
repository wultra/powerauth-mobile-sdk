/*
 * Copyright 2016-2017 Wultra s.r.o.
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

#include "ProtocolUtils.h"
#include "Constants.h"
#include "../crypto/CryptoUtils.h"
#include <cc7/Base64.h>
#include <cc7/Endian.h>

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
	
	bool ValidateActivationCodeSignature(const std::string & code, const std::string & sig, EC_KEY * mk)
	{
		CC7_ASSERT(mk, "mk is required parametr");
		if (code.empty() && sig.empty()) {
			// For custom activations, there's no activation code & signature.
			return true;
		}
		if (!code.empty() && sig.empty()) {
			// Code is present, but no signature. That's also valid state.
			return true;
		}
		cc7::ByteArray signature;
		bool result = signature.readFromBase64String(sig);
		if (!result || signature.empty()) {
			return false;
		}
		return crypto::ECDSA_ValidateSignature(cc7::MakeRange(code), signature, mk);
	}
	
	
	cc7::ByteArray ReduceSharedSecret(const cc7::ByteRange & secret)
	{
		size_t s = secret.size();
		if (s != SHARED_SECRET_KEY_SIZE) {
			CC7_LOG("Shared secret has unexpected size.");
			return cc7::ByteArray();
		}
		s = s / 2;
		cc7::ByteArray reduced(s, 0);
		for (size_t i = 0; i < secret.size() / 2; i++) {
			reduced[i] = secret[i] ^ secret[i + SHARED_SECRET_KEY_SIZE/2];
		}
		return reduced;
	}

	/**
	 Returns ByteArray( {0,0,0,0,0,0,0,0} + BigEndian(n) )
	 */
	static inline cc7::ByteArray _U64ToData(cc7::U64 n)
	{
		cc7::ByteArray data(8, 0);
		n = cc7::ToBigEndian(n);
		data.append(cc7::MakeRange(n));
		CC7_ASSERT(data.size() == 16, "Wrong key size after index append");
		return data;
	}
	
	cc7::ByteArray DeriveSecretKey(const cc7::ByteRange & secret, cc7::U64 index)
	{
		cc7::ByteArray key = _U64ToData(index);
		return crypto::AES_CBC_Encrypt(secret, ZERO_IV, key);
	}
	
	
	bool DeriveAllSecretKeys(SignatureKeys & keys, cc7::ByteArray & vaultKey, const cc7::ByteRange & masterSecret)
	{
		keys.possessionKey  = DeriveSecretKey(masterSecret, 1);
		keys.knowledgeKey   = DeriveSecretKey(masterSecret, 2);
		keys.biometryKey    = DeriveSecretKey(masterSecret, 3);
		keys.transportKey   = DeriveSecretKey(masterSecret, 1000);
		vaultKey            = DeriveSecretKey(masterSecret, 2000);
		return  keys.possessionKey.size() == SIGNATURE_KEY_SIZE &&
				keys.knowledgeKey.size()  == SIGNATURE_KEY_SIZE &&
				keys.biometryKey.size()   == SIGNATURE_KEY_SIZE &&
				keys.transportKey.size()  == SIGNATURE_KEY_SIZE &&
				vaultKey.size()           == SIGNATURE_KEY_SIZE;
	}

	
	cc7::ByteArray DeriveSecretKeyFromPassword(const cc7::ByteRange & password, const cc7::ByteRange & salt, cc7::U32 iterations)
	{
		return crypto::PBKDF2_HMAC_SHA1(password, salt, iterations, SIGNATURE_KEY_SIZE);
	}
	
	
	cc7::ByteArray DeriveSecretKeyFromIndex(const cc7::ByteRange & masterKey, const cc7::ByteRange & index)
	{
		if (masterKey.size() == SIGNATURE_KEY_SIZE && index.size() == SIGNATURE_KEY_SIZE) {
			// Calculate HMAC SHA256 without cropping the result
			cc7::ByteArray result = crypto::HMAC_SHA256(masterKey, index);
			if (result.size() == 32) {
				// Everything looks fine, just xor the final array.
				for (size_t i = 0; i < 16; i++) {
					result[i] = result[i] ^ result[i + 16];
				}
				result.resize(SIGNATURE_KEY_SIZE);
				return result;
			}
		} else {
			CC7_ASSERT(false, "Provided masterKey or index has wrong size.");
		}
		return cc7::ByteArray();
	}
	
	//
	// MARK: - Signatures -
	//
	
	static cc7::ByteArray _EncryptSignatureKey(const cc7::ByteRange & protection_key, const cc7::ByteArray * ext_key, const cc7::ByteRange & signature_key)
	{
		if (ext_key == nullptr) {
			return crypto::AES_CBC_Encrypt(protection_key, ZERO_IV, signature_key);
		} else {
			cc7::ByteArray tmp = crypto::AES_CBC_Encrypt(protection_key, ZERO_IV, signature_key);
			return crypto::AES_CBC_Encrypt(*ext_key, ZERO_IV, tmp);
		}
	}
	
	static cc7::ByteArray _DecryptSignatureKey(const cc7::ByteRange & protection_key, const cc7::ByteArray * ext_key, const cc7::ByteRange & c_signature_key)
	{
		if (ext_key == nullptr) {
			return crypto::AES_CBC_Decrypt(protection_key, ZERO_IV, c_signature_key);
		} else {
			cc7::ByteArray tmp = crypto::AES_CBC_Decrypt(*ext_key, ZERO_IV, c_signature_key);
			return crypto::AES_CBC_Decrypt(protection_key, ZERO_IV, tmp);
		}
	}
	
	bool LockSignatureKeys(SignatureKeys & secret, const SignatureKeys & plain, const SignatureUnlockKeysReq & request)
	{
		if (request.keys == nullptr) {
			CC7_ASSERT(false, "request.keys pointer is required parameter");
			return false;
		}
		const SignatureUnlockKeys & keys = *request.keys;
		SignatureFactor factor = request.factor;
		if (!CC7_CHECK(ValidateUnlockKeys(keys, request.ext_key, factor), "You have provided invalid unlock keys.")) {
			return false;
		}
		bool has_biometry = !keys.biometryUnlockKey.empty();
		bool first_lock   = factor == SF_FirstLock;
		bool validate_eek = (factor & SF_Biometry) == SF_Biometry ||
							(factor & SF_Knowledge) == SF_Knowledge;
		if (first_lock) {
			// Prepare "full" factor mask + transport key.
			factor = FullFactorMask(has_biometry) | SF_Transport;
			// This is first, lock, just set the flag about exgternal key in the structure to initial value.
			secret.usesExternalKey = request.ext_key != nullptr;
		} else {
			// This is not a first lock. We should check if we're using external key correctly!
			if (validate_eek) {
				if (plain.usesExternalKey != (request.ext_key != nullptr)) {
					if (secret.usesExternalKey) {
						// Signature keys were protected with additional encryption key and therefore you have to provide that
						// key now. Check how you're using Session object and if your higher level infrastrucutre works as
						// expected.
						CC7_LOG("LockSignatureKeys: Additional encryption key mish-mash. The additional key is missing.");
					} else {
						// Signature keys were NOT protected with additional encryption key, but you're trying to unlock them
						// with the key. We can recover from this situation (simply ignore that key), but this kind of misuse
						// usually means, that you're using a Session object in wrong way. Check your higher level code, if
						// it works as expected.
						CC7_LOG("LockSignatureKeys: Additional encryption key mish-mash. The additional key is present.");
					}
					return false;
				}
			}
			// ...and keep that flag in destination structure.
			secret.usesExternalKey = plain.usesExternalKey;
		}
		
		if (!CC7_CHECK(ValidateSignatureKeys(plain, factor), "You have provided invalid keys for lock.")) {
			return false;
		}
		// Lock possession & transport. We're not using EEK for this two keys.
		if (factor & SF_Possession) {
			secret.possessionKey = _EncryptSignatureKey(keys.possessionUnlockKey, nullptr, plain.possessionKey);
		}
		if (factor & SF_Transport) {
			secret.transportKey  = _EncryptSignatureKey(keys.possessionUnlockKey, nullptr, plain.transportKey);
		}
		if (factor & SF_Knowledge) {
			// Derive password, and protect knowledge key
			if (request.pbkdf2_salt == nullptr || request.pbkdf2_iter == 0) {
				CC7_ASSERT(false, "Missing salt or zero number of iterations for PBKDF2");
				return false;
			}
			if (request.pbkdf2_salt->size() < protocol::PBKDF2_SALT_SIZE) {
				CC7_ASSERT(false, "salt is too small");
				return false;
			}
			cc7::ByteArray derived_password = DeriveSecretKeyFromPassword(keys.userPassword, *request.pbkdf2_salt, request.pbkdf2_iter);
			secret.knowledgeKey  = _EncryptSignatureKey(derived_password, request.ext_key, plain.knowledgeKey);
		}
		
		// Protect biometry key if key is available
		if (factor & SF_Biometry) {
			secret.biometryKey = _EncryptSignatureKey(keys.biometryUnlockKey, request.ext_key, plain.biometryKey);
		} else if (first_lock) {
			secret.biometryKey.clear();
		}
		// Finally, validate if AES encryptions produced valid results.
		return ValidateSignatureKeys(secret, factor);
	}
	
	
	bool UnlockSignatureKeys(SignatureKeys & plain, const SignatureKeys & secret, const SignatureUnlockKeysReq & request)
	{
		if (request.keys == nullptr) {
			CC7_ASSERT(false, "request.keys pointer is required parameter");
			return false;
		}
		const SignatureUnlockKeys & keys = *request.keys;
		if (!ValidateUnlockKeys(keys, request.ext_key, request.factor)) {
			CC7_LOG("UnlockSignatureKeys: You have provided invalid unlock keys!");
			return false;
		}
		if (!ValidateSignatureKeys(secret, request.factor)) {
			// You're probably asking for biometry factor calculation and module doesn't have biometry key stored in PD.
			CC7_LOG("UnlockSignatureKeys: You're requesting unlock for factor which has no defined key.");
			return false;
		}
		bool validate_eek = (request.factor & SF_Biometry) == SF_Biometry ||
							(request.factor & SF_Knowledge) == SF_Knowledge;
		// Usage of EEK is important for Possession & Biometry, so we have to check if key should be present or not.
		if (validate_eek) {
			if (secret.usesExternalKey != (request.ext_key != nullptr)) {
				if (secret.usesExternalKey) {
					// Signature keys were protected with additional encryption key and therefore you have to provide that
					// key now. Check how you're using Session object and if your higher level infrastrucutre works as
					// expected.
					CC7_LOG("UnlockSignatureKeys: Additional encryption key mish-mash. The additional key is missing.");
				} else {
					// Signature keys were NOT protected with additional encryption key, but you're trying to unlock them
					// with the key. We can recover from this situation (simply ignore that key), but this kind of misuse
					// usually means, that you're using a Session object in wrong way. Check your higher level code, if
					// it works as expected.
					CC7_LOG("UnlockSignatureKeys: Additional encryption key mish-mash. The additional key is present.");
				}
				return false;
			}
		}
		// Copy an external keys flag to the destination structure. The information is useful for
		// several scenarios, when Session locks the keys again.
		plain.usesExternalKey = secret.usesExternalKey;
		
		// Possession & Transport are protected with the same key. Note that we're not using EEK for additional protection.
		if (request.factor & SF_Possession) {
			plain.possessionKey = _DecryptSignatureKey(keys.possessionUnlockKey, nullptr, secret.possessionKey);
			if (plain.possessionKey.empty()) {
				return false;
			}
		} else {
			plain.possessionKey.clear();
		}
		if (request.factor & SF_Transport) {
			plain.transportKey  = _DecryptSignatureKey(keys.possessionUnlockKey, nullptr, secret.transportKey);
			if (plain.transportKey.empty()) {
				return false;
			}
		} else {
			plain.transportKey.clear();
		}
		// Derive password, and unlock knowledge key
		if (request.factor & SF_Knowledge) {
			if (request.pbkdf2_salt == nullptr || request.pbkdf2_iter == 0) {
				CC7_ASSERT(false, "Missing salt or zero number of iterations for PBKDF2");
				return false;
			}
			if (request.pbkdf2_salt->size() < protocol::PBKDF2_SALT_SIZE) {
				CC7_ASSERT(false, "salt is too small");
				return false;
			}
			cc7::ByteArray derived_password = DeriveSecretKeyFromPassword(keys.userPassword, *request.pbkdf2_salt, request.pbkdf2_iter);
			plain.knowledgeKey  = _DecryptSignatureKey(derived_password, request.ext_key, secret.knowledgeKey);
			if (plain.knowledgeKey.empty()) {
				return false;
			}
		} else {
			plain.knowledgeKey.clear();
		}
		// Unlock biometry key if key is available
		if (request.factor & SF_Biometry) {
			plain.biometryKey = _DecryptSignatureKey(keys.biometryUnlockKey, request.ext_key, secret.biometryKey);
			if (plain.biometryKey.empty()) {
				return false;
			}
		} else {
			plain.biometryKey.clear();
		}
		return true;
	}
	
	
	bool ProtectSignatureKeysWithEEK(SignatureKeys & secret, const cc7::ByteRange & eek, bool protect)
	{
		if (secret.usesExternalKey == protect) {
			// Internal error. The PD has probably different value than SK structure.
			CC7_ASSERT(false, "PD flag for EEK usage is different than in SK structure");
			return false;
		}
		cc7::ByteArray c_knowledge_key;
		cc7::ByteArray c_biometry_key;
		if (protect) {
			c_knowledge_key = crypto::AES_CBC_Encrypt(eek, ZERO_IV, secret.knowledgeKey);
		} else {
			c_knowledge_key = crypto::AES_CBC_Decrypt(eek, ZERO_IV, secret.knowledgeKey);
		}
		if (c_knowledge_key.size() != SIGNATURE_KEY_SIZE) {
			return false;
		}
		if (!secret.biometryKey.empty()) {
			if (protect) {
				c_biometry_key = crypto::AES_CBC_Encrypt(eek, ZERO_IV, secret.biometryKey);
			} else {
				c_biometry_key = crypto::AES_CBC_Decrypt(eek, ZERO_IV, secret.biometryKey);
			}
			if (c_biometry_key.size() != SIGNATURE_KEY_SIZE) {
				return false;
			}
			secret.biometryKey = c_biometry_key;
		}
		secret.knowledgeKey = c_knowledge_key;
		secret.usesExternalKey = protect;
		return true;
	}

	
	cc7::ByteArray SignatureCounterToData(cc7::U64 counter)
	{
		return _U64ToData(counter);
	}
	
	/**
	 Move hash based counter forward.
	 */
	inline cc7::ByteArray _NextCounterValue(const cc7::ByteRange & prev)
	{
		return ReduceSharedSecret(crypto::SHA256(prev));
	}
	
	void CalculateNextCounterValue(PersistentData & pd)
	{
		if (pd.isV3()) {
			// Move hash-based counter forward. Vault unlock is ignored in V3
			pd.signatureCounterData = _NextCounterValue(pd.signatureCounterData);
			//
		} else {
			// Move old counter forward
			pd.signatureCounter += 1;
		}
	}
	
	
	std::string CalculateSignature(const SignatureKeys & sk, SignatureFactor factor, const cc7::ByteRange & ctr_data, const cc7::ByteRange & data, bool online)
	{
		// Prepare keys into one linear vector
		std::vector<const cc7::ByteArray*> keys;
		if ((factor & SF_Possession) != 0) {
			keys.push_back(&sk.possessionKey);
		}
		if ((factor & SF_Knowledge) != 0) {
			keys.push_back(&sk.knowledgeKey);
		}
		if ((factor & SF_Biometry) != 0) {
			keys.push_back(&sk.biometryKey);
		}
		
		// Pepare byte array for online signature or final string for offline signature.
		cc7::ByteArray signature_bytes;
		std::string signature_string;
		if (online) {
			signature_bytes.reserve(keys.size() * 16);
		} else {
			signature_string.reserve(keys.size() * 8 + keys.size() - 1);
		}
		// Now calculate signature for all involved factors.
		for (size_t i = 0; i < keys.size(); i++) {
			// Outer loop, for over key in the vector.
			const cc7::ByteArray & signature_key = *keys[i];
			auto derived_key = crypto::HMAC_SHA256(ctr_data, signature_key);
			if (derived_key.size() == 0) {
				CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
				return std::string();
			}
			for (size_t j = 0; j < i; j++) {
				const cc7::ByteArray & signature_key_inner = *keys[j + 1];
				auto derived_key_inner = crypto::HMAC_SHA256(ctr_data, signature_key_inner);
				derived_key = crypto::HMAC_SHA256(derived_key, derived_key_inner);
				if (derived_key.size() == 0) {
					CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
					return std::string();
				}
			}
			// Calculate HMAC for given data
			auto signature_factor_bytes = crypto::HMAC_SHA256(data, derived_key);
			if (signature_factor_bytes.size() == 0) {
				CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
				return std::string();
			}
			if (online) {
				// For new online signature, just append last 16 bytes of HMAC result.
				// We'll calculate final signature string later.
				signature_bytes.append(signature_factor_bytes.byteRange().subRangeFrom(16));
			} else {
				// Offline signature is using old, decimalized format.
				auto signature_factor = CalculateDecimalizedSignature(signature_factor_bytes);
				if (!signature_string.empty()) {
					signature_string.append(DASH);
				}
				signature_string.append(signature_factor);
			}
		}
		if (online) {
			// Now calculate a final Base64 string for online signature
			cc7::Base64_Encode(signature_bytes, 0, signature_string);
		}
		// Otherwise, for offline signature, just return the result which already
		// contains the final string.
		return signature_string;
	}
	
	
	cc7::ByteArray NormalizeDataForSignature(const std::string & method,
											 const std::string & uri,
											 const std::string & nonce_b64,
											 const cc7::ByteRange & body,
											 const std::string & app_secret)
	{
		std::string body_b64 = cc7::ToBase64String(body);
		std::string uri_b64  = cc7::ToBase64String(cc7::MakeRange(uri));
		
		cc7::ByteArray data_for_signing;
		data_for_signing.reserve(method.size() + uri_b64.size() + nonce_b64.size() + body_b64.size() + app_secret.size() + 5);
		
		// Construct data for signing
		data_for_signing.assign(method.begin(), method.end());
		data_for_signing.push_back('&');
		data_for_signing.append(uri_b64.begin(), uri_b64.end());
		data_for_signing.push_back('&');
		data_for_signing.append(nonce_b64.begin(), nonce_b64.end());
		data_for_signing.push_back('&');
		data_for_signing.append(body_b64.begin(), body_b64.end());
		data_for_signing.push_back('&');
		data_for_signing.append(app_secret.begin(), app_secret.end());
		
		return data_for_signing;
	}
	
	
	std::string ConvertSignatureFactorToString(SignatureFactor factor)
	{
		switch (factor & 0x0fff) {
			case SF_Possession:
				return std::string("possession");
			case SF_Knowledge:
				return std::string("knowledge");
			case SF_Biometry:
				return std::string("biometry");
			case SF_Possession_Biometry:
				return std::string("possession_biometry");
			case SF_Possession_Knowledge:
				return std::string("possession_knowledge");
			case SF_Possession_Knowledge_Biometry:
				return std::string("possession_knowledge_biometry");
			default:
				CC7_ASSERT(false, "Unknown factor %d", factor);
				return std::string();
		}
	}


	/**
	 Convers |val| to normalized string. Zero characters are used for the indentation padding
	 when the string representation is shorter than 8 characters (e.g. 123 is converted to "00000123").
	 */
	static std::string _ValToNormString(cc7::U32 val)
	{
		std::string result = std::to_string(val);
		static const std::string zero("00000000");
		if (result.length() < protocol::ACTIVATION_FINGERPRINT_SIZE) {
			result.insert(0, zero.substr(0, protocol::ACTIVATION_FINGERPRINT_SIZE - result.length()));
		}
		CC7_ASSERT(result.length() == protocol::ACTIVATION_FINGERPRINT_SIZE, "Wrong normalized size");
		return result;
	}
	
	
	
	std::string CalculateDecimalizedSignature(const cc7::ByteRange & signature)
	{
		if (signature.size() < 4) {
			// This must be handled on higher level.
			CC7_ASSERT(false, "The signature is too short");
			return std::string();
		}
		size_t offset = signature.size() - 4;
		// "dynamic binary code" from HOTP draft
		cc7::U32 dbc = (signature[offset + 0] & 0x7F) << 24 |
						signature[offset + 1] << 16 |
						signature[offset + 2] << 8  |
						signature[offset + 3];
		return _ValToNormString(dbc % 100000000);
	}

	std::string CalculateActivationFingerprint(const cc7::ByteRange & device_pub_key, const cc7::ByteRange & server_pub_key, const std::string activation_id, Version v)
	{
		std::string result;
		
		crypto::BNContext ctx;
		
		EC_KEY * device_public_key = nullptr;
		EC_KEY * server_public_key = nullptr;
		do {
			crypto::BNContext ctx;
			
			// Import device's public key
			device_public_key = crypto::ECC_ImportPublicKey(nullptr, device_pub_key, ctx);
			auto device_coord_x = crypto::ECC_ExportPublicKeyToNormalizedForm(device_public_key, ctx);
			if (device_coord_x.empty()) {
				break;
			}
			cc7::ByteArray data;
			if (v == Version_V2) {
				// Stiil at V2 activation
				data.reserve(device_coord_x.size());
				// data = device_coord_x
				data.assign(device_coord_x);
			} else {
				// V3 activation
				// Import server's public key
				server_public_key = crypto::ECC_ImportPublicKey(nullptr, server_pub_key, ctx);
				auto server_coord_x = crypto::ECC_ExportPublicKeyToNormalizedForm(server_public_key, ctx);
				if (server_coord_x.empty()) {
					break;
				}
				// data = device_coord_x + activation_id + server_coord_x
				data.reserve(device_coord_x.size() + activation_id.size() + server_coord_x.size());
				data.assign(device_coord_x);
				data.append(cc7::MakeRange(activation_id));
				data.append(server_coord_x);
			}
			// Now calculate decimalized signature
			result = protocol::CalculateDecimalizedSignature(crypto::SHA256(data));
			if (result.size() != protocol::ACTIVATION_FINGERPRINT_SIZE) {
				result.clear();
			}
			
		} while (false);
		
		// Release OpenSSL objects
		EC_KEY_free(device_public_key);
		EC_KEY_free(server_public_key);
		
		return result;
	}
	
	//
	// MARK: - Encrypted status -
	//
	
	cc7::ByteArray DeriveIVForStatusBlobDecryption(const cc7::ByteRange & challenge,
												   const cc7::ByteRange & nonce,
												   const cc7::ByteRange & transport_key)
	{
		if (challenge.size() == STATUS_BLOB_CHALLENGE_SIZE && nonce.size() == STATUS_BLOB_NONCE_SIZE) {
			// Derive base IV key from transport key
			auto key_transport_iv = DeriveSecretKey(transport_key, 3000);
			// KDF_INTERNAL
			auto key_challenge = ReduceSharedSecret(crypto::HMAC_SHA256(challenge, key_transport_iv));
			// challenge_key ^= nonce
			if (key_challenge.size() == nonce.size()) {
				for (size_t i = 0; i < key_challenge.size(); i++) {
					key_challenge[i] ^= nonce[i];
				}
				return key_challenge;
			}
		}
		// In case of failure, return empty array.
		return cc7::ByteArray();
	}
	
	int CalculateHashCounterDistance(const cc7::ByteRange & counter1, const cc7::ByteRange & counter2, int max_iterations)
	{
		cc7::ByteArray cnt = counter1;
		int iteration = 0;
		while (max_iterations > 0) {
			if (cnt == counter2) {
				return iteration;
			}
			cnt = _NextCounterValue(cnt);
			++iteration;
			--max_iterations;
		}
		return -1;
	}
	
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
