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
	
	bool ValidateShortIdAndOtpSignature(const std::string & sid, const std::string & otp, const std::string & sig, EC_KEY * mk)
	{
		CC7_ASSERT(mk, "mk is required parametr");
		CC7_ASSERT(!sid.empty(), "sid is required parameter");
		CC7_ASSERT(!otp.empty(), "otp is required parameter");
		if (sig.empty()) {
			// Signature is optional, we can return true
			return true;
		}
		bool result;
		cc7::ByteArray signature;
		result = signature.readFromBase64String(sig);
		if (!result || signature.empty()) {
			return false;
		}
		// Prepare data for signature validation
		std::string signed_data = sid;
		signed_data.append(DASH);
		signed_data.append(otp);
		return crypto::ECDSA_ValidateSignature(cc7::MakeRange(signed_data), signature, mk);
	}
	
	
	bool ValidateActivationDataSignature(const std::string & activationId, const std::string & cServerPublicKeyB64, const cc7::ByteRange & sig, EC_KEY * mk)
	{
		std::string signed_data;
		signed_data.append(cc7::ToBase64String(cc7::MakeRange(activationId)));
		signed_data.append(AMP);
		signed_data.append(cServerPublicKeyB64);
		return crypto::ECDSA_ValidateSignature(cc7::MakeRange(signed_data), sig, mk);
	}

	
	cc7::ByteArray ExpandOTPKey(const std::string & activationIdShort, const std::string & otp)
	{
		return crypto::PBKDF2_HMAC_SHA_1(cc7::MakeRange(otp), cc7::MakeRange(activationIdShort), PBKDF2_OTP_EXPAND_ITERATIONS, SIGNATURE_KEY_SIZE);
	}

	
	cc7::ByteArray EncryptDevicePublicKey(ActivationData & ad, const std::string & activationIdShort, const std::string & otp)
	{
		if (ad.devicePublicKeyData.empty() || (ad.activationNonce.size() != ACTIVATION_NONCE_SIZE) || (ad.activationNonce == ZERO_IV) || ad.ephemeralDeviceKey == nullptr) {
			CC7_ASSERT(false, "The required parameter is missing.");
			return cc7::ByteArray();
		}
        // Calculate and import ephemeral shared secret
        cc7::ByteArray ephemeral_shared_secret = ReduceSharedSecret(crypto::ECDH_SharedSecret(ad.masterServerPublicKey, ad.ephemeralDeviceKey));
        if (ephemeral_shared_secret.empty()) {
            CC7_ASSERT(false, "Ephemeral shared key calculation failed.");
            return cc7::ByteArray();
        }
		ad.expandedOtp = ExpandOTPKey(activationIdShort, otp);
        cc7::ByteArray tmp_data = crypto::AES_CBC_Encrypt_Padding(ad.expandedOtp, ad.activationNonce, ad.devicePublicKeyData);
        cc7::ByteArray result = crypto::AES_CBC_Encrypt_Padding(ephemeral_shared_secret, ad.activationNonce, tmp_data);
        return result;
	}

	
	bool DecryptServerPublicKey(ActivationData & ad, const cc7::ByteRange & ephemeral, const cc7::ByteRange & encryptedPk, const cc7::ByteRange & nonce)
	{
		crypto::BNContext ctx;
		// Import ephemeral server key
		ad.ephemeralServerKey = crypto::ECC_ImportPublicKey(nullptr, ephemeral, ctx);
		if (!ad.ephemeralServerKey) {
			return false;
		}
		// Calculate ephemeral shared secret
		cc7::ByteArray ephemeral_shared_secret = ReduceSharedSecret(crypto::ECDH_SharedSecret(ad.ephemeralServerKey, ad.devicePrivateKey));
		if (ephemeral_shared_secret.empty()) {
			CC7_ASSERT(false, "Ephemeral shared key calculation failed.");
			return false;
		}
		// Decrypt server's public key with double AES decryption
		cc7::ByteArray tmp_data	= crypto::AES_CBC_Decrypt_Padding(ephemeral_shared_secret, nonce, encryptedPk);
		ad.serverPublicKeyData	= crypto::AES_CBC_Decrypt_Padding(ad.expandedOtp, nonce, tmp_data);
		ad.serverPublicKey		= crypto::ECC_ImportPublicKey(nullptr, ad.serverPublicKeyData, ctx);
		return ad.serverPublicKey != nullptr;
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
		return crypto::PBKDF2_HMAC_SHA_1(password, salt, iterations, SIGNATURE_KEY_SIZE);
	}
	
	
	cc7::ByteArray DeriveSecretKeyFromIndex(const cc7::ByteRange & masterKey, const cc7::ByteRange & index)
	{
		if (masterKey.size() == SIGNATURE_KEY_SIZE && index.size() == SIGNATURE_KEY_SIZE) {
			// Calculate HMAC SHA256 without cropping the result
			cc7::ByteArray result = crypto::HMAC_SHA256(masterKey, index, 0);
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

	
	std::string CalculateSignature(const SignatureKeys & sk, SignatureFactor factor, cc7::U64 ctr, const cc7::ByteRange & data)
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
		
		// Prepare data with counter; [ 0x0 * 8 + BigEndian(ctr) ]
		auto counter = _U64ToData(ctr);
		std::string result;
		for (size_t i = 0; i < keys.size(); i++) {
			// Outer loop, for over key in the vector.
			const cc7::ByteArray & signature_key = *keys[i];
			auto derived_key = crypto::HMAC_SHA256(counter, signature_key, 0);
			if (derived_key.size() == 0) {
				CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
				return std::string();
			}
			for (size_t j = 0; j < i; j++) {
				const cc7::ByteArray & signature_key_inner = *keys[j + 1];
				auto derived_key_inner = crypto::HMAC_SHA256(counter, signature_key_inner, 0);
				derived_key = crypto::HMAC_SHA256(derived_key, derived_key_inner, 0);
				if (derived_key.size() == 0) {
					CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
					return std::string();
				}
			}
			// Calculate HMAC for given data
			auto signature_long = crypto::HMAC_SHA256(data, derived_key, 0);
			if (signature_long.size() == 0) {
				CC7_ASSERT(false, "HMAC_SHA256() calculation failed.");
				return std::string();
			}
			// Finally, calculate decimalized value from signature and append it to the
			// output string.
			auto signature = CalculateDecimalizedSignature(signature_long);
			if (!result.empty()) {
				result.append(DASH);
			}
			result.append(signature);
		}
		return result;
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
	
	
	std::string CalculateApplicationSignature(const std::string & activationIdShort,
											  const std::string & activationNonce,
											  const std::string & cDevicePublicKey,
											  const std::string & applicationKey,
											  const std::string & applicationSecret)
	{
		cc7::ByteArray app_secret;
		bool b_result = app_secret.readFromBase64String(applicationSecret);
		if (b_result == false || app_secret.empty()) {
			return std::string();
		}
		
		std::string data_for_signature;
		data_for_signature.append(activationIdShort);
		data_for_signature.append(AMP);
		data_for_signature.append(activationNonce);
		data_for_signature.append(AMP);
		data_for_signature.append(cDevicePublicKey);
		data_for_signature.append(AMP);
		data_for_signature.append(applicationKey);
		
		auto signature = crypto::HMAC_SHA256(cc7::MakeRange(data_for_signature), app_secret, 0);
		return cc7::ToBase64String(signature);
	}

	/**
	 Convers |val| to normalized string. Zero characters are used for the indentation padding
	 when the string representation is shorter than 8 characters (e.g. 123 is converted to "00000123").
	 */
	static std::string _ValToNormString(cc7::U32 val)
	{
		std::string result = std::to_string(val);
		static const std::string zero("00000000");
		if (result.length() < protocol::HK_DEVICE_PUBLIC_KEY_SIZE) {
			result.insert(0, zero.substr(0, protocol::HK_DEVICE_PUBLIC_KEY_SIZE - result.length()));
		}
		CC7_ASSERT(result.length() == protocol::HK_DEVICE_PUBLIC_KEY_SIZE, "Wrong normalized size");
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


	
} // io::getlime::powerAuth::protocol
} // io::getlime::powerAuth
} // io::getlime
} // io
