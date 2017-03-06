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

#include <PowerAuth/Encryptor.h>
#include <cc7/Base64.h>
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"
#include "crypto/CryptoUtils.h"

using namespace io::getlime::powerAuth::protocol;

namespace io
{
namespace getlime
{
namespace powerAuth
{
	//
	// MARK: - Helper structure -
	//
	
	/**
	 The E2EEData is an internal structure used during the End-To-End Encryption operations.
	 */
	struct E2EEData
	{
		// Input or Output members, mapped to public EncryptedMessage structure.
		Encryptor::Mode mode;
		cc7::ByteArray encryptedData;
		cc7::ByteArray mac;
		cc7::ByteArray sessionIndex;
		cc7::ByteArray adHocIndex;
		cc7::ByteArray macIndex;
		cc7::ByteArray nonce;
		
		E2EEData(Encryptor::Mode mode)
			: mode(mode)
		{
		}
		
		bool importFromMessage(const EncryptedMessage & message)
		{
			bool result =	   cc7::Base64_Decode(message.encryptedData,	0, encryptedData);
			result = result && cc7::Base64_Decode(message.mac,				0, mac);
			result = result && cc7::Base64_Decode(message.sessionIndex,		0, sessionIndex);
			result = result && cc7::Base64_Decode(message.adHocIndex,		0, adHocIndex);
			result = result && cc7::Base64_Decode(message.macIndex,			0, macIndex);
			result = result && cc7::Base64_Decode(message.nonce,			0, nonce);
			
			// validate sizes...
			result = result &&
					 sessionIndex.size() == protocol::SIGNATURE_KEY_SIZE &&
					 adHocIndex.size() == protocol::SIGNATURE_KEY_SIZE &&
					 macIndex.size() == protocol::SIGNATURE_KEY_SIZE &&
					 nonce.size() == protocol::SIGNATURE_KEY_SIZE;
			return result;
		}
		
		bool exportToMessage(EncryptedMessage & out_message)
		{
			out_message.encryptedData	= cc7::ToBase64String(encryptedData);
			out_message.mac				= cc7::ToBase64String(mac);
			out_message.sessionIndex	= cc7::ToBase64String(sessionIndex);
			out_message.adHocIndex		= cc7::ToBase64String(adHocIndex);
			out_message.macIndex		= cc7::ToBase64String(macIndex);
			out_message.nonce			= cc7::ToBase64String(nonce);
			
			return true;
		}
	};
	
	// MARK: - Encryptor implementation -
	
	// MARK: Construction
	
	Encryptor::Encryptor(Mode mode, const cc7::ByteRange & session_index, const cc7::ByteRange & transport_key) :
		_mode(mode),
		_session_index(session_index)
	{
		_key_transport_partial = protocol::DeriveSecretKeyFromIndex(transport_key, _session_index);
	}
	
	void Encryptor::setPersonalizedParams(const std::string & activation_id)
	{
		if (CC7_CHECK(_mode == Personalized, "Encryptor is configured for different mode")) {
			_app_key_or_activation_id = activation_id;
		}
	}
	
	void Encryptor::setNonpersonalizedParams(const std::string & ephemeral_key, const std::string & application_key)
	{
		if (CC7_CHECK(_mode == Nonpersonalized, "Encryptor is configured for different mode")) {
			_ephemeral_public_key		= ephemeral_key;
			_app_key_or_activation_id	= application_key;
		}
	}
	
	bool Encryptor::validateConfiguration() const
	{
		bool result = _session_index.size() == protocol::SIGNATURE_KEY_SIZE;
		result = result && _key_transport_partial.size() == protocol::SIGNATURE_KEY_SIZE;
		result = result && !_app_key_or_activation_id.empty();
		if (_mode == Nonpersonalized) {
			result = result && !_ephemeral_public_key.empty();
		}
		return result;
	}
	
	
	// MARK: - Getters
	
	const cc7::ByteArray & Encryptor::sessionIndex() const
	{
		return _session_index;
	}
	
	Encryptor::Mode Encryptor::encryptionMode() const
	{
		return _mode;
	}
	
	
	// MARK: - Encrypt / Decrypt
	
	ErrorCode Encryptor::encrypt(const cc7::ByteRange & data, EncryptedMessage & out_message)
	{
		CC7_ASSERT(validateConfiguration(), "Using encryptor with invalid configuration");
		
		E2EEData edata(_mode);
		
		// Prepare unique cryptographic indexes & nonce
		std::vector<const cc7::ByteRange> indexes;
		indexes.reserve(4);
		edata.sessionIndex	= _session_index;
		indexes.push_back(protocol::ZERO_IV);
		indexes.push_back(edata.sessionIndex);
		edata.adHocIndex	= crypto::GetUniqueRandomData(protocol::SIGNATURE_KEY_SIZE, indexes);
		indexes.push_back(edata.adHocIndex);
		edata.macIndex		= crypto::GetUniqueRandomData(protocol::SIGNATURE_KEY_SIZE, indexes);
		edata.nonce			= crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE, true);
		if (edata.sessionIndex.empty() || edata.adHocIndex.empty() || edata.macIndex.empty() || edata.nonce.empty()) {
			return EC_Encryption;
		}
		
		// Compute transport encryption key & enctypt data
		auto encryption_key	= protocol::DeriveSecretKeyFromIndex(_key_transport_partial, edata.adHocIndex);
		edata.encryptedData = crypto::AES_CBC_Encrypt_Padding(encryption_key, edata.nonce, data);
		if (encryption_key.empty() || edata.encryptedData.empty()) {
			return EC_Encryption;
		}
	
		// Calculate signature
		auto mac_key		= protocol::DeriveSecretKeyFromIndex(_key_transport_partial, edata.macIndex);
		edata.mac			= crypto::HMAC_SHA256(edata.encryptedData, mac_key, 0);
		if (mac_key.empty() || edata.mac.empty()) {
			return EC_Encryption;
		}
		
		// Fill to message structure
		edata.exportToMessage(out_message);
		
		if (_mode == Nonpersonalized) {
			// Fill optional members for nonpersonalized mode
			out_message.ephemeralPublicKey	= _ephemeral_public_key;
			out_message.applicationKey		= _app_key_or_activation_id;
			out_message.activationId.clear();
		} else {
			// Fill optional members for personalized mode
			out_message.activationId		= _app_key_or_activation_id;
			out_message.ephemeralPublicKey.clear();
			out_message.applicationKey.clear();
		}
		return EC_Ok;
	}
	
	
	
	ErrorCode Encryptor::decrypt(const EncryptedMessage & message, cc7::ByteArray & out_data)
	{
		CC7_ASSERT(validateConfiguration(), "Using encryptor with invalid configuration");
		
		E2EEData edata(_mode);
		// Import & validate message
		bool valid = edata.importFromMessage(message);
		valid = valid && _mode == edata.mode;
		valid = valid && _session_index == edata.sessionIndex;
		if (_mode == Nonpersonalized) {
			valid = valid && message.applicationKey		== _app_key_or_activation_id;
			valid = valid && message.ephemeralPublicKey == _ephemeral_public_key;
		} else {
			valid = valid && message.activationId		== _app_key_or_activation_id;
		}
		if (!valid) {
			return EC_WrongParam;
		}
		
		// Validate encrypted data
		auto mac_key		= protocol::DeriveSecretKeyFromIndex(_key_transport_partial, edata.macIndex);
		auto our_mac		= crypto::HMAC_SHA256(edata.encryptedData, mac_key, 0);
		
		// Compute transport key & decrypt data
		bool dec_error;
		auto decryption_key	= protocol::DeriveSecretKeyFromIndex(_key_transport_partial, edata.adHocIndex);
		out_data			= crypto::AES_CBC_Decrypt_Padding(decryption_key, edata.nonce, edata.encryptedData, &dec_error);
		
		// Validate result and return right error code.
		return (dec_error || our_mac != edata.mac) ? EC_Encryption : EC_Ok;
	}
	
} // io::getlime::powerAuth
} // io::getlime
} // io
