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

#include <PowerAuth/PublicTypes.h>

namespace io
{
namespace getlime
{
namespace powerAuth
{	
	/**
	 The Encryptor class provides an End-To-End Encryption between the client
	 and the server. This class is used for both personalized and nonpersonalized
	 E2EE modes of PA2 protocol.
	 
	 The direct instantiation of the object is not allowed but you can use the
	 Session class for this purpose. You can use Session.createNonpersonalizedEncryptor()
	 or Session.createPersonalizedEncryptor() methods depending on what kind of 
	 encryptor you need.
	 */
	class Encryptor
	{
	public:

		// MARK: - Public API
		
		/**
		 Mode of encryption
		 */
		enum Mode
		{
			Nonpersonalized, Personalized,
		};
		
		/**
		 Returns current encryption mode.
		 */
		Mode encryptionMode() const;

		/**
		 Returns session index.
		 */
		const cc7::ByteArray & sessionIndex() const;
		
		/**
		 Encrypts a given bytes from |data| parameter and fills the |out_message| structure with
		 the result. The method fills appropriate members of the structure depending on the mode
		 of encryption. For more details, check the EncryptedMessage structure documentation.
		 
		 Returns EC_Ok			if operation succeeded
				 EC_Encryption	if internal encryption operation failed
		 */
		ErrorCode encrypt(const cc7::ByteRange & data, EncryptedMessage & out_message);
		
		/**
		 Decrypts data from |message| and fills the result to the |out_data| byte array.
		 The EncryptedMessage structure must contain all mandatory properties for current
		 encryption mode. For more details, check the EncryptedMessage structure documentation.
		 
		 Returns EC_Ok			if operation succeeded
				 EC_WrongParam	if the provided message contains invalid data or
								if some required property is missing
				 EC_Encryption	if the decryption operation failed

		 */
		ErrorCode decrypt(const EncryptedMessage & message, cc7::ByteArray & out_data);
		
		// Disable object copying
		Encryptor(const Encryptor &) = delete;
		Encryptor& operator=(const Encryptor &) = delete;
		
	private:
		friend class Session;
		
		/**
		 Current encryptor mode
		 */
		Mode			_mode;
		/**
		 Session index used during the object creation.
		 */
		cc7::ByteArray	_session_index;
		/**
		 Partial encryption key
		 */
		cc7::ByteArray	_key_transport_partial;
		/**
		 Ephemeral public key in Base64 format.
		 */
		std::string		_ephemeral_public_key;
		/**
		 The content of the member vary between the encryptor modes. If the personalized mode is in use
		 then the activation id is stored in the member. Otherwise the application key is present.
		 */
		std::string		_app_key_or_activation_id;
		
		// MARK: - Construction & Setup
		
		/**
		 Constructs an Encryptor instance for required mode. The transport key, as it is, is not stored 
		 in the instance but is used for partial transport key derivation.
		 */
		Encryptor(Mode mode, const cc7::ByteRange & session_index, const cc7::ByteRange & transport_key);
		
		/**
		 Sets params required for personalized mode of the operation.
		 */
		void setPersonalizedParams(const std::string & activation_id);
		/**
		 Sets params required for nonpersonalized mode of the operation.
		 */
		void setNonpersonalizedParams(const std::string & ephemeral_key, const std::string & application_key);
		/**
		 Validates current configuration (combination of keys & per-mode variables) and returns
		 true if configuration is correct.
		 */
		bool validateConfiguration() const;
	};
	
	
} // io::getlime::powerAuth
} // io::getlime
} // io
