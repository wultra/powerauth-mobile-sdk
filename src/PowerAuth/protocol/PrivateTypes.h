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

#pragma once

#include <PowerAuth/PublicTypes.h>
#include <openssl/ec.h>

// Forward declarations

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace utils
{

	class DataReader;
	class DataWriter;
}
}
}
}


namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
	// MARK: - Private structures -
	
	// Additional SignatureFactor flags
	
	/**
	 Used internally for transportation key unlocking.
	 */
	const SignatureFactor SF_Transport                        = 0x4000;
	/**
	 Used internally for keys locking, during the activation process.
	 */
	const SignatureFactor SF_FirstLock                        = 0x8000;

	
	/**
	 The ActivationData structure contains all information
	 received, generated or calculated during the activation
	 process.
	 */
	struct ActivationData
	{
		// OpenSSL EC keys, used during the activation
		
		EC_KEY *		masterServerPublicKey;
		EC_KEY *		devicePrivateKey;
		EC_KEY *		serverPublicKey;
		
		// Information gathered during the activation
		
		std::string		activationCode;			// Step1: short activation ID
		std::string		activationId;			// Step2: Full activation ID
		
		// Information generated or received during the activation
		
		cc7::ByteArray	serverPublicKeyData;	// Server's public key
		cc7::ByteArray	devicePublicKeyData;	// Our public key
		
		cc7::ByteArray	masterSharedSecret;		// The result of ECDH. This value is VERY sensitive!
		cc7::ByteArray	ctrData;				// Initial value for hash-based counter
		RecoveryData	recoveryData;			// Received recovery data
		
		// Construction, destruction
		
		ActivationData() :
			masterServerPublicKey(nullptr),
			devicePrivateKey(nullptr),
			serverPublicKey(nullptr)
		{
		}
		
		~ActivationData()
		{
			EC_KEY_free(masterServerPublicKey);
			EC_KEY_free(devicePrivateKey);
			EC_KEY_free(serverPublicKey);
		}
	};
	
	
	/**
	 The SignatureKeys structure contains locked or unlocked keys for signatures. 
	 The content of the structure may be very sensitive and should not be exposed 
	 to the public interface.
	 */
	struct SignatureKeys
	{
		cc7::ByteArray		possessionKey;
		cc7::ByteArray		knowledgeKey;
		cc7::ByteArray		biometryKey;
		cc7::ByteArray		transportKey;
		
		bool usesExternalKey;
		
		SignatureKeys() :
			usesExternalKey(false)
		{
		}
	};
	
	
	/**
	 The PersistentData structure contains information about valid activation.
	 This data structure must be completely serialized into the persistent storage.
	 */
	struct PersistentData
	{
		/**
		 V2: Counter for signature calculations
		 */
		cc7::U64		signatureCounter;
		/**
		 V3: Data for hash-based counter for signature calculations
		 */
		cc7::ByteArray	signatureCounterData;
		/**
		 V3.1: Least significant byte from the signature counter
		 */
		cc7::byte		signatureCounterByte;
		/**
		 ActivationId, that's our identity known on the server
		 */
		std::string		activationId;
		/**
		 Number of iterations for PBKDF2
		 */
		cc7::U32		passwordIterations;
		/**
		 Salt value for PBKDF2
		 */
		cc7::ByteArray	passwordSalt;
		/**
		 Actual signature keys. Each key in the structure is encrypted
		 with appropriate protection key (check the SignatureUnlockKeys structure)
		 */
		SignatureKeys	sk;
		/**
		 Server's public key
		 */
		cc7::ByteArray	serverPublicKey;
		/**
		 Device's public key
		 */
		cc7::ByteArray	devicePublicKey;
		/**
		 Encrypted device's private key.
		 */
		cc7::ByteArray	cDevicePrivateKey;
		/**
		 Encrypted recovery data.
		 */
		cc7::ByteArray	cRecoveryData;

		struct _Flags {
			/**
			 True if the session is waiting for vault key unlock.
			 The flag is deprecated sice protocol V3, and should not be used.
			 */
			cc7::U32	waitingForVaultUnlock	: 1;
			/**
			 True if activation was estabilished with additional 
			 external key.
			 */
			cc7::U32	usesExternalKey			: 1;
			/**
			 Bits reserved for current pending protocol upgrade
			 */
			cc7::U32	pendingUpgradeVersion	: 8;
			/**
			 True if `signatureCounterByte` is valid and can be used for calculations.
			 */
			cc7::U32	hasSignatureCounterByte	: 1;
		};
		union {
			_Flags		flags;
			cc7::U32	flagsU32;
		};
		
		static_assert(sizeof(_Flags) <= sizeof(cc7::U32), "Flags structure is too big");
		
		PersistentData() :
			signatureCounter(0),
			passwordIterations(0),
			flagsU32(0)
		{
		}
		
		/**
		 Returns version of protocol, depending on data stored in the structure.
		 */
		inline Version protocolVersion() const
		{
			return signatureCounterData.empty() ? Version_V2 : Version_V3;
		}
		
		/**
		 Returns true if data stored in structure matches V3 protocol.
		 */
		inline bool isV3() const {
			return protocolVersion() == Version_V3;
		}
	};
	
	
	/**
	 The SignatureUnlockKeysReq is internal structure and helps with internal keys
	 locking & unlocking. All objects referenced in the structure must still exist and
	 must be valid during the whole operation.
	 
	 The structure simply keeps all possible parameters required for signature keys unlocking
	 (or locking, during the activation). You should use designed constructor for structure
	 creation.
	 */
	struct SignatureUnlockKeysReq
	{
		SignatureUnlockKeysReq(SignatureFactor sf, const SignatureUnlockKeys * ukeys, const cc7::ByteArray * ext_key,
							   const cc7::ByteArray * salt, uint32_t iterations) :
			factor(sf),
			keys(ukeys),
			ext_key(ext_key),
			pbkdf2_salt(salt),
			pbkdf2_iter(iterations)
		{
		}
		SignatureFactor				factor;
		const SignatureUnlockKeys *	keys;
		const cc7::ByteArray *		ext_key;
		const cc7::ByteArray *		pbkdf2_salt;
		cc7::U32					pbkdf2_iter;
	};

	
	// MARK: - Helper functions -
	
	/**
	 Validates session setup, assigned during the module construction. If parameter |also_validate_key|
	 is true then also validates whether the provided key is valid or not. Use this value wisely, because
	 the key validation must import ECC public key and that's time consuming operation.
	 */
	bool ValidateSessionSetup(const SessionSetup & setup, bool also_validate_key);
	
	/**
	 Validates content of presistent data. The method simply validates key sizes
	 and presence of required attributes in the PD structure.
	 */
	bool ValidatePersistentData(const PersistentData & pd);
	
	/**
	 Validates whether |factor| contains valid combination of factors.
	 */
	bool ValidateSignatureFactor(SignatureFactor factor);
	
	/**
	 Validates |unlock| keys and the external key, if the key is present. The function simply checks whether
	 the provided keys in the structure have correct lengths and there's an appropriate key for each required 
	 signature factor. The |ext_key| parameter is optional and may be NULL.
	 */
	bool ValidateUnlockKeys(const SignatureUnlockKeys & unlock, const cc7::ByteArray * ext_key, SignatureFactor factor);
	
	/**
	 Validates internal signature |keys| structure. The function simply checks whether the provided keys
	 in the structure have correct lengths and there's an appropriate key for each required signature factor.
	 */
	bool ValidateSignatureKeys(const SignatureKeys & keys, SignatureFactor factor);
	
	/**
	 Simply returns SF_Possession_Knowledge_Biometry if |has_biometry| is true or
	 SF_Possession_Knowledge mask, if not.
	 */
	inline SignatureFactor FullFactorMask(bool has_biometry)
	{
		return has_biometry
				? SF_Possession_Knowledge_Biometry
				: SF_Possession_Knowledge;
	}
	
	
	//
	// MARK: - Serialization -
	//
	
	/**
	 Serializes a persistent data from |pd| structure into the provided |writer|. The current
	 implementation of the function always returns true.
	 */
	bool SerializePersistentData(const PersistentData & pd, utils::DataWriter & writer);
	
	/**
	 Deserializes a persistent data from the |reader| into the |pd| reference.
	 Returns false if the byte stream contains invalid data.
	 */
	bool DeserializePersistentData(PersistentData & pd, utils::DataReader & reader);

	
	//
	// MARK: - Recovery codes -
	//
	
	/**
	 Validates |data| in provided structure and returns true if structure contains valid data. The true is returned also
	 in case that RecoveryData structure is empty.
	 */
	bool ValidateRecoveryData(const RecoveryData & data);
	
	/**
	 Serializes provided |data| structure into sequence of bytes and then encrypts that sequence with using |vaultKey|.
	 The resulted sequence of bytes is stored to the |out_data| array. If |data| structure is empty, then result is
	 an empty sequence of bytes.
	 
	 Returns false in case of encryption failure.
	 */
	bool SerializeRecoveryData(const RecoveryData & data, const cc7::ByteRange vault_key, cc7::ByteArray & out_data);
	
	/**
	 Decrypts provided |serialized| data with using vault key and then deserializes decrypted sequence into |out_data|
	 structure. Returns true in case that both steps succeeded.
	 */
	bool DeserializeRecoveryData(const cc7::ByteRange & serialized, const cc7::ByteRange vault_key, RecoveryData & out_data);
	
		
} // io::getlime::powerAuth::detail
} // io::getlime::powerAuth
} // io::getlime
} // io
