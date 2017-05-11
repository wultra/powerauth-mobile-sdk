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

namespace io
{
namespace getlime
{
namespace powerAuth
{
	//
	// MARK: - Setup & Error code -
	//

	/**
	 The SessionSetup structure defines unique constants required during the lifetime
	 of the Session class.
	 */
	struct SessionSetup
	{
		/**
		 Defines APPLICATION_KEY for the session.
		 */
		std::string applicationKey;
		
		/**
		 Defines APPLICATION_SECRET for the module.
		 */
		std::string applicationSecret;
		
		/**
		 The master server public key, in BASE64 format.
		 It's strongly recommended to use different keys for the testing
		 and production servers.
		 */
		std::string masterServerPublicKey;
		
		/**
		 Optional session identifier helps with session identification
		 in multi-session environments. You can assign any value
		 which helps you identify multiple sessions in your system.
		 The session itself doesn't use this value.
		 */
		cc7::U32 sessionIdentifier;
		
		/**
		 Optional external encryption key. If the array contains 16 bytes,
		 then the key is considered as valid and will be used during the
		 cryptographic operations.
		 
		 The additional encryption key is useful in  multibanking applications, where it allows the
		 application to create chain of trusted PA2 activations. If the key is set, then the session will
		 perform additional encryption / decryption operations when the signature keys are being used.
		 
		 The session implements a couple of simple protections against misuse of this feature and therefore
		 once the session is activated with the EEK, then you have to use that EEK for all future cryptographic
		 operations. The key is NOT serialized in the session's state and thus it's up to the application,
		 how it manages the chain of multiple PA2 sessions.
		 */
		cc7::ByteArray externalEncryptionKey;
		
		/**
		 Constructs a new empty setup structure.
		 */
		SessionSetup() :
			sessionIdentifier(0)
		{
		}
	};
	
	
	/**
	 The ErrorCode enumeration defines all possible error codes
	 produced by Session class. You normally need to check only
	 if operation ended with EC_Ok or not. All other codes are
	 only hints and should be used only for debugging purposes.
	 
	 For example, if the operation fails at EC_WrongState or EC_WrongParam,
	 then it's usualy your fault and you're using session in wrong way.
	 */
	enum ErrorCode
	{
		/**
		 Everything is OK.
		 You can go out with your friends and enjoy the beer or two :)
		 */
		EC_Ok = 0,
		/**
		 The method failed on an encryption. Whatever that means it's
		 usually very wrong and the UI response depends on what
		 method did you call. Typically, you have to perform retry
		 or restart for the whole process.
		 
		 This error code is also returned when decoding of important
		 parameter failed. For example, if BASE64 encoded value
		 is in wrong format, then this is considered as an attack
		 attempt.
		 */
		EC_Encryption,
		/**
		 You have called method in wrong session's state. Usually that
		 means that you're using session in a  wrong way. This kind
		 of error should not be propagated to the UI. It's your
		 responsibility to handle session states correctly.
		 */
		EC_WrongState,
		/**
		 You have called method with wrong or missing parameters.
		 Usually this error code means that you're using session
		 in wrong way and you did not provide all required data.
		 This kind of error should not be propagated to UI. It's
		 your responsibility to handle all user's inputs
		 and validate all responses from server before you
		 ask session for processing.
		 */
		EC_WrongParam,
	};
	
	
	//
	// MARK: - Signatures -
	//
	
	/**
     The SignatureFactor constants defines factors involved in the signature
     computation. The factor types are tightly coupled with SignatureUnlockKeys
     structure.
     */
	typedef int SignatureFactor;
	/**
	 The possession factor, you have to provide possessionUnlocKey.
	 */
	const SignatureFactor SF_Possession				= 0x0001;
	/**
	 The knowledge factor, you have to provide userPassword
	 */
	const SignatureFactor SF_Knowledge				= 0x0010;
	/**
	 The biometry factor, you have to provide biometryUnlockKey.
	 */
	const SignatureFactor SF_Biometry				= 0x0100;
	/**
	 2FA, with using possession and knowledge factors.
	 */
	const SignatureFactor SF_Possession_Knowledge			= SF_Possession | SF_Knowledge;
	/**
	 2FA, with using possession and biometric factors.
	 */
	const SignatureFactor SF_Possession_Biometry			= SF_Possession | SF_Biometry;
	/**
	 3FA, with using all supported factors.
	 */
	const SignatureFactor SF_Possession_Knowledge_Biometry	= SF_Possession | SF_Knowledge | SF_Biometry;
	
	/**
	 You can combine any signature factor with this flag and prepare for vault unlock.
	 */
	const SignatureFactor SF_PrepareForVaultUnlock	= 0x1000;
	
	
	/**
	 The SignatureUnlockKeys object contains all keys, required for signature computation.
	 You have to provide all keys involved into the signature computation, for selected combination
	 of factors. For example, if you're going to compute signature for Possession + Biometry
	 factor, then this object must contain valid possessionUnlockKey and biometryUnlockKey.
	 
	 Discussion
	 
	 Internally, the Session keeps keys for signature computation always encrypted
	 and doesn't expose these from outside of the class. This very strict approach is
	 a prevention against accidental sensitive information leakage. Your application has
	 control only over the keys, which actually encrypts and decrypts this sensitive information.
	 
	 At first read, it looks like that this additional protection layer has no cryptographic 
	 benefit at all. Yes, this is basically true :) The purpose of this layer is just to simplify 
	 the Session's interface. In this approach, the exact state of the session is always fully 
	 serializable and the only application's responsibility is to provide the lock / unlock keys 
	 in the right time, when these are really required. 
	 
	 But still, you need to take care about how you're working
	 with these unlock keys.
	 */
	struct SignatureUnlockKeys
	{
		/**
		 The key required for signatures with "possession" factor.
		 You have to provide a key based on the unique properties of the device.
		 For example, WI-FI MAC address or UDID are a good sources for this
		 key. You can use Session::normalizeSignatureUnlockKeyFromData method
		 to convert arbitrary data into normalized key.
		 
		 It is recommended to calculate this key for once, when the application starts
		 and store in the volatile memory. You should never save this key to the
		 permanent storage, like file system or keychain.
		 
		 You cannot use data object filled with zeros as a key.
		 */
		cc7::ByteArray possessionUnlockKey;
		/**
		 The key required for signatures with "biometry" factor. You should not
		 use this key and factor, if device has no biometric engine available.
		 You can use Session::generateSignatureUnlockKey for new key creation.
		 
		 You should store this key only to the storage, which can protect the
		 key with using the biometry engine. For example, on iOS9+, you can use
		 a keychain record, created with kSecAccessControlTouchID* flags.
		 
		 You cannot use data object filled with zeros as a key.
		 */
		cc7::ByteArray biometryUnlockKey;
		/**
		 The password required for signatures with "knowledge" factor. The complexity
		 of the password depends on the rules, defined by the application. You should
		 never store the password to the permanent storage (like file system, or keychain)
		 
		 The Session validates only the minimum lenght of the password (check private
		 Constants.h and MINIMAL_PASSWORD_LENGTH constant for details)
		 */
		cc7::ByteArray userPassword;
	};
	
	
	/**
	 The HTTPRequestData structure contains all data required for signature calculation.
	 You have to provide values at least non-empty strings to `method` and `uri` members,
	 to pass a data validation.
	 */
	struct HTTPRequestData
	{
		/**
		 A whole POST body or data blob prepared in 'Session::prepareKeyValueMapForDataSigning'
		 method. You can also calculate signature for an empty request with no body or without 
		 any GET parameters. In this case the member may be empty.
		 */
		cc7::ByteArray body;
		/**
		 HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected)
		 */
		std::string method;
		/**
		 Relative URI of the request.
		 */
		std::string uri;
		/**
		 Optional, contains NONCE generated externally, for offline data signing purposes.
		 */
		cc7::ByteArray offlineNonce;
		
		/**
		 Constructs an empty HTTPRequestData structure.
		 */
		HTTPRequestData();
		
		/**
		 Constructs a HTTPRequestData structure with provided |body|, |method| 
		 and |uri| parameters. The optional `offlineNonce` member will be empty.
		 */
		HTTPRequestData(const cc7::ByteRange & body,
						const std::string & method,
						const std::string & uri);
		
		/**
		 Constructs a HTTPRequestData structure with provided |body|, |method|, |uri| 
		 and |nonce| parameters.
		 */
		HTTPRequestData(const cc7::ByteRange & body,
						const std::string & method,
						const std::string & uri,
						const cc7::ByteRange & nonce);
		
		/**
		 Returns true when structure contains valid data.
		 */
		bool hasValidData() const;
	};
	
	/**
	 The HTTPRequestDataSignature object contains result from HTTP request data signing 
	 operation.
	 */
	struct HTTPRequestDataSignature
	{
		/**
		 Version of PowerAuth protocol. Current value is "2.0"
		 */
		std::string version;
		/**
		 Activation identifier received during the actiation process.
		 */
		std::string activationId;
		/**
		 Application key copied from SessionSetup structure.
		 */
		std::string applicationKey;
		/**
		 NONCE used for the signature calculation.
		 */
		std::string nonce;
		/**
		 String representation of signature factor.
		 */
		std::string factor;
		/**
		 Calculated signature
		 */
		std::string signature;
		
		/**
		 Builds a value for "X-PowerAuth-Authorization" HTTP header.
		 */
		std::string buildAuthHeaderValue() const;
	};
	
	
	//
	// MARK: - Session activation steps -
	//
	
	/**
	 Parameters for first step of device activation.
	 */
	struct ActivationStep1Param
	{
		/**
		 Short activation ID
		 */
		std::string activationIdShort;
		/**
		 Activation OTP (one time password)
		 */
		std::string activationOtp;
		/**
		 Signature calculated from activationIdShort and activationOtp.
		 The value is optional in cases, when the user re-typed codes
		 manually. If the value is available, then the Base64 string is expected.
		 */
		std::string	activationSignature;
	};
	
	/**
	 Result from first step of device activation.
	 */
	struct ActivationStep1Result
	{
		/**
		 Activation nonce, in Base64 format.
		 */
		std::string	activationNonce;
		/**
		 Encrypted device's public key, in Base64 format.
		 */
		std::string	cDevicePublicKey;
		/**
		 Application signature proving that activation was completed
		 with correct application, in Base64 format.
		 */
		std::string	applicationSignature;
        /**
         An ephemeral public key used to deduce ad-hoc encryption
         secret for cDevicePublicKey, in Base64 format.
         */
        std::string ephemeralPublicKey;
	};
	
	/**
	 Parameters for second step of device activation.
	 */
	struct ActivationStep2Param
	{
		/**
		 Real Activation ID received from server.
		 */
		std::string	activationId;
		/**
		 Ephemeral nonce, generated on the server, in Base64 format.
		 */
		std::string	ephemeralNonce;
		/**
		 Server's part for ephemeral key in Base64 format.
		 */
		std::string	ephemeralPublicKey;
		/**
		 Encrypted server public key, in Base64 format.
		 */
		std::string	encryptedServerPublicKey;
		/**
		 Siganture, calculated from activationId & encryptedServerPublicKey,
		 in Base64 format.
		 */
		std::string	serverDataSignature;
	};
	
	/**
	 Result from 2nd step of activation.
	 */
	struct ActivationStep2Result
	{
		/**
		 Short, human readable string, calculated from device's public key.
		 You can display this code to the UI and user can confirm visually
		 if the code is the same on both, server & client sides. This feature
		 must be supported on the server's side of the activation flow.
		 */
		std::string	hkDevicePublicKey;
	};
	
	
	
	//
	// MARK: - Activation status -
	//

	
	/**
	 The ActivationStatus structure represents complete status
	 of the activation. The status is typically received
	 as an encrypted blob and you can use Session to decode
	 that blob into this structure.
	 */
	struct ActivationStatus
	{
		/**
		 The State enumeration defines all possible states of activation.
		 The state is a part of information received together with the rest
		 of the ActivationStatus structure. Don't misinterpret this enumeration
		 as a session's internal state. These enumerations have complete different
		 meanings.
		 */
		enum State
		{
			Created  = 1,
			OTP_Used = 2,
			Active   = 3,
			Blocked  = 4,
			Removed  = 5,
		};
		
		/**
		 State of the activation
		 */
		State state;
		/**
		 Number of failed authentication attempts in a row.
		 */
		cc7::U32 failCount;
		/**
		 Maximum number of allowed failed authentication attempts in a row.
		 */
		cc7::U32 maxFailCount;
		/**
		 Counter on the server's side. The session should not synchronize
		 itself with this counter.
		 */
		cc7::U64 counter;
		
		/**
		 Constructs a new empty activation status structure.
		 */
		ActivationStatus() :
			state(Created),
			failCount(0),
			maxFailCount(0),
			counter(0)
		{
		}
	};
	
	
	
	//
	// MARK: - End-To-End Encryption -
	//
	
	
	/**
	 The EncryptedMessage structure represents an encrypted data transmitted 
	 between the client and the server. The object is mostly used as a parameter in
	 interface, provided by Encryptor class.
	 
	 The message is used in both ways, for the request encryption and also for 
	 response decryption. Note that some members of the structure are optional
	 or depends on the mode of E2EE or the direction of communication.
	 
	 For more details check the online documentation about End-To-End Encryption.
	 */
	struct EncryptedMessage
	{
		/**
		 Contains applicationKey copied from the Session which constructed the Encryptor
		 object. The value is valid only for non-personalized encryption and is
		 validated in responses, received from the server.
		 */
		std::string applicationKey;
		/**
		 Contains activationId copied  from the Session which constructed the Encryptor
		 object. The value is valid only for personalized encryption and is validated
		 in responses, received from the server.
		 */
		std::string activationId;
		/**
		 Data encrypted in the Encryptor or decrypted by the class when received
		 a response from the server.
		 */
		std::string encryptedData;
		/**
		 Encrypted data signature.
		 */
		std::string mac;
		/**
		 Key index specific for one particular Encryptor. The value is validated for
		 responses received from the server.
		 
		 Note that the term "session" is different than the Session used in this PA2 
		 implementation. The "sessionIndex" in this case is a constant representing
		 an estabilished session between client and the server. It's up to application
		 to acquire and manage the value. Check the PA2 online documentation for details.
		 */
		std::string sessionIndex;
		/**
		 Key index used for one request or response. The value is calculated by
		 the Encryptor during the encryption and required in decryption operation.
		 */
		std::string adHocIndex;
		/**
		 Key index used for one request or response. The value is calculated by
		 the Encryptor during the encryption and required in decryption operation.
		 */
		std::string macIndex;
		/**
		 Nonce value used as IV for encryption. The value is calculated by
		 the Encryptor during the encryption and required in decryption operation.
		 */
		std::string nonce;
		/**
		 A key used for deriving temporary secret. The value is provided by 
		 the Encryptor class during the encryption operation, but only if the 
		 nonpersonalized mode is in use.
		 */
		std::string ephemeralPublicKey;		
	};
	
} // io::getlime::powerAuth
} // io::getlime
} // io
