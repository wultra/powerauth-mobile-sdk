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
#include <map>
#include <tuple>

namespace io
{
namespace getlime
{
namespace powerAuth
{
	/*
	 Forward declaration for private objects
	 */
	namespace protocol
	{
		struct PersistentData;
		struct ActivationData;
	}
	
	/*
	 Forward declaration for public objects.
	 */
	class Encryptor;
	
	/**
	 The Session class provides all cryptographic operations defined in PowerAuth2
	 protocol. The object also represents a long term session estabilished
	 between the client and the server. 
	 
	 This is a low level C++ implementation, which should be wrapped and exported
	 in appropriate way to the programming environments, typically used on the mobile
	 platform.
	 */
	class Session
	{
	public:
		
		// MARK: - Construction / Destruction -
		
		/**
		 Initializes a session object with a given SessionSetup object. The session
		 is in not-activated state just after the object construction, but you
		 can call 'loadSessionState' or 'startActivation' to change that.
		 */
		Session(const SessionSetup & setup);
		
		/**
		 Object's destructor. You can destroy session in any state.
		 */
		~Session();
		
		// Disable object copying
		Session(const Session &) = delete;
		Session& operator=(const Session &) = delete;
		
		// MARK: - Initialization, State control -
		
		/**
		 Returns pointer to an internal SessionSetup structure. Returns null if
		 session has a no valid setup.
		 */
		const SessionSetup * sessionSetup() const;
		
		/**
		 Returns value of sessionSetup()->sessionIdentifier if the setup structure is present or 0 if not.
		 */
		cc7::U32 sessionIdentifier() const;
				
		/**
		 Resets session into its initial state. The existing session's setup and the external encryption
		 key is preserved by this call.
		 */
		void resetSession();

		
		// MARK: - State probing -
		
		/**
		 Returns true if the internal SessionSetup structure is valid. 
		 Note that the method doesn't validate whether the provided master key is valid
		 or not. The key validation is time consuming operation and therefore is
		 performend only during the activation process.
		 */
		bool hasValidSetup() const;
		/**
		 Returns true if the session is in state where it's possible to start a new activation.
		 */
		bool canStartActivation() const;
		/**
		 Returns true if the session has pending and unfinished activation.
		 */
		bool hasPendingActivation() const;
		/**
		 Returns true if the session has valid activation and the shared secret between the client and
		 the server has been estabilished. You can sign data in this state.
		 */
		bool hasValidActivation() const;
		
		
		// MARK: - Serialization -
		
		/**
		 Saves state of session into the sequence of bytes. The saved sequence contains content of 
		 internal PersistentData structure, if is present.
		 
		 Note that saving a state during the pending activation has no effect. In this case, 
		 the returned byte sequence represents the state of the session before the activation started.
		 */
		cc7::ByteArray saveSessionState() const;
		
		/**
		 Loads state of session from previously saved sequence of bytes. If the serialized state is
		 invalid then the session ends in its initial state.
		 */
		ErrorCode loadSessionState(const cc7::ByteRange & serialized_state);
		
		
		// MARK: - Activation -
		
		/**
		 If the session has valid activation, then returns the activation identifier.
		 Otherwise returns empty string.
		 */
		std::string activationIdentifier() const;
		
        /**
         Starts a new activation process. The session must have valid setup. Once the activation 
		 is started you have to complete whole activation sequence or reset a whole session.
         
         You have to provide ActivationStep1Param structure with all required properties available.
         The result of the operation is stored into the ActivationStep1Result structure.
         
         Returns EC_Ok,         if operation succeeded
                 EC_Encryption, if you provided invalid Base64 strings or if signature is invalid
                 EC_WrongState, if called in wrong session's state
                 EC_WrongParam, if some required parameter is missing
         */
		ErrorCode startActivation(const ActivationStep1Param & param, ActivationStep1Result & result);
		
		/**
		 Validates activation respose received from the server. The session expects that the activation
		 process was previously started with using 'startActivation' method. You have to provide 
		 ActivationStep2Param structure with all members filled with the response. The result of the
		 operation is stored in the ActivationStep2Result structure. If the response is correct then 
		 you can call 'completeActivation' and finish the activation process.
		 
		 Discussion
		 
		 If the operation succeeds then the PA2 handshake is from a network communication point of view
		 considered as complete. The server knows our client and both sides have calculated shared
		 secret key. Because of the complexity of the operation, there's one more separate step in our
		 activation flow, which finally protects all sensitive information with user password and
		 other local keys. This last step is offline only, no data is transmitted over the network
		 and therefore if you don't complete the activation (you can reset session for example)
		 then the server will keep its part of shared secret but nobody will be able to use that
		 estabilished context.
		 
		 Returns EC_Ok,         if operation succeeded
                 EC_Encryption, if provided data, signature or keys are invalid. 
                                If this error occurs then the session resets its state.
                 EC_WrongState, if called in wrong session's state
                 EC_WrongParam, if required parameter is missing
		 */
		ErrorCode validateActivationResponse(const ActivationStep2Param & param, ActivationStep2Result & result);
		
		/**
		 Completes previously started activation process and protects sensitive local information with
		 provided protection keys. Please check the documentation for SignatureUnlockKeys structure 
		 for details about constructing protection keys and for other related information.
		 
		 You have to provide at least keys.userPassword and keys.possessionUnlockKey to pass the method's
		 input validation. After the activation is complete, you can finally save session's state
		 into the persistent storage.
		 
		 WARNING: You have to save session's staate when the activation is completed!
		 
		 Returns EC_Ok,         if operation succeeded
                 EC_Encryption, if some internal encryption failed
                                if this error occurs, then the session resets its state
                 EC_WrongState, if called in wrong session's state
                 EC_WrongParam, if required parameter is missing
		 */
		ErrorCode completeActivation(const SignatureUnlockKeys & keys);
		
		
		// MARK: - Status -
		
		/**
		 The method decodes received status blob into ActivationStatus structure. You can call this method after successful
		 activation and obtain information about pairing between the client and server. You have to provide valid
		 possessionUnlockKey in the |keys| structure.
		 */
		ErrorCode decodeActivationStatus(const std::string & statusBlob, const SignatureUnlockKeys & keys, ActivationStatus & status);
		
		
		// MARK: - Data signing -
		
		/**
		 Converts key:value map into normalized data, suitable for data signing. The method is useful in cases where 
		 you want to sign parameters of GET request. You have to provide key-value map constructed from your GET parameters.
		 The result is normalized byte sequence, prepared for data signing. For POST requests it's recommended to sign
		 a whole POST body.
		 
		 Compatibility note
		 
		 This interface doesn't support multiple values for the same key. This is a known limitation, due to fact, that
		 std::map<> doesn't allow duplicit keys. The arrays in GET requests are so rare that I've decided to do not support
		 them. You can still implement your own data normalization, if this is your situation.
		 */
		static cc7::ByteArray prepareKeyValueMapForDataSigning(const std::map<std::string, std::string> & key_value_map);

		/**
         Calculates signature from given |request_data| structure. You have to provide all involved unlock keys 
		 in |keys| structure, required for desired |signature_factor|. For the |request_data.body| you can provide whole POST
		 body or you can prepare data with using 'prepareKeyValueMapForDataSigning' method. The |request_data.method|
		 parameter is the HTML method of the request (e.g. GET, POST, etc...). The |request_data.uri| parameter should be 
		 relative URI. Check the original PA2 documentation for details about signing the HTTP requests.
         
		 The result is stored to the |out_signature| structure and can be converted to a full value for
		 X-PowerAuth-Authorization header.
		 
         If you're going to sign request for a vault key retrieving, then you have to specifiy signature
         factor combined with SF_PrepareForVaultUnlock flag. Otherwise the subsequent vault unlock
         operation will calculate wrong transport key (KEY_ENCRYPTION_VAULT_TRANSPORT) and you'll
         not be able to complete the operation.
		 
         WARNING
         
         You have to save session's state after the successful operation, due to internal counter change.
         If you don't save the state then you'll sooner or later loose synchronization with the server 
		 and your client will not be able to sign data anymore.
         
         Discussion about thread safety
         
         If your networking infrastructure allows simultaneous HTTP requests then it's recommended to
         guard this method with external locking. There's possible race condition when the internal signing counter
         is raised in persistent data structure. The Session doesn't provide locking internally.
         
         Returns EC_Ok,         if operation succeeded
                 EC_Encryption, if some cryptographic operation failed
                 EC_WrongState, if the session has no valid activation
                 EC_WrongParam, if some required parameter is missing
		 */
		ErrorCode signHTTPRequestData(const HTTPRequestData & request_data,
									  const SignatureUnlockKeys & keys, SignatureFactor signature_factor,
									  HTTPRequestDataSignature & out_signature);
		
		/**
		 Returns name of authorization header. The value is constant and is equal to "X-PowerAuth-Authorization".
		 You can calculate appropriate value with using signHTTPRequest() method.
		 */
		const std::string & httpAuthHeaderName() const;
		
		
		// MARK: - Signature keys management -
		
		/**
         Changes user's password. You have to save session's state to keep this change for later.
         
         The method doesn't perform old password validation and therefore, if the wrong password is provided,
         then the knowledge key will be permanently lost. Before calling this method, you have to validate 
		 old password by calling some server's endpoint, which requires at least knowledge factor for completion.
         
         So, the typical flow for password change has a following steps:
         
             1. ask user for an old password
             2. send HTTP request, signed with knowledge factor, use an old password for key unlock
                  - if operation fails, then you can repeat step 1 or exit the flow
             3. ask user for a new password as usual (e.g. ask for passwd for twice, compare both,
                check minimum length, entropy, etc...)
             4. call `changeUserPassword` with old and new password
             5. save session's state
         
         WARNING
         
         All this, is just a preliminary proposal functionality and is not covered by PA2 specification.
         The behavior or a whole flow of password changing may be a subject of change in the future.
		 
         Returns EC_Ok,         if operation succeeded
                 EC_Encryption, if underlying cryptographic operation did fail or
                                if you provided too short passwords.
                 EC_WrongState, if the session has no valid activation
		 */
		ErrorCode changeUserPassword(const cc7::ByteRange & old_password, const cc7::ByteRange & new_password);
		
		/**
		 Adds a key for biometry factor. You have to provide encrypted vault key |c_vault_key| and
		 |keys| structure where the valid possessionUnlockKey is set. The |keys| structure also must
		 contain a new biometryUnlockKey, which will be used for a protection of the newly created
		 biometry signature key. You should always save session's state after this operation, whether 
		 it ends with error or not.
		 
		 Discussion
		 
		 The adding a new key for biometry factor is a quite complex task. At first, you need to ask server
		 for a vault key and sign this HTTP request with using SF_PrepareForVaultUnlock flag in combination
		 with other required factors. The flag guarantees that the internal counter will be correctly raised
		 and next subsequent operation for vault key decryption will finish correctly.
		 
		 If you don't receive response from the server then it's OK to leave the session as is. The session's
		 counter is probably at the same value as server's or slightly ahead and therefore everything should 
		 later work correctly. The session then only display a warning to the debug console about the previous
		 pending vault unlock operation.
		 
		 Returns EC_Ok,         if operation succeeded
				 EC_Encryption, if general encryption error occurs
				 EC_WrongState, if the session has no valid activation or
								if you did not sign previous http request with SF_PrepareForVaultUnlock flag
				 EC_WrongParam, if some required parameter is missing

		 */
		ErrorCode addBiometryFactor(const std::string & c_vault_key, const SignatureUnlockKeys & keys);
		
		/**
		 Checks if the key for the biometry related factor exists for the session, returns the value as a reference.
		 
		 Returns EC_Ok,         if operation succeeded
				 EC_WrongState,	if the session has no valid activation
		 */
		ErrorCode hasBiometryFactor(bool & hasBiometryFactor);
		
		/**
		 Removes existing key for biometric signatures from the session. You have to save state of the session 
		 after the operation.
		 
		 Returns EC_Ok,         if operation succeeded
				 EC_WrongState, if the session has no valid activation
		 */
		ErrorCode removeBiometryFactor();
		
		
		// MARK: - Vault operations -
		
		/**
		 Calculates a cryptographic key, derived from encrypted vault key, received from the server. The method 
		 is useful for situations, where the application needs to protect locally stored data with a cryptographic
		 key, which is normally not present on the device and must be acquired from the server at first.
		 
		 You have to provide encrypted |c_vault_key| and |keys| structure with a valid possessionUnlockKey.
		 The |key_index| is a parameter to the key derivation function and if the operation succeeds then the
		 derived key is stored to the |out_key| byte array. You should always save session's state after this 
		 operation, whether it ends with error or not.
		 
		 Discussion
		 
		 You should NOT store the produced key to the permanent storage. If you store the key to the filesystem
		 or even to the keychain, then the whole server based protection scheme will have no effect. You can, of
		 course, keep the key in the volatile memory, if the application needs use the key for longer period.
		 
		 Note that just like the "addBiometryFactor", you have to properly sign HTTP request with using
		 SF_PrepareForVaultUnlock flag, otherwise the operation will fail.


 		 Returns EC_Ok,         if operation succeeded
				 EC_Encryption, if general encryption error occurs
				 EC_WrongState, if the session has no valid activation or
								if you did not sign previous http request with SF_PrepareForVaultUnlock flag
				 EC_WrongParam, if some required parameter is missing

		 */
		ErrorCode deriveCryptographicKeyFromVaultKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys,
													 cc7::U64 key_index, cc7::ByteArray & out_key);
		
		/**
		 Computes a ECDSA-SHA256 signature of given |data| with using device's private key. You have to provide
		 encrypted |c_vault_key| and |keys| structure with a valid possessionUnlockKey.
		 
		 Discussion
		 
		 The session's state contains device private key but is encrypted with vault key, which is normally not
		 available on the device. Just like other vault related operations, you have to properly sign HTTP request 
		 with using SF_PrepareForVaultUnlock flag, otherwise the operation will fail.

 		 Returns EC_Ok,         if operation succeeded
				 EC_Encryption, if general encryption error occurs
				 EC_WrongState, if the session has no valid activation or
								if you did not sign previous http request with SF_PrepareForVaultUnlock flag
				 EC_WrongParam, if some required parameter is missing
		 */
		ErrorCode signDataWithDevicePrivateKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys,
											   const cc7::ByteRange & data, cc7::ByteArray & out_signature);
		
	private:

		/**
		 Decrypts vault key received from the server. The method is private and is used internally for vault 
		 unlocking. The keys.possessionUnlockKey is required.
		 */
		ErrorCode decryptVaultKey(const std::string & c_vault_key, const SignatureUnlockKeys & keys,
								  cc7::ByteArray & out_key);
		
	public:
		
		// MARK: - External encryption key -
		
		/**
		 Returns true if EEK (external encryption key) is set.
		 */
		bool hasExternalEncryptionKey() const;
		
		/**
		 Sets a known external encryption key to the internal SessionSetup structure. This method 
		 is useful, when the Session is using EEK, but the key is not known yet. You can restore 
		 the session without the EEK and use it for a very limited set of operations, like the status 
		 decode. The data signing will also work correctly, but only for a knowledge factor, which 
		 is by design not protected with EEK.
		 
		 Returns EC_Ok			if operation succeeded
				 EC_WrongParam	if key is already set and new EEK is different, or
								if provided EEK has invalid length.
				 EC_WrongState	if you're setting key to activated session which doesn't use EEK
		 */
		ErrorCode setExternalEncryptionKey(const cc7::ByteRange & eek);
		
		/**
		 Adds a new external encryption key permanently to the activated Session and to the internal 
		 SessionSetup structure. The method is different than 'setExternalEncryptionKey' and is useful 
		 for scenarios, when you need to add the EEK additionally, after the activation.
		 
		 You have to save state of the session after the operation.
		 
		 Returns EC_Ok			if operation succeeded and session is using EEK for all future operations
				 EC_WrongParam	if the EEK has wrong size
				 EC_WrongState	if session has no valid activation, or
								if the EEK is already set.
				 EC_Encryption	if internal cryptographic operation failed
		 */
		ErrorCode addExternalEncryptionKey(const cc7::ByteArray & eek);
		
		/**
		 Removes existing external encryption key from the activated Session. The method removes EEK permanently
		 and clears internal EEK usage flag from the persistent data. The session has to be activated and EEK
		 must be set at the time of call (e.g. 'hasExternalEncryptionKey' returns true).
	
		 You have to save state of the session after the operation.
		 
		 Returns EC_Ok			if operation succeeded and session doesn't use EEK anymore
				 EC_WrongState	if session has no valid activation, or
								if session has no EEK set
				 EC_Encryption	if internal cryptographic operation failed
		 */
		ErrorCode removeExternalEncryptionKey();
		
		
		// MARK: - End-To-End Encryption -
		
		/**
		 Creates a new instace of Encryptor class initialized for nonpersonalized End-To-End Encryption.
		 The nonpersonalized mode of E2EE is available after the correct Session object initialization,
		 so you can basically use the method anytime during the object's lifetime. The |session_index| 
		 range must point to 16 bytes long sequence of bytes. If your application doesn't have mechanism
		 for session index creation, then you can use generateSignatureUnlockKey() for this purpose.
		 
		 Note that the method doesn't change persistent state of the Session, so you don't need to
		 serialize its state after the call.
		 
		 Returns a tuple containing error code and newly created instance of Encryptor. The returned
		 pointer is valid only when the operation succeeds.
		 
		 ErrorCode value is:
					EC_Ok		  if operation succeeded. The returned pointer is valid.
					EC_WrongState if session has no valid setup. The returned pointer is nullptr.
					EC_WrongParam if session_index has wrong size, or
								  if session_index is filled with zeros, or
								  The returned pointer is nullptr.
					EC_Encryption if internal cryptographic operation failed. The returned pointer is nullptr.
		 */
		std::tuple<ErrorCode, Encryptor*> createNonpersonalizedEncryptor(const cc7::ByteRange & session_index);
		
		/**
		 Creates a new instace of Encryptor class initialized for personalized End-To-End Encryption.
		 The personalized mode of E2EE is available only when the session contains valid activation.
		 The |session_index| range has to be 16 bytes long sequence of bytes. If your application doesn't
		 have mechanism for session index creation, then you can use generateSignatureUnlockKey() for
		 this purpose.
		 The provided |keys| structure must contain valid unlock key for a possession factor.
		 
		 Note that the method doesn't change persistent state of the Session, so you don't need to
		 serialize its state after the call.
		 
		 Returns a tuple containing error code and newly created instance of Encryptor. The returned
		 pointer is valid only when the operation succeeds.
		 
		 ErrorCode value is:
					EC_Ok			if operation succeeded. The returned pointer is valid.
					EC_WrongState	if session has no valid activation. The returned pointer is nullptr.
					EC_WrongParam	if session_index has wrong size, or
									if session_index is filled with zeros, or
									if possession unlock key is missing.
									The returned pointer is nullptr.
					EC_Encryption	if internal cryptographic operation failed. The returned pointer is nullptr.
		 */
		std::tuple<ErrorCode, Encryptor*> createPersonalizedEncryptor(const cc7::ByteRange & session_index,
																	  const SignatureUnlockKeys & keys);
		
		
		// MARK: - Utilities for generic keys -
		
		/**
		 Returns normalized key suitable for a signagure keys protection. The key is computed from
		 provided data with using one-way hash function (SHA256)
		 
		 Discussion
		 
		 This method is useful for situations, where you have to prepare key for possession factor,
		 but your source data is not normalized. For example, WI-FI or UDID doesn't fit to
		 requirements for cryptographic key and this function helps derive the key from an input data.
		 */
		static cc7::ByteArray normalizeSignatureUnlockKeyFromData(const cc7::ByteRange & any_data);
		
		/**
		 Returns new normalized key usable for a signature keys protection.
		 
		 Discussion
		 
		 The method is useful for situations, whenever you need to create a new key which will be
		 protected with another, external factor. The best example is when a "biometry" factor is
		 involved in the signatures. For this situation, you can generate a new key and save it
		 to the storage, protected by the biometric factor.
		 
		 Internally, method only generates 16 bytes long random data and therefore is also suitable
		 for all other situations, when the generated random key is required.
		 */
		static cc7::ByteArray generateSignatureUnlockKey();

		
	public:
		
		/**
		 The State enumeration is an internal state of the session.
		 */
		enum State
		{
			SS_Invalid, SS_Empty, SS_Activation1, SS_Activation2, SS_Activated
		};
		
	private:
		
		// MARK: - Private section -
		
		/**
		 Current session's state.
		 */
		State _state;
				
		/**
		 Private copy of SessionSetup structure.
		 */
		SessionSetup _setup;

		/**
		 Pointer to private persistent data structure. The pointer is valid only
		 after the correctly finished activation of the session.
		 */
		protocol::PersistentData * _pd;
		
		/**
		 Pointer to private activation data structure. The pointer is valid only
		 during the activation process.
		 */
		protocol::ActivationData * _ad;
		
		/**
		 Commits a |new_pd| and |new_state| as a new valid session state.
		 Check documentation in method's implementation for details.
		 */
		void commitNewPersistentState(protocol::PersistentData * new_pd, State new_state);
		
		/**
		 Changes internal state to a new one. If code is compiled with DEBUG build flags
		 then dumps this change in human readable format to the debug console.
		 */
		void changeState(State new_state);
		
		/**
		 Returns non-null pointer to ByteArray with EEK if session works with EEK.
		 */
		const cc7::ByteArray * eek() const;
		
	};
	
} // io::getlime::powerAuth
} // io::getlime
} // io
