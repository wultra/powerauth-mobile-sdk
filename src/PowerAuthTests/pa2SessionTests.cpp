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

#include <cc7tests/CC7Tests.h>
#include <cc7tests/detail/StringUtils.h>

#include <cc7/CC7.h>

#include "crypto/CryptoUtils.h"
#include "protocol/ProtocolUtils.h"
#include "protocol/Constants.h"
#include "utils/DataReader.h"

#include <PowerAuth/Session.h>
#include <PowerAuth/ECIES.h>
#include <map>

using namespace cc7;
using namespace cc7::tests;
using namespace io::getlime::powerAuth;

namespace io
{
namespace getlime
{
namespace powerAuthTests
{
	typedef std::map<std::string, std::string> StringMap;
	
	class pa2SessionTests : public UnitTest
	{
	public:
		
		pa2SessionTests()
		{
			CC7_REGISTER_TEST_METHOD(testKeyValueMapNormalization);
			CC7_REGISTER_TEST_METHOD(testBeforeActivation);
			CC7_REGISTER_TEST_METHOD(testActivationWithoutEEK);
			CC7_REGISTER_TEST_METHOD(testActivationWithEEKUsingSetup);
			CC7_REGISTER_TEST_METHOD(testActivationWithEEKUsingSetter);
			CC7_REGISTER_TEST_METHOD(testServerSignedData);
			CC7_REGISTER_TEST_METHOD(testOldDataMigration);
			CC7_REGISTER_TEST_METHOD(testPersistentDataUpgradeFromV2ToV5);
			CC7_REGISTER_TEST_METHOD(testPersistentDataUpgradeFromV3ToV5);
			CC7_REGISTER_TEST_METHOD(testPersistentDataUpgradeFromV4ToV5);
		}
		
		EC_KEY *	_masterServerPrivateKey;
		
		std::string _masterServerPublicKeyStr;
		SessionSetup _setup;
		
		std::string	_activation_code;
		std::string _activation_id;
		
		std::string _recovery_code;
		std::string _recovery_puk;

		const std::string PA_VER = "3.1";
		
		void setUp() override
		{
			_masterServerPrivateKey = crypto::ECC_GenerateKeyPair();
			ccstAssertNotNull(_masterServerPrivateKey);
			_masterServerPublicKeyStr = crypto::ECC_ExportPublicKeyToB64(_masterServerPrivateKey);
			
			_setup.applicationKey			= "MDEyMzQ1Njc4OUFCQ0RFRg==";
			_setup.applicationSecret		= "QUJDREVGMDEyMzQ1Njc4OQ==";
			_setup.masterServerPublicKey	= _masterServerPublicKeyStr;
			_setup.sessionIdentifier		= 99;

			// prepare some other constants
			_activation_code	= "VVVVV-VVVVV-VVVVV-VTFVA";
			_activation_id		= "ED7BA470-8E54-465E-825C-99712043E01C";
			
			_recovery_code		= "55555-55555-55555-55YMA";
			_recovery_puk		= "0123456789";
		}
		
		void tearDown() override
		{
			EC_KEY_free(_masterServerPrivateKey);
			_masterServerPrivateKey = nullptr;
		}
		
		// unit tests
		
		void testKeyValueMapNormalization()
		{
			std::map<std::string, std::string> map;
			map["zingly"] = "is da best";
			map["420"] = "is equal to 10*42";
			map["hello"] = "world";
			map["hell0"] = "w0rld";
			
			Session ss(_setup);
			const char * expected = "420=is+equal+to+10*42&hell0=w0rld&hello=world&zingly=is+da+best";
			cc7::ByteArray normalized_data = ss.prepareKeyValueMapForDataSigning(map);
			cc7::ByteArray expected_data = cc7::MakeRange(expected);
			
			bool result = normalized_data == expected_data;
			if (!result) {
				ccstAssertTrue(result, "key-value normalization failed.");
				CC7_LOG("Expected: %s", expected);
				CC7_LOG("Produced: %s", cc7::CopyToString(normalized_data).c_str());
			}
		}
		
		void compareSetup(const SessionSetup * ss, const char * message)
		{
			if (!ss) {
				return;
			}
			ccstMessage("Testing SessionSetup : %s", message);
			ccstAssertEqual(ss->applicationKey,			_setup.applicationKey);
			ccstAssertEqual(ss->applicationSecret,		_setup.applicationSecret);
			ccstAssertEqual(ss->masterServerPublicKey,	_setup.masterServerPublicKey);
			ccstAssertEqual(ss->sessionIdentifier,		_setup.sessionIdentifier);
		}
		
		void testBeforeActivation()
		{
			// valid setup
			{
				Session s1(_setup);
				ErrorCode ec;
				// initial state, nothing is allowed
				ccstAssertNotNull(s1.sessionSetup());
				ccstAssertTrue(s1.hasValidSetup());
				ccstAssertTrue(s1.canStartActivation());
				ccstAssertFalse(s1.hasPendingActivation());
				ccstAssertFalse(s1.hasValidActivation());
				
				cc7::ByteArray state_empty1 = s1.saveSessionState();
				ccstAssertFalse(state_empty1.empty());	// it's empty, but still has some data
				// Check empty state after reset
				s1.resetSession();
				ccstAssertNotNull(s1.sessionSetup());
				ccstAssertTrue(s1.hasValidSetup());
				ccstAssertTrue(s1.canStartActivation());
				ccstAssertFalse(s1.hasPendingActivation());
				ccstAssertFalse(s1.hasValidActivation());
				ccstMessage("Empty data: %s", state_empty1.hexString().c_str());
				// Deserialize empty state. Must lead to the same state
				ec = s1.loadSessionState(state_empty1);
				ccstAssertEqual(ec, EC_Ok);
				ccstAssertNotNull(s1.sessionSetup());
				ccstAssertTrue(s1.hasValidSetup());
				ccstAssertTrue(s1.canStartActivation());
				ccstAssertFalse(s1.hasPendingActivation());
				ccstAssertFalse(s1.hasValidActivation());
			}
			// invalid setup
			{
				SessionSetup wrong_setup;
				Session s2(wrong_setup);
				ccstAssertNull(s2.sessionSetup());
				ccstAssertFalse(s2.hasValidSetup());
				ccstAssertFalse(s2.canStartActivation());
				ccstAssertFalse(s2.hasPendingActivation());
				ccstAssertFalse(s2.hasValidActivation());

			}
			// Other initial tests for empty session
			{
				Session s3(_setup);
				bool bf = true;
				ccstAssertEqual(EC_WrongState, s3.hasBiometryFactor(bf));
				ccstAssertFalse(bf);
			}
		}
		
		void testActivationWithoutEEK()
		{
			testActivation(nullptr, false, "Without EEK");
		}
		
		
		void testActivationWithEEKUsingSetup()
		{
			cc7::ByteArray eek1 = Session::generateSignatureUnlockKey();
			testActivation(&eek1, false, "EEK Setup");
		}

		void testActivationWithEEKUsingSetter()
		{
			cc7::ByteArray eek1 = Session::generateSignatureUnlockKey();
			testActivation(&eek1, true, "EEK Setter");
		}

		void testActivation(const cc7::ByteArray * eek, bool eek_setter, const char * eek_msg)
		{
			ErrorCode ec;
			if (eek) {
				if (!eek_setter) {
					_setup.externalEncryptionKey = *eek;
				} else {
					_setup.externalEncryptionKey.clear();
				}
			} else {
				_setup.externalEncryptionKey.clear();
			}
			Session s1(_setup);
			
			if (eek) {
				if (!eek_setter) {
					ccstAssertTrue(s1.sessionSetup()->externalEncryptionKey == *eek);
				}
			} else {
				ccstAssertTrue(s1.sessionSetup()->externalEncryptionKey.size() == 0);
			}
			
			// The 'break_in_step' value controls step in which we'll reset the session
			// during the activation. For example:
			//	1 - we'll break activation after the startActivation() is called
			//	0 - means that the whole sequence will be executed
			
			for (int break_in_step = 0; break_in_step <= 4; break_in_step++)
			{
				const char * eek_msg = eek ? "With EEK" : "Wout EEK";
				if (break_in_step > 0) {
					ccstMessage("%s || Let's break the activation in step No. %d", eek_msg, break_in_step);
				} else {
					ccstMessage("%s || Let's don't break the activation", eek_msg);
				}
				
				const bool USE_RECOVERY_CODE = break_in_step == 4;
			
				EC_KEY * serverPrivateKey = nullptr;
				EC_KEY * devicePublicKey  = nullptr;

				s1.resetSession();
				
				// SERVER STEP 1,
				//  ...prepare short-id, otp & activation signature
				ActivationStep1Param param1;
				{
					param1.activationCode		= _activation_code;
					param1.activationSignature	= T_calculateActivationSignature(_activation_code);
				}
				// CLIENT STEP 1
				//  ...process param1 & produce result1
				ActivationStep1Result result1;
				{
					ec = s1.startActivation(param1, result1);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(s1.hasValidSetup());
					ccstAssertFalse(s1.canStartActivation());
					ccstAssertTrue(s1.hasPendingActivation());
					ccstAssertFalse(s1.hasValidActivation());
					ccstAssertTrue(s1.activationIdentifier().empty());
					ccstAssertTrue(s1.activationFingerprint().empty());
					
					if (break_in_step == 1) {
						s1.resetSession();
						ccstAssertTrue(s1.hasValidSetup());
						ccstAssertTrue(s1.canStartActivation());
						ccstAssertFalse(s1.hasPendingActivation());
						ccstAssertFalse(s1.hasValidActivation());
						ccstAssertTrue(s1.activationIdentifier().empty());
						ccstAssertTrue(s1.activationFingerprint().empty());
						continue;
					}
					
					// Test other methods and call them in wrong state
					ActivationStep1Param fake_param;
					ActivationStep1Result fake_result;
					ec = s1.startActivation(fake_param, fake_result);
					ccstAssertEqual(ec, EC_WrongState);
					SignatureUnlockKeys fake_keys;
					ec = s1.completeActivation(fake_keys);
					ccstAssertEqual(ec, EC_WrongState);
					HTTPRequestDataSignature fake_signature;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::ByteArray(), std::string(), std::string()), fake_keys, SF_Biometry, fake_signature);
					ccstAssertEqual(ec, EC_WrongState);
				}
				// SERVER STEP 2
				//  ... validate result1 & prepare param2
				ActivationStep2Param param2;
				std::string ACTIVATION_FINGERPRINT;
				cc7::ByteArray MASTER_SHARED_SECRET;
				cc7::ByteArray CTR_DATA;
				{
					// Let's make response for client
					serverPrivateKey = crypto::ECC_GenerateKeyPair();
					
					cc7::ByteArray KEY_DEVICE_PUBLIC	= cc7::FromBase64String(result1.devicePublicKey);
					ccstAssertTrue(KEY_DEVICE_PUBLIC.size() > 0);
					devicePublicKey						= crypto::ECC_ImportPublicKey(nullptr, KEY_DEVICE_PUBLIC);
					ccstAssertNotNull(devicePublicKey);
					
                    // Prepare the response data
					cc7::ByteArray serverPublicKey		= crypto::ECC_ExportPublicKey(serverPrivateKey);
					CTR_DATA							= crypto::GetRandomData(16);

					MASTER_SHARED_SECRET				= protocol::ReduceSharedSecret(crypto::ECDH_SharedSecret(devicePublicKey, serverPrivateKey));
					ccstAssertTrue(MASTER_SHARED_SECRET.size() == 16);
					
					param2.activationId				= _activation_id;
					param2.ctrData					= CTR_DATA.base64String();
					param2.serverPublicKey          = serverPublicKey.base64String();
					if (USE_RECOVERY_CODE) {
						// Store recovery code
						param2.activationRecovery.recoveryCode = _recovery_code;
						param2.activationRecovery.puk = _recovery_puk;
					}
					
					// calculate hkKEY_DEVICE_PUBLIC on dummy server's side
					auto fingerprint_data = crypto::ECC_ExportPublicKeyToNormalizedForm(devicePublicKey);
					fingerprint_data.append(cc7::MakeRange(_activation_id));
					fingerprint_data.append(crypto::ECC_ExportPublicKeyToNormalizedForm(crypto::ECC_ImportPublicKey(nullptr, serverPublicKey)));
					cc7::ByteArray hash = crypto::SHA256(fingerprint_data);
					size_t off    = hash.size() - 4;
					uint32_t v = ((hash[off] & 0x7f) << 24) | (hash[off+1] << 16) | (hash[off+2] << 8) | hash[off+3];
					v = v % 100000000;
					char buffer[32];
					sprintf(buffer, "%08d", v);
					ACTIVATION_FINGERPRINT = buffer;
					
					ccstMessage("Shared secret: %s", MASTER_SHARED_SECRET.hexString().c_str());
				}
				// CLIENT STEP 2
				//  ...client must process param2 & produce result2
				ActivationStep2Result result2;
				{
					ec = s1.validateActivationResponse(param2, result2);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(ACTIVATION_FINGERPRINT, result2.activationFingerprint);
					
					ccstAssertTrue(s1.hasValidSetup());
					ccstAssertFalse(s1.canStartActivation());
					ccstAssertTrue(s1.hasPendingActivation());
					ccstAssertFalse(s1.hasValidActivation());
					ccstAssertEqual(_activation_id, s1.activationIdentifier());
					ccstAssertEqual(s1.activationFingerprint(), ACTIVATION_FINGERPRINT);
					
					if (break_in_step == 2) {
						s1.resetSession();
						ccstAssertTrue(s1.hasValidSetup());
						ccstAssertTrue(s1.canStartActivation());
						ccstAssertFalse(s1.hasPendingActivation());
						ccstAssertFalse(s1.hasValidActivation());
						continue;
					}
					
					// Test for calling methods in wrong states
					ActivationStep2Param fake_param;
					ActivationStep2Result fake_result;
					ec = s1.startActivation(param1, result1);
					ccstAssertEqual(ec, EC_WrongState);
					SignatureUnlockKeys fake_keys;
					ec = s1.validateActivationResponse(fake_param, fake_result);
					ccstAssertEqual(ec, EC_WrongState);
					HTTPRequestDataSignature foo_fighters;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::ByteArray(), std::string(), std::string()), fake_keys, SF_Biometry, foo_fighters);
					ccstAssertEqual(ec, EC_WrongState);
				}
				// CLIENT STEP 3
				// ... client has to generate protection keys & provide user's passowrd
				cc7::ByteArray biometryUnlock   = Session::generateSignatureUnlockKey();
				cc7::ByteArray possessionUnlock = Session::generateSignatureUnlockKey();
				std::string password     = "password";
				std::string new_password = "nbusr123";	// Yeah! That's very famous pwd in Slovakia :D
				cc7::ByteArray new_biometryUnlock = Session::generateSignatureUnlockKey();
				{
					if (eek) {
						if (eek_setter) {
							// EEK is not set yet and now it's the last time to set it.
							ec = s1.setExternalEncryptionKey(*eek);
							ccstAssertEqual(ec, EC_Ok);
							ccstAssertTrue(s1.sessionSetup()->externalEncryptionKey == *eek);
						}
						// Now we can test if setter works as expected.
						// Setting the same key is allowed
						ec = s1.setExternalEncryptionKey(*eek);
						ccstAssertEqual(ec, EC_Ok);
						// Setting different key is not allowed
						ec = s1.setExternalEncryptionKey(protocol::ZERO_IV);
						ccstAssertEqual(ec, EC_WrongParam);
						// Setting wrong key is also not allowed
						ec = s1.setExternalEncryptionKey(cc7::ByteArray({0,1,2,3,}));
						ccstAssertEqual(ec, EC_WrongParam);
					} else {
						// EEK is not used, but we can test if setting wrong key doesn't pass in this state
						ec = s1.setExternalEncryptionKey(cc7::ByteArray({0,1,2,3,}));
						ccstAssertEqual(ec, EC_WrongParam);
					}
					SignatureUnlockKeys lock_keys;
					lock_keys.userPassword = cc7::MakeRange(password);
					lock_keys.biometryUnlockKey = biometryUnlock;
					lock_keys.possessionUnlockKey = possessionUnlock;
					
					ec = s1.completeActivation(lock_keys);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(s1.activationIdentifier(), _activation_id);
					ccstAssertEqual(s1.activationFingerprint(), ACTIVATION_FINGERPRINT);
					ccstAssertTrue(s1.hasValidSetup());
					ccstAssertFalse(s1.canStartActivation());
					ccstAssertFalse(s1.hasPendingActivation());
					ccstAssertTrue(s1.hasValidActivation());
					
					if (break_in_step == 3) {
						s1.resetSession();
						ccstAssertTrue(s1.hasValidSetup());
						ccstAssertEqual(s1.activationIdentifier(), "");
						ccstAssertTrue(s1.canStartActivation());
						ccstAssertFalse(s1.hasPendingActivation());
						ccstAssertFalse(s1.hasValidActivation());
						continue;
					}

					// Test for calling methods in wrong states
					ActivationStep2Param fake_param;
					ActivationStep2Result fake_result;
					SignatureUnlockKeys fake_keys;
					ec = s1.startActivation(param1, result1);
					ccstAssertEqual(ec, EC_WrongState);
					ec = s1.validateActivationResponse(fake_param, fake_result);
					ccstAssertEqual(ec, EC_WrongState);
					ec = s1.completeActivation(fake_keys);
					ccstAssertEqual(ec, EC_WrongState);
				}
				
				// Now we have fully activated session, let's try to serialize & deserialize
				cc7::ByteArray state_active1 = s1.saveSessionState();
				ccstAssertFalse(state_active1.empty());
				{
					// Reset & Restore
					s1.resetSession();
					ec = s1.loadSessionState(state_active1);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(s1.activationIdentifier(), _activation_id);
					ccstAssertTrue(s1.hasValidSetup());
					ccstAssertFalse(s1.canStartActivation());
					ccstAssertFalse(s1.hasPendingActivation());
					ccstAssertTrue(s1.hasValidActivation());
					// Compare whether the fingerprint is still correct
					ccstAssertEqual(s1.activationFingerprint(), ACTIVATION_FINGERPRINT);
					// Validate existence of recovery data
					ccstAssertTrue(s1.hasActivationRecoveryData() == USE_RECOVERY_CODE);
				}
				// Signature test #1
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.biometryUnlockKey   = biometryUnlock;
					keys.userPassword        = cc7::MakeRange(password);
					
					std::string sigHeader = s1.httpAuthHeaderName();
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::ByteRange(), "POST", "/user/login"), keys, SF_Possession_Knowledge_Biometry, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(sigHeader, "X-PowerAuth-Authorization");
					ccstAssertTrue(!sigValue.empty());

					StringMap parsedSignature = T_parseSignature(sigValue);
					ccstAssertEqual(parsedSignature["pa_activation_id"], _activation_id);
					ccstAssertEqual(parsedSignature["pa_application_key"], _setup.applicationKey);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					ccstAssertEqual(parsedSignature["pa_signature_type"], "possession_knowledge_biometry");
					ccstAssertEqual(parsedSignature["pa_version"], PA_VER);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::ByteRange(), "POST", "/user/login", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge_Biometry, 0, CTR_DATA, false);
					ccstAssertEqual(signature, our_signature);
				}
				
				// Save state, reset & reload
				cc7::ByteArray active_state2;
				{
					active_state2 = s1.saveSessionState();
					s1.resetSession();
					ec = s1.loadSessionState(active_state2);
					ccstAssertEqual(ec, EC_Ok);
				}
				
				// Change password
				{
					ec = s1.changeUserPassword(cc7::MakeRange(password), cc7::MakeRange(new_password));
					ccstAssertEqual(ec, EC_Ok);
				}
								
				// Signature test #2
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(new_password);
					
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("HELLO WORLD!!"), "POST", "/user/execute/me"), keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					
					StringMap parsedSignature = T_parseSignature(sigValue);
					ccstAssertEqual(parsedSignature["pa_activation_id"], _activation_id);
					ccstAssertEqual(parsedSignature["pa_application_key"], _setup.applicationKey);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					ccstAssertEqual(parsedSignature["pa_signature_type"], "possession_knowledge");
					ccstAssertEqual(parsedSignature["pa_version"], PA_VER);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("HELLO WORLD!!"), "POST", "/user/execute/me", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge, 1, CTR_DATA, false);
					// Must match
					ccstAssertEqual(signature, our_signature);
				}
				
				// Add / Remove EEK (1st test)
				if (eek) {
					// Remove EEK
					ec = s1.addExternalEncryptionKey(*eek);
					ccstAssertEqual(ec, EC_WrongState);
					ccstAssertTrue(s1.hasExternalEncryptionKey());
					// valid remove
					ec = s1.removeExternalEncryptionKey();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(s1.hasExternalEncryptionKey());
					ec = s1.removeExternalEncryptionKey();
					ccstAssertEqual(ec, EC_WrongState);
				} else {
					// Add EEK
					// Setting valid EEK, while session doesn't use the key must produce error.
					ec = s1.setExternalEncryptionKey(crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE));
					ccstAssertEqual(ec, EC_WrongState);
					// Test for adding invalid EEK
					ec = s1.addExternalEncryptionKey(crypto::GetRandomData(10));
					ccstAssertEqual(ec, EC_WrongParam);
					ccstAssertFalse(s1.hasExternalEncryptionKey());
					// valid add
					ec = s1.addExternalEncryptionKey(crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE));
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(s1.hasExternalEncryptionKey());
					ec = s1.addExternalEncryptionKey(crypto::GetRandomData(protocol::SIGNATURE_KEY_SIZE));
					ccstAssertEqual(ec, EC_WrongState);
				}
				
				// Signature test #3 ... should fail at final signature compare, because we're using old passwd
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(password);
					
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("My creativity ends here!"), "POST", "/hack.me/if-you-can"), keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					
					StringMap parsedSignature = T_parseSignature(sigValue);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("My creativity ends here!"), "POST", "/hack.me/if-you-can", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge, 2, CTR_DATA, false);
					// Signatures must not match.
					ccstAssertNotEqual(signature, our_signature);
				}
				
				// Signature test #4 ... yet another valid test, now use "offline" nonce.
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(new_password);
					
					HTTPRequestData requestData(cc7::MakeRange("My creativity ends here!"), "POST", "/hack.me/if-you-can", "Q2hhcm1pbmdOb25jZTEyMw==");
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(requestData, keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					ccstAssertEqual(requestData.offlineNonce, sigData.nonce);
					ccstAssertEqual(sigData.applicationKey, "offline");
					
					StringMap parsedSignature = T_parseSignature(sigValue);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("My creativity ends here!"), "POST", "/hack.me/if-you-can", MASTER_SHARED_SECRET, nonceB64, "offline", SF_Possession_Knowledge, 3, CTR_DATA, true);
					// Signatures must match.
					ccstAssertEqual(signature, our_signature);
				}
				
				// Add / Remove EEK (2nd test)
				if (eek) {
					// Add EEK
					ec = s1.addExternalEncryptionKey(crypto::GetRandomData(10));
					ccstAssertEqual(ec, EC_WrongParam);
					ccstAssertFalse(s1.hasExternalEncryptionKey());
					ec = s1.addExternalEncryptionKey(*eek);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(s1.hasExternalEncryptionKey());
					ec = s1.addExternalEncryptionKey(*eek);
					ccstAssertEqual(ec, EC_WrongState);
				} else {
					// Remove EEK
					ec = s1.addExternalEncryptionKey(*eek);
					ccstAssertEqual(ec, EC_WrongState);
					ccstAssertTrue(s1.hasExternalEncryptionKey());
					ec = s1.removeExternalEncryptionKey();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(s1.hasExternalEncryptionKey());
					ec = s1.removeExternalEncryptionKey();
					ccstAssertEqual(ec, EC_WrongState);
				}
				
				// Sign with possession, when EEK is used, but is not set yet
				if (eek && eek_setter) {
					auto state = s1.saveSessionState();
					ccstAssertTrue(state.size() > 0);
					// Try several attempts for calculating just possession, when EEK is not set.
					for (int attempt_count = 1; attempt_count <= 2; attempt_count++) {
						// Create a fresh new Session object
						Session s2(_setup);
						ec = s2.loadSessionState(state);
						ccstAssertEqual(ec, EC_Ok);
						ccstAssertFalse(s2.hasExternalEncryptionKey());
						
						SignatureUnlockKeys keys;
						keys.possessionUnlockKey = possessionUnlock;
						HTTPRequestDataSignature sigData;
						ec = s2.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("Must work!"), "POST", "/hack.me/if-you-can"), keys, SF_Possession, sigData);
						std::string sigValue = sigData.buildAuthHeaderValue();
						ccstAssertEqual(ec, EC_Ok);
						ccstAssertTrue(!sigValue.empty());
						
						StringMap parsedSignature = T_parseSignature(sigValue);
						std::string nonceB64 = parsedSignature["pa_nonce"];
						ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
						std::string signature = parsedSignature["pa_signature"];
						ccstAssertTrue(!signature.empty());
						std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("Must work!"), "POST", "/hack.me/if-you-can", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession, 3 + attempt_count, CTR_DATA, false);
						// Signatures must match.
						ccstAssertEqual(signature, our_signature);
						// Save state for next loop or for subsequent tests...
						state = s2.saveSessionState();
						ccstAssertTrue(state.size() > 0);
					}
					// Now, try to calculate 2FA, on yet another fresh Session object
					Session s3(_setup);
					ec = s3.loadSessionState(state);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(s3.hasExternalEncryptionKey());
					
					// Try to use 2FA when EEK is not set. Must fail.
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword = cc7::MakeRange(new_password);
					HTTPRequestDataSignature sigData;
					ec = s3.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("EEK must be set!"), "POST", "/hack.me/if-you-can"), keys, SF_Possession_Knowledge, sigData);
					ccstAssertEqual(ec, EC_Encryption);

					// Now set EEK and try again... Must pass!
					ec = s3.setExternalEncryptionKey(*eek);
					ccstAssertEqual(ec, EC_Ok);

					ec = s3.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("EEK must be set!"), "POST", "/hack.me/if-you-can"), keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					
					StringMap parsedSignature = T_parseSignature(sigValue);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("EEK must be set!"), "POST", "/hack.me/if-you-can", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge, 3 + 3, CTR_DATA, false);
					// Signatures must match.
					ccstAssertEqual(signature, our_signature);
				}
				
				// remove biometry factor
				{
					// check if BF exists
					bool bf;
					ccstAssertEqual(EC_Ok, s1.hasBiometryFactor(bf));
					ccstAssertTrue(bf);
					// remove
					ec = s1.removeBiometryFactor();
					ccstAssertEqual(ec, EC_Ok);
					// check the status again
					ccstAssertEqual(EC_Ok, s1.hasBiometryFactor(bf));
					ccstAssertFalse(bf);
					
					// 2nd. remove should pass. The implementation only prints a warning about removing empty key.
					ec = s1.removeBiometryFactor();
					ccstAssertEqual(ec, EC_Ok);

					// Try to use biometry factor
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.biometryUnlockKey   = biometryUnlock;

					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("My creativity ends here!"), "POST", "/hack.me/if-you-can"), keys, SF_Possession_Biometry, sigData);
					ccstAssertEqual(ec, EC_Encryption);
					
					// Check serialization without biometry key
					auto state_without_biometry = s1.saveSessionState();
					Session s2(_setup);
					ec = s2.loadSessionState(state_without_biometry);
					ccstAssertEqual(ec, EC_Ok);
				}
				// Vault test #1-A, getting vault key
				std::string cVaultKey;
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(new_password);
					
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("Getting vault key!"), "POST", "/vault/unlock"), keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					
					// Just to be sure, check if signature calculated with "prepare for vault" flag is still valid
					StringMap parsedSignature = T_parseSignature(sigValue);
					ccstAssertEqual(parsedSignature["pa_activation_id"], _activation_id);
					ccstAssertEqual(parsedSignature["pa_application_key"], _setup.applicationKey);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					ccstAssertEqual(parsedSignature["pa_signature_type"], "possession_knowledge");
					ccstAssertEqual(parsedSignature["pa_version"], PA_VER);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("Getting vault key!"), "POST", "/vault/unlock", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge, 4, CTR_DATA, false);
					// Must match
					ccstAssertEqual(signature, our_signature);
					
					cVaultKey = T_encryptedVaultKey(MASTER_SHARED_SECRET);
					ccstAssertTrue(!cVaultKey.empty());
				}
				// Vault test #1-B, adding biometry factor back again
				{
					bool bf;
					ccstAssertEqual(EC_Ok, s1.hasBiometryFactor(bf));
					ccstAssertFalse(bf);
					SignatureUnlockKeys keys;
					// No keys filled, should fail on missing params
					ec = s1.addBiometryFactor(cVaultKey, keys);
					ccstAssertEqual(ec, EC_WrongParam);
					// valid keys
					keys.possessionUnlockKey = possessionUnlock;
					keys.biometryUnlockKey = new_biometryUnlock;
					ec = s1.addBiometryFactor(cVaultKey, keys);
					ccstAssertEqual(ec, EC_Ok);
					// check BF flag again
					ccstAssertEqual(EC_Ok, s1.hasBiometryFactor(bf));
					ccstAssertTrue(bf);
				}
				// Vault test #1-C, try to use newly estabilished factor
				{
					// Try to use biometry factor
					SignatureUnlockKeys keys;
					keys.biometryUnlockKey   = new_biometryUnlock;
					
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("My creativity ends here!"), "DELETE", "/hack.me/if-you-can"), keys, SF_Biometry, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					
					StringMap parsedSignature = T_parseSignature(sigValue);
					ccstAssertEqual(parsedSignature["pa_activation_id"], _activation_id);
					ccstAssertEqual(parsedSignature["pa_application_key"], _setup.applicationKey);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					ccstAssertEqual(parsedSignature["pa_signature_type"], "biometry");
					ccstAssertEqual(parsedSignature["pa_version"], PA_VER);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("My creativity ends here!"), "DELETE", "/hack.me/if-you-can", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Biometry, 5, CTR_DATA, false);
					// Must match
					ccstAssertEqual(signature, our_signature);
				}
				// Vault test #2-A, get vault key
				{
					// get vault key
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(new_password);
					HTTPRequestDataSignature sig;
					// counter value should be #7
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("Getting vault key!"), "POST", "/vault/unlock"), keys, SF_Possession_Knowledge, sig);
					std::string sigValue = sig.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					// Just to be sure, check that calculated signature
					StringMap parsedSignature = T_parseSignature(sigValue);
					ccstAssertEqual(parsedSignature["pa_activation_id"], _activation_id);
					ccstAssertEqual(parsedSignature["pa_application_key"], _setup.applicationKey);
					std::string nonceB64 = parsedSignature["pa_nonce"];
					ccstAssertTrue(cc7::FromBase64String(nonceB64).size() == 16);
					ccstAssertEqual(parsedSignature["pa_signature_type"], "possession_knowledge");
					ccstAssertEqual(parsedSignature["pa_version"], PA_VER);
					std::string signature = parsedSignature["pa_signature"];
					ccstAssertTrue(!signature.empty());
					std::string our_signature = T_calculateSignatureForData(cc7::MakeRange("Getting vault key!"), "POST", "/vault/unlock", MASTER_SHARED_SECRET, nonceB64, _setup.applicationSecret, SF_Possession_Knowledge, 6, CTR_DATA, false);
					// Must match
					ccstAssertEqual(signature, our_signature);
					// get encrypted vault
					cVaultKey = T_encryptedVaultKey(MASTER_SHARED_SECRET);
				}
				// Vault test #2-B, signing data with private key
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					
					cc7::ByteArray signature;
					ec = s1.signDataWithDevicePrivateKey(cVaultKey, keys, cc7::MakeRange("Hello World!"), signature);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!signature.empty());
					// Validate signature...
					
					bool bResult = crypto::ECDSA_ValidateSignature(cc7::MakeRange("Hello World!"), signature, devicePublicKey);
					ccstAssertTrue(bResult);
				}
				// Vault test #3-A, get vault key
				{
					// get vault key
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					keys.userPassword        = cc7::MakeRange(new_password);
					
					// counter value should be #9
					HTTPRequestDataSignature sigData;
					ec = s1.signHTTPRequestData(HTTPRequestData(cc7::MakeRange("Getting vault key!"), "POST", "/vault/unlock"), keys, SF_Possession_Knowledge, sigData);
					std::string sigValue = sigData.buildAuthHeaderValue();
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!sigValue.empty());
					// encrypted vault key
					cVaultKey = T_encryptedVaultKey(MASTER_SHARED_SECRET);
				}
				// Vault test #3-B, derive custom cryptographic key from vault key.
				{
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					cc7::ByteArray derived_key;
					ec = s1.deriveCryptographicKeyFromVaultKey(cVaultKey, keys, 1977, derived_key);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertTrue(!derived_key.empty());
					
					cc7::ByteArray vault_key = protocol::DeriveSecretKey(MASTER_SHARED_SECRET, 2000);
					cc7::ByteArray expected_derived_key = protocol::DeriveSecretKey(vault_key, 1977);
					ccstAssertEqual(derived_key, expected_derived_key);
				}
				// Server signed data with personalized key
				{
					SignedData signedData;
					signedData.signingKey = SignedData::ECDSA_PersonalizedKey;
					signedData.data = cc7::MakeRange("This piece of text needs to be signed.");
					signedData.signature = T_calculateServerSignature(signedData.data, serverPrivateKey);
					// Verify...
					ec = s1.verifyServerSignedData(signedData);
					ccstAssertTrue(ec == EC_Ok);
					
					// modify data
					signedData.data.pop_back();
					ec = s1.verifyServerSignedData(signedData);
					ccstAssertTrue(ec == EC_Encryption);
					
					// use clear signature
					signedData.signature.clear();
					ec = s1.verifyServerSignedData(signedData);
					ccstAssertTrue(ec == EC_WrongParam);
				}
				// ECIES "application" scope
				{
					SignatureUnlockKeys foo;
					ECIESEncryptor encryptor;
					ec = s1.getEciesEncryptor(ECIES_ApplicationScope, foo, cc7::MakeRange("/pa/test"), encryptor);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(encryptor.sharedInfo1(), cc7::MakeRange("/pa/test"));
					ccstAssertEqual(encryptor.sharedInfo2(), crypto::SHA256(cc7::MakeRange(_setup.applicationSecret)));
					ccstAssertEqual(encryptor.publicKey(), cc7::FromBase64String(_setup.masterServerPublicKey));
					
					// Now try to encrypt data
					ECIESCryptogram request_enc;
					ec = encryptor.encryptRequest(cc7::MakeRange("Hello!"), request_enc);
					ccstAssertEqual(ec, EC_Ok);
					
					// ...and decrypt on "server" side
					ECIESCryptogram request_dec;
					ECIESDecryptor decryptor(crypto::ECC_ExportPrivateKey(_masterServerPrivateKey),
											 cc7::MakeRange("/pa/test"),
											 crypto::SHA256(cc7::MakeRange(_setup.applicationSecret)));
					cc7::ByteArray request_data;
					ec = decryptor.decryptRequest(request_enc, request_data);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(request_data, cc7::MakeRange("Hello!"));
				}
				// ECIES "activation" scope
				{					
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					ECIESEncryptor encryptor;
					ec = s1.getEciesEncryptor(ECIES_ActivationScope, keys, cc7::MakeRange("/pa/activation/test"), encryptor);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(encryptor.sharedInfo1(), cc7::MakeRange("/pa/activation/test"));
					ccstAssertEqual(encryptor.sharedInfo2(), crypto::HMAC_SHA256(cc7::MakeRange(_setup.applicationSecret), protocol::DeriveSecretKey(MASTER_SHARED_SECRET, 1000)));
					ccstAssertEqual(encryptor.publicKey(), crypto::ECC_ExportPublicKey(serverPrivateKey));
					
					// Now try to encrypt data
					ECIESCryptogram request_enc;
					ec = encryptor.encryptRequest(cc7::MakeRange("Plan9!"), request_enc);
					ccstAssertEqual(ec, EC_Ok);
					
					// ...and decrypt on "server" side
					ECIESCryptogram request_dec;
					ECIESDecryptor decryptor(crypto::ECC_ExportPrivateKey(serverPrivateKey),
											 cc7::MakeRange("/pa/activation/test"),
											 crypto::HMAC_SHA256(cc7::MakeRange(_setup.applicationSecret), protocol::DeriveSecretKey(MASTER_SHARED_SECRET, 1000)));
					cc7::ByteArray request_data;
					ec = decryptor.decryptRequest(request_enc, request_data);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertEqual(request_data, cc7::MakeRange("Plan9!"));
				}
				// Recovery codes
				if (USE_RECOVERY_CODE) {
					// Recovery data is available
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					RecoveryData recovery_data;
					ec = s1.getActivationRecoveryData(cVaultKey, keys, recovery_data);
					ccstAssertEqual(ec, EC_Ok);
					ccstAssertFalse(recovery_data.isEmpty());
					ccstAssertEqual(recovery_data.recoveryCode, _recovery_code);
					ccstAssertEqual(recovery_data.puk, _recovery_puk);
				} else {
					// Recovery data is not available
					SignatureUnlockKeys keys;
					keys.possessionUnlockKey = possessionUnlock;
					RecoveryData recovery_data;
					ec = s1.getActivationRecoveryData(cVaultKey, keys, recovery_data);
					ccstAssertEqual(ec, EC_WrongState);
					ccstAssertTrue(recovery_data.isEmpty());
				}
				
				// release keys, just for sure
				EC_KEY_free(serverPrivateKey);
				EC_KEY_free(devicePublicKey);
				
			} // for (int break_in_step...
		}
		
		void testServerSignedData()
		{
			Session s1(_setup);
			ErrorCode ec;
			
			SignedData signedData;
			signedData.signingKey = SignedData::ECDSA_MasterServerKey;
			signedData.data = cc7::MakeRange("This piece of text needs to be signed.");
			signedData.signature = T_calculateServerSignature(signedData.data);
			// Verify...
			ec = s1.verifyServerSignedData(signedData);
			ccstAssertTrue(ec == EC_Ok);

			// modify data
			signedData.data.pop_back();
			ec = s1.verifyServerSignedData(signedData);
			ccstAssertTrue(ec == EC_Encryption);
			
			// use clear signature
			signedData.signature.clear();
			ec = s1.verifyServerSignedData(signedData);
			ccstAssertTrue(ec == EC_WrongParam);
		}
		
		// DATA_MIGRATION_TAG
		void testOldDataMigration()
		{
            // Old format is no longer supported, so loading such data will lead to error.
            
			// constants
			std::string master_server_public_key  = "AuCDGp3fAHL695yWxCP6d+jZEzwZleOdmCU+qFIImjBs";
			//std::string master_server_private_key = "8fzrRXY+y+eH8+u6SbwxHWEvXMD4LGiW6oM8cgntOI8=";
			cc7::ByteArray MASTER_SHARED_SECRET = cc7::FromBase64String("u0fy4LqR0Ax/zjXbM7Ey3w==");
			
			// Keys used for lock the data in old library version
			cc7::ByteArray password               = cc7::MakeRange("password");
			cc7::ByteArray possessionUnlockKey    = cc7::MakeRange("possession_unlck");
			cc7::ByteArray biometryUnlockKey      = cc7::MakeRange("biometry_unlock_");

			SessionSetup oldSetup;
			oldSetup.applicationKey		= "MDEyMzQ1Njc4OUFCQ0RFRg==";
			oldSetup.applicationSecret	= "QUJDREVGMDEyMzQ1Njc4OQ==";
			oldSetup.masterServerPublicKey = master_server_public_key;
			
			Session s1(oldSetup);
			
			// Empty data
			auto empty_status = cc7::FromBase64String("UEFNMmn/");
			ErrorCode ec = s1.loadSessionState(empty_status);
			ccstAssertTrue(ec == EC_WrongParam);
			ccstAssertTrue(s1.canStartActivation());
			ccstAssertFalse(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			
			// Activated data
			auto activated_status = cc7::FromBase64String("UEFNMmEAG0ZVTEwtQlVULUZBS0UtQUNUSVZBVElPTi1JRAAAAAAAAAAAAAAAAAAQXEPXfgDuOCt"
														  "9eqObNFI0SgAAJxAAEPlopTXWLHC0P6W62CaofW4AEOpVVjyUvLZm8wC2nBnAau0AEGAsKs9Rh8"
														  "mZL1u+aQ3kdsgAECnthxOWjFD/t5nNGYM6NV0AIQL43xDyVNbn0Ef/nHof55qHGL2fsDhqPMuC1"
														  "oLe1MmEPwAwDeNQFrAcETbOjAr1OEkviQI8k9/NlURxmGHq/X4itDJuPlZ4PYeEUvAQmvWce+ZJ"
														  "AAdLRVkwMDAx/w==");
			ec = s1.loadSessionState(activated_status);
			ccstAssertTrue(ec == EC_WrongParam);
            ccstAssertTrue(s1.canStartActivation());
            ccstAssertFalse(s1.hasValidActivation());
            ccstAssertFalse(s1.hasPendingActivation());
            ccstAssertFalse(s1.hasExternalEncryptionKey());
		}
		
		void testPersistentDataUpgradeFromV2ToV5()
		{
			// constants
			std::string master_server_public_key  = "AuCDGp3fAHL695yWxCP6d+jZEzwZleOdmCU+qFIImjBs";
			
			SessionSetup oldSetup;
			oldSetup.applicationKey		= "MDEyMzQ1Njc4OUFCQ0RFRg==";
			oldSetup.applicationSecret	= "QUJDREVGMDEyMzQ1Njc4OQ==";
			oldSetup.masterServerPublicKey = master_server_public_key;
			
			Session s1(oldSetup);
			
			// v2 data, where counter = 522
			auto v2_data = cc7::FromBase64String("UEECUDMAAAAAAAACChtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAACcQEFxD134A7"
												 "jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwGrtEGAsKs9Rh8"
												 "mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+eahxi9n7A4ajz"
												 "LgtaC3tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQybj5WeD2HhFLw"
												 "EJr1nHvmSQAAAAA=");
			
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			auto ec = s1.loadSessionState(v2_data);
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V2);
			ccstAssertFalse(s1.canStartActivation());
			ccstAssertTrue(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			ccstAssertEqual(s1.activationIdentifier(), "FULL-BUT-FAKE-ACTIVATION-ID");
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			ccstAssertFalse(s1.hasActivationRecoveryData());

			ec = s1.startProtocolUpgrade();
			ccstAssertEqual(ec, EC_Ok);
			ccstAssertEqual(Version_V3, s1.pendingProtocolUpgradeVersion());
			
			// Apply protocol upgrade data
			ProtocolUpgradeData upgrade_data;
			upgrade_data.toV3.ctrData = crypto::GetRandomData(16).base64String();
			ec = s1.applyProtocolUpgradeData(upgrade_data);
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertEqual(Version_V3, s1.pendingProtocolUpgradeVersion());
			
			// Now finish the upgrade
			ec = s1.finishProtocolUpgrade();
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			
			// Try to save, reset & reload data
			cc7::ByteArray v5_data = s1.saveSessionState();
			s1.resetSession();
			
			ec = s1.loadSessionState(v5_data);
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			
			// Try low level function. We have to test whether the counter has been
			// ignored and not moved to the ctr_byte.
			protocol::PersistentData pd;
			utils::DataReader data_reader(v5_data);
			data_reader.openVersion('P', 'A');	// Open version
			data_reader.skipBytes(1);			// Skip flag byte
			
			auto b_result = protocol::DeserializePersistentData(pd, data_reader);
			ccstAssertTrue(b_result);
			ccstAssertEqual(pd.flags.hasSignatureCounterByte, 0);
		}
		
		void testPersistentDataUpgradeFromV3ToV5()
		{
			// constants
			std::string master_server_public_key  = "AuCDGp3fAHL695yWxCP6d+jZEzwZleOdmCU+qFIImjBs";
			
			SessionSetup oldSetup;
			oldSetup.applicationKey		= "MDEyMzQ1Njc4OUFCQ0RFRg==";
			oldSetup.applicationSecret	= "QUJDREVGMDEyMzQ1Njc4OQ==";
			oldSetup.masterServerPublicKey = master_server_public_key;
			
			Session s1(oldSetup);
			
			auto v3_data = cc7::FromBase64String("UEECUDQQcXKzF7KLEfVzcb6F7dQ2jhtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAACcQEFx"
												 "D134A7jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwGrtEGAsKs9Rh8"
												 "mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+eahxi9n7A4ajzLgtaC3"
												 "tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQybj5WeD2HhFLwEJr1nHvmSQAA"
												 "AAA=");
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			auto ec = s1.loadSessionState(v3_data);
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertFalse(s1.canStartActivation());
			ccstAssertTrue(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			ccstAssertEqual(s1.activationIdentifier(), "FULL-BUT-FAKE-ACTIVATION-ID");
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			ccstAssertFalse(s1.hasActivationRecoveryData());
			
			auto v5_data = s1.saveSessionState();
			s1.resetSession();
			ec = s1.loadSessionState(v5_data);
			
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertFalse(s1.canStartActivation());
			ccstAssertTrue(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			ccstAssertEqual(s1.activationIdentifier(), "FULL-BUT-FAKE-ACTIVATION-ID");
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			ccstAssertFalse(s1.hasActivationRecoveryData());
			
			// Try low level function. The ctr_byte must not be available.
			protocol::PersistentData pd;
			utils::DataReader data_reader(v5_data);
			data_reader.openVersion('P', 'A');	// Open version
			data_reader.skipBytes(1);			// Skip flag byte
			
			auto b_result = protocol::DeserializePersistentData(pd, data_reader);
			ccstAssertTrue(b_result);
			ccstAssertEqual(pd.flags.hasSignatureCounterByte, 0);
		}
		
		void testPersistentDataUpgradeFromV4ToV5()
		{
			// constants
			std::string master_server_public_key  = "AuCDGp3fAHL695yWxCP6d+jZEzwZleOdmCU+qFIImjBs";
			
			SessionSetup oldSetup;
			oldSetup.applicationKey		= "MDEyMzQ1Njc4OUFCQ0RFRg==";
			oldSetup.applicationSecret	= "QUJDREVGMDEyMzQ1Njc4OQ==";
			oldSetup.masterServerPublicKey = master_server_public_key;
			
			Session s1(oldSetup);
			
			auto v4_data = cc7::FromBase64String("UEECUDUQcXKzF7KLEfVzcb6F7dQ2jhtGVUxMLUJVVC1GQUtFLUFDVElWQVRJT04tSUQAA"
												 "CcQEFxD134A7jgrfXqjmzRSNEoQ+WilNdYscLQ/pbrYJqh9bhDqVVY8lLy2ZvMAtpwZwG"
												 "rtEGAsKs9Rh8mZL1u+aQ3kdsgQKe2HE5aMUP+3mc0Zgzo1XSEC+N8Q8lTW59BH/5x6H+e"
												 "ahxi9n7A4ajzLgtaC3tTJhD8AMA3jUBawHBE2zowK9ThJL4kCPJPfzZVEcZhh6v1+IrQy"
												 "bj5WeD2HhFLwEJr1nHvmSQAAAAAA");
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			auto ec = s1.loadSessionState(v4_data);
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertFalse(s1.canStartActivation());
			ccstAssertTrue(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			ccstAssertEqual(s1.activationIdentifier(), "FULL-BUT-FAKE-ACTIVATION-ID");
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			ccstAssertFalse(s1.hasActivationRecoveryData());
			
			auto v5_data = s1.saveSessionState();
			s1.resetSession();
			ec = s1.loadSessionState(v5_data);
			
			ccstAssertTrue(ec == EC_Ok);
			ccstAssertEqual(s1.protocolVersion(), Version_V3);
			ccstAssertFalse(s1.canStartActivation());
			ccstAssertTrue(s1.hasValidActivation());
			ccstAssertFalse(s1.hasPendingActivation());
			ccstAssertFalse(s1.hasExternalEncryptionKey());
			ccstAssertEqual(s1.activationIdentifier(), "FULL-BUT-FAKE-ACTIVATION-ID");
			ccstAssertEqual(Version_NA, s1.pendingProtocolUpgradeVersion());
			ccstAssertFalse(s1.hasActivationRecoveryData());
			
			// Try low level function. The ctr_byte must not be available.
			protocol::PersistentData pd;
			utils::DataReader data_reader(v5_data);
			data_reader.openVersion('P', 'A');	// Open version
			data_reader.skipBytes(1);			// Skip byte with flags
			
			auto b_result = protocol::DeserializePersistentData(pd, data_reader);
			ccstAssertTrue(b_result);
			ccstAssertEqual(pd.flags.hasSignatureCounterByte, 0);
		}
		
		
		// Helper methods
		
		std::string T_calculateActivationSignature(const std::string & code)
		{
			cc7::ByteArray signature;
			bool result = crypto::ECDSA_ComputeSignature(cc7::MakeRange(code), _masterServerPrivateKey, signature);
			if (!result) {
				ccstFailure("Activation signature calculation failed");
				return std::string();
			}
			return signature.base64String();
		}
		
		cc7::ByteArray T_calculateServerSignature(const cc7::ByteRange & data, EC_KEY * private_key = nullptr)
		{
			cc7::ByteArray signature;
			if (private_key == nullptr) {
				private_key = _masterServerPrivateKey;
			}
			bool result = crypto::ECDSA_ComputeSignature(data, private_key, signature);
			if (!result) {
				ccstFailure("Server signature calculation failed");
				return cc7::ByteArray();
			}
			return signature;
		}
		
		cc7::ByteArray prepareCounterData(const cc7::ByteRange & base_ctr_data, cc7::U64 counter)
		{
			if (base_ctr_data.empty()) {
				// V2 signature (older tests)
				cc7::ByteArray counterData(8, 0);
				cc7::U64 be_counter = cc7::ToBigEndian(counter);
				counterData.append(cc7::MakeRange(be_counter));
				return counterData;
			}
			cc7::ByteArray ctr = base_ctr_data;
			while (counter > 0) {
				ctr = protocol::ReduceSharedSecret(crypto::SHA256(ctr));
				--counter;
			}
			return ctr;
		}
		
		/*
		 Complete PA2 signing reimplementation
		 */
		std::string T_calculateSignatureForData
		(
			const cc7::ByteRange &	data,
			const std::string &		method,
			const std::string &		uri,
			const cc7::ByteRange &	secret,
			const std::string &		nonce,
			const std::string &		app_secret,
			const SignatureFactor	factor,
			const cc7::U64			counter,
		 	const cc7::ByteRange &	counter_data,
		 	const bool				is_decimal_format
		)
		{
			// Normalize data
			std::string sigData;
			std::string dataB64 = data.base64String();
			std::string uriB64 = cc7::MakeRange(uri).base64String();
			std::string ampersad("&");
			
			sigData = method + ampersad + uriB64 + ampersad + nonce + ampersad +
					  dataB64 + ampersad + app_secret;
			
			ccstMessage("Normalized: %s", sigData.c_str());
			
			// Derive keys
			protocol::SignatureKeys plain;
			cc7::ByteArray vaultKey_foo;
			if (false == protocol::DeriveAllSecretKeys(plain, vaultKey_foo, secret)) {
				ccstFailure("Unable to derive keys");
				return std::string();
			}
			
			// Prepare vector of keys
			std::vector<cc7::ByteArray> sigKeys;
			if (factor & SF_Possession) {
				sigKeys.push_back(plain.possessionKey);
			}
			if (factor & SF_Knowledge) {
				sigKeys.push_back(plain.knowledgeKey);
			}
			if (factor & SF_Biometry) {
				sigKeys.push_back(plain.biometryKey);
			}
			
			// Finally, calculate signature
			cc7::ByteArray counterData = prepareCounterData(counter_data, counter);
			
			std::string result_string;
			cc7::ByteArray result_bytes;
			for (size_t i = 0; i < sigKeys.size(); i++) {
				cc7::ByteArray signatureKey = sigKeys.at(i);
				cc7::ByteArray derivedKey   = crypto::HMAC_SHA256(counterData, signatureKey);
				for (size_t j = 0; j < i; j++) {
					cc7::ByteArray signatureKeyInnter = sigKeys.at(j + 1);
					cc7::ByteArray derivedKeyInner    = crypto::HMAC_SHA256(counterData, signatureKeyInnter);
					derivedKey						  = crypto::HMAC_SHA256(derivedKey,  derivedKeyInner);
				}
				cc7::ByteArray signatureLong = crypto::HMAC_SHA256(cc7::MakeRange(sigData),  derivedKey);
				ccstAssertTrue(signatureLong.size() >= 4);
				if (is_decimal_format) {
					// Old V2 & V3 signature version (now used only for offline signatures)
					size_t offset = signatureLong.size() - 4;
					const cc7::byte * signatureBytes = (const cc7::byte *)signatureLong.data();
					// "dynamic binary code" from HOTP draft
					uint32_t dbc = (signatureBytes[offset + 0] & 0x7F) << 24 |
									signatureBytes[offset + 1] << 16 |
									signatureBytes[offset + 2] << 8  |
									signatureBytes[offset + 3];
					dbc = dbc % 100000000;
					
					char decimalized[32];
					sprintf(decimalized, "%08d", dbc);
					if (!result_string.empty()) {
						result_string.append("-");
					}
					result_string.append(decimalized);
				} else {
					// New V3.1 online signature version
					result_bytes.append(signatureLong.byteRange().subRangeFrom(16));
				}
			}
			if (!is_decimal_format) {
				// Finalize V3.1 online signature
				cc7::Base64_Encode(result_bytes, 0, result_string);
			}
			return result_string;
		}
		
		std::string T_encryptedVaultKey(const cc7::ByteRange & master_shared_secret)
		{
			cc7::ByteArray transport_key = protocol::DeriveSecretKey(master_shared_secret, 1000);
			cc7::ByteArray vault_key = protocol::DeriveSecretKey(master_shared_secret, 2000);
			cc7::ByteArray c_vault_key = crypto::AES_CBC_Encrypt_Padding(transport_key, protocol::ZERO_IV, vault_key);
			return c_vault_key.base64String();
		}

		
		StringMap T_parseSignature(const std::string & signature)
		{
			StringMap result;
			
			auto pos = signature.find("PowerAuth ");
			if (pos != 0) {
				ccstFailure("Wrong prefix in signature");
				return result;
			}
			
			std::string signature_values = signature.substr(10);
			std::vector<std::string> items = cc7::tests::detail::SplitString(signature_values, ' ');
			for (auto && key_value : items) {
				auto eq_pos = key_value.find('=');
				if (eq_pos != key_value.npos && eq_pos < key_value.size() - 1) {
					std::string key = key_value.substr(0, eq_pos);
					std::string value = key_value.substr(eq_pos + 1);
					if (value.back() == ',') {
						value.pop_back();
					}
					if (value.front() == '"' && value.back() == '"') {
						value = value.substr(1, value.size() - 2);
						result[key] = value;
					} else {
						ccstFailure("Unescaped value: %s", key_value.c_str());
					}
				} else {
					ccstFailure("Wrong received data: %s", key_value.c_str());
				}
			}
			return result;
		}
		
	};
	
	CC7_CREATE_UNIT_TEST(pa2SessionTests, "pa2")
	
} // io::getlime::powerAuthTests
} // io::getlime
} // io
