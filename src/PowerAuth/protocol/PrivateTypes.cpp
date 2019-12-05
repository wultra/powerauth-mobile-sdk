/*
 * Copyright 2016-2019 Wultra s.r.o.
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

#include "PrivateTypes.h"
#include "Constants.h"
#include "../crypto/ECC.h"
#include "../crypto/AES.h"
#include "../utils/DataReader.h"
#include "../utils/DataWriter.h"

#include <PowerAuth/OtpUtil.h>
#include <cc7/Base64.h>

using namespace cc7;

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace protocol
{
	//
	// MARK: - Helper functions -
	//
	
	bool ValidateSessionSetup(const SessionSetup & setup, bool also_validate_key)
	{
		bool result = !setup.applicationKey.empty() &&
					  !setup.applicationSecret.empty() &&
					  !setup.masterServerPublicKey.empty();
		if (result) {
			ByteArray foo_data;
			// app key
			result = cc7::Base64_Decode(setup.applicationKey, 0, foo_data);
			result = result && !foo_data.empty();
			// app secret
			result = result && cc7::Base64_Decode(setup.applicationSecret, 0, foo_data);
			result = result && !foo_data.empty();
			// master pk
			result = result && cc7::Base64_Decode(setup.masterServerPublicKey, 0, foo_data);
			result = result && !foo_data.empty();
			// optional eek
			if (result && !setup.externalEncryptionKey.empty()) {
				result = setup.externalEncryptionKey.size() == SIGNATURE_KEY_SIZE;
			}
			
			// optional master key validation
			if (result && also_validate_key) {
				EC_KEY * foo_key = crypto::ECC_ImportPublicKey(nullptr, foo_data);
				if (nullptr == foo_key) {
					CC7_LOG("ValidateSessionSetup: Provided masterServerPublicKey is invalid.");
					result = false;
				} else {
					EC_KEY_free(foo_key);
				}
			}
		}
		return result;
	}
		
	bool ValidatePersistentData(const PersistentData & pd)
	{
		SignatureFactor expectedFactor = FullFactorMask(!pd.sk.biometryKey.empty()) | SF_Transport;
		bool result = ValidateSignatureKeys(pd.sk, expectedFactor);
		result = result && pd.passwordIterations >= PBKDF2_PASS_ITERATIONS && pd.passwordSalt.size() == PBKDF2_SALT_SIZE;
		result = result && pd.activationId.length()  > 0;
		result = result && pd.serverPublicKey.size() > 0; // && pd.devicePublicKey.size() > 0; // Check #51 issue
		result = result && pd.cDevicePrivateKey.size() > 0;
		return result;
	}
	
	bool ValidateSignatureFactor(SignatureFactor factor)
	{
		if ((factor & (SF_Possession_Knowledge_Biometry | SF_Transport)) == 0) {
			CC7_ASSERT(false, "SignatureFactor leads to empty mask");
			return false;
		}
		if ((factor & (SF_Possession_Knowledge_Biometry)) == (SF_Knowledge|SF_Biometry)) {
			CC7_ASSERT(false, "SF_Knowledge + SF_Biometry is not allowed");
			return false;
		}
		return true;
	}
	
	bool ValidateUnlockKeys(const SignatureUnlockKeys & unlock, const cc7::ByteArray * ext_key, SignatureFactor factor)
	{
		if (factor == SF_FirstLock) {
			factor = FullFactorMask(!unlock.biometryUnlockKey.empty());
		}
		
		// Check combination of factors
		if (!ValidateSignatureFactor(factor)) {
			return false;
		}

		// We don't accept zeroed possession or biometry key.
		// Better reject zeroes now than cry later :) This is a prevention against
		// lazy developers who wants to trick the module.
		
		bool result = true;
		if (ext_key != nullptr) {
			result = ext_key->size() == SIGNATURE_KEY_SIZE;
		}
		if ((factor & SF_Possession) || (factor & SF_Transport)) {
			result = result && (unlock.possessionUnlockKey.size() == SIGNATURE_KEY_SIZE);
			result = result && (unlock.possessionUnlockKey != ZERO_IV);
		}
		if (factor & SF_Knowledge) {
			result = result && (unlock.userPassword.size() >= MINIMAL_PASSWORD_LENGTH);
		}
		if (factor & SF_Biometry) {
			result = result && (unlock.biometryUnlockKey.size() == SIGNATURE_KEY_SIZE);
			result = result && (unlock.biometryUnlockKey != ZERO_IV);
		}
		return result;

	}
	
	bool ValidateSignatureKeys(const SignatureKeys & keys, SignatureFactor factor)
	{
		// This is a self check. Provided SF must contain some bitmask for a validation.
		if (!ValidateSignatureFactor(factor)) {
			return false;
		}
		
		bool result = true;
		if (factor & SF_Possession) {
			result = keys.possessionKey.size() == SIGNATURE_KEY_SIZE;
		}
		if (result && (factor & SF_Transport)) {
			result = keys.transportKey.size() == SIGNATURE_KEY_SIZE;
		}
		if (result && (factor & SF_Knowledge)) {
			result = keys.knowledgeKey.size() == SIGNATURE_KEY_SIZE;
		}
		if (result && (factor & SF_Biometry)) {
			result = keys.biometryKey.size() == SIGNATURE_KEY_SIZE;
		}
		return result;
	}
	
	//
	// MARK: - Data serialization -
	//
	
	const cc7::byte PD_TAG     = 'P';
	const cc7::byte PD_VERSION_V2 = '3';	// data version is one step ahead
	const cc7::byte PD_VERSION_V3 = '4';	// + protocol V3
	const cc7::byte PD_VERSION_V4 = '5';	// + recovery codes
	const cc7::byte PD_VERSION_V5 = '6';	// + signature counter byte

	// WARNING: If you update PD_VERSION, then please update also routine
	//          located in PA2SessionStatusDataReader.m in iOS extensions project.

	
	bool SerializePersistentData(const PersistentData & pd, utils::DataWriter & writer)
	{
		CC7_ASSERT(ValidatePersistentData(pd), "Invalid persistent data");
		
		cc7::byte version_marker;
		if (pd.isV3()) {
			version_marker = pd.flags.hasSignatureCounterByte ? PD_VERSION_V5 : PD_VERSION_V4;
		} else {
			version_marker = PD_VERSION_V2;
		}
		writer.openVersion(PD_TAG, version_marker);
		
		// Serialize hash data or counter, depending on data version
		if (pd.isV3()) {
			writer.writeData(pd.signatureCounterData);
		} else {
			writer.writeU64	(pd.signatureCounter);
		}
		writer.writeString	(pd.activationId);
		writer.writeU32		(pd.passwordIterations);
		writer.writeData	(pd.passwordSalt);
		// write signature keys
		writer.writeData	(pd.sk.possessionKey);
		writer.writeData	(pd.sk.knowledgeKey);
		writer.writeData	(pd.sk.biometryKey);
		writer.writeData	(pd.sk.transportKey);
		// write public keys
		writer.writeData	(pd.serverPublicKey);
		writer.writeData	(pd.devicePublicKey);
		// encrypted private key
		writer.writeData	(pd.cDevicePrivateKey);
		// flags
		writer.writeU32		(pd.flagsU32);

		// encrypted recovery data (PD v4)
		writer.writeData	(pd.cRecoveryData);
		
		// Counter byte
		if (writer.currentVersion() == PD_VERSION_V5) {
			writer.writeByte(pd.signatureCounterByte);
		}
		
		writer.closeVersion();
		return true;
	}
	
	bool DeserializePersistentData(PersistentData & pd, utils::DataReader & reader)
	{
		// Open version with V2, which automatically allows deserialization of future variants.
		bool result = reader.openVersion(PD_TAG, PD_VERSION_V2);
		
		// Deserialize hash data or counter, depending on version stored in the header.
		if (reader.currentVersion() >= PD_VERSION_V3) {
			result = result && reader.readData	(pd.signatureCounterData, SIGNATURE_KEY_SIZE);
			pd.signatureCounter = 0;
		} else {
			result = result && reader.readU64	(pd.signatureCounter);
			pd.signatureCounterData.clear();
		}
		result = result && reader.readString	(pd.activationId);
		result = result && reader.readU32		(pd.passwordIterations);
		result = result && reader.readData		(pd.passwordSalt, PBKDF2_SALT_SIZE);
		// signature keys
		result = result && reader.readData		(pd.sk.possessionKey, SIGNATURE_KEY_SIZE);
		result = result && reader.readData		(pd.sk.knowledgeKey, SIGNATURE_KEY_SIZE);
		result = result && reader.readData		(pd.sk.biometryKey);
		result = result && reader.readData		(pd.sk.transportKey, SIGNATURE_KEY_SIZE);
		// public keys
		result = result && reader.readData		(pd.serverPublicKey);
		result = result && reader.readData		(pd.devicePublicKey);
		// encrypted private key
		result = result && reader.readData		(pd.cDevicePrivateKey);
		// flags
		result = result && reader.readU32		(pd.flagsU32);
		
		// Copy external key flag to the SignatureKeys structure
		pd.sk.usesExternalKey = pd.flags.usesExternalKey;
		
		// encrypted recovery data (PD v4)
		if (reader.currentVersion() >= PD_VERSION_V4) {
			result = result && reader.readData	(pd.cRecoveryData);
		} else {
			pd.cRecoveryData.clear();
		}
		
		// signature counter byte (PD v5)
		if (reader.currentVersion() >= PD_VERSION_V5) {
			result = result && reader.readByte(pd.signatureCounterByte);
			pd.flags.hasSignatureCounterByte = 1;
		} else {
			pd.flags.hasSignatureCounterByte = 0;
			pd.signatureCounterByte = 0;
		}
		
		// close versioned section & validate data
		result = result && reader.closeVersion();
		result = result && ValidatePersistentData(pd);
		
		return result;
	}
	
	
	//
	// MARK: - Recovery codes -
	//
	
	const cc7::byte RD_TAG     	  = 'R';
	const cc7::byte RD_VERSION_V1 = '1';	// recovery data version
	
	bool ValidateRecoveryData(const RecoveryData & data)
	{
		if (data.isEmpty()) {
			return true;
		}
		// Validate recovery code and PUK. Recovery code should not contain "R:" prefix.
		return OtpUtil::validateRecoveryCode(data.recoveryCode, false) &&
			   OtpUtil::validateRecoveryPuk(data.puk);
	}
	
	bool SerializeRecoveryData(const RecoveryData & data, const cc7::ByteRange vault_key, cc7::ByteArray & out_data)
	{
		CC7_ASSERT(ValidateRecoveryData(data), "Invalid recovery data");
		
		if (data.isEmpty()) {
			out_data.clear();
			return true;
		}
		// Serialize structure to sequence of bytes
		utils::DataWriter writer;
		writer.openVersion(RD_TAG, RD_VERSION_V1);
		writer.writeString(data.recoveryCode);
		writer.writeString(data.puk);
		writer.closeVersion();
		
		// Encrypt sequence of bytes
		out_data = crypto::AES_CBC_Encrypt_Padding(vault_key, ZERO_IV, writer.serializedData());
		return !out_data.empty();
	}
	
	bool DeserializeRecoveryData(const cc7::ByteRange & serialized, const cc7::ByteRange vault_key, RecoveryData & out_data)
	{
		// Should not be called with an empty data. Unlike in serialization routine, we consider this as an error.
		if (serialized.empty()) {
			CC7_ASSERT(false, "Should not be called when recovery data is not available");
			return false;
		}
		
		// Decrypt serialized sequence of bytes.
		bool error = false;
		auto decrypted = crypto::AES_CBC_Decrypt_Padding(vault_key, ZERO_IV, serialized, &error);
		if (error) {
			return false;
		}
		
		utils::DataReader reader(decrypted);

		// Open version with V1, which automatically allows deserialization of future variants.
		bool result = reader.openVersion(RD_TAG, RD_VERSION_V1);
		result = result && reader.readString(out_data.recoveryCode);
		result = result && reader.readString(out_data.puk);
		result = result && reader.closeVersion();
		
		result = result && ValidateRecoveryData(out_data);
		
		return result;
	}
	
	
	// MARK: - Support for old data format -
	
	//
	// For a historical reasons, we still have to support old persistent data format,
	// which has been used in very old, closed source version of PowerAuth library.
	//
	// Once all users will migrate to app based on our open source library, then this
	// code will be removed.
	//
	// DATA_MIGRATION_TAG
	
	static bool _old_readData(utils::DataReader & reader, cc7::ByteArray & out_data, size_t expected_size = 0)
	{
		uint16_t size;
		if (!reader.readU16(size)) {
			return false;
		}
		if (expected_size > 0 && expected_size != size) {
			return false;
		}
		if (!reader.readMemory(out_data, size)) {
			return false;
		}
		return true;
	}
	
	static bool _old_readString(utils::DataReader & reader, std::string & out_string)
	{
		uint16_t size;
		if (!reader.readU16(size)) {
			return false;
		}
		cc7::ByteRange range;
		if (!reader.readMemoryRange(range, size)) {
			return false;
		}
		out_string.assign((const char*)range.data(), range.size());
		return true;
	}

	bool TryDeserializeOldPersistentData(PersistentData & pd, utils::DataReader & reader)
	{
		enum OldDataTags
		{
			// magic & length of header
			H_1 = 'P', H_2 = 'A', H_3 = 'M',
			H_SIZE = 4,
			// supported versions
			H_VER1 = '1', H_VER2 = '2',
			// Activation or not...
			H_ACT      = 'a',
			H_NO_ACT   = 'i',
			// End of records
			H_END     = 0xff
		};

		// reset stream offset to the zero
		reader.reset();

		// read header
		cc7::ByteRange header;
		cc7::byte ver = 0, status = 0, end = 0;
		cc7::U32 foo;
		bool result = reader.readMemoryRange(header, H_SIZE) &&
					  reader.readByte(status);
		if (!result || header[0] != H_1 || header[1] != H_2 || header[2] != H_3) {
			return false;	// unknown magic in header
		}
		ver = header[3];
		if ((ver != H_VER1 && ver != H_VER2) || (status != H_ACT && status != H_NO_ACT)) {
			return false;	// unknown version or status tag
		}
		if (status == H_ACT) {
			// has activation, so deserialize persistent data
			result = result && _old_readString(reader, pd.activationId);
			result = result && reader.readU64(pd.signatureCounter);
			result = result && reader.readU32(foo);	// ignore "flags", there's nothing important there
			result = result && _old_readData(reader, pd.passwordSalt);
			result = result && reader.readU32(pd.passwordIterations);
			result = result && _old_readData(reader, pd.sk.possessionKey, SIGNATURE_KEY_SIZE);
			result = result && _old_readData(reader, pd.sk.knowledgeKey, SIGNATURE_KEY_SIZE);
			result = result && _old_readData(reader, pd.sk.biometryKey);
			result = result && _old_readData(reader, pd.sk.transportKey, SIGNATURE_KEY_SIZE);
			result = result && _old_readData(reader, pd.serverPublicKey);
			result = result && _old_readData(reader, pd.cDevicePrivateKey);
			if (ver == H_VER2) {
				std::string foo;
				result = result && _old_readString(reader, foo); // this value is no longer important
			}
			result = result && ValidatePersistentData(pd);
		}
		result = result && reader.readByte(end);
		return   result && (end == H_END) && (reader.remainingSize() == 0);
	}

	
} // io::getlime::powerAuth::detail
} // io::getlime::powerAuth
} // io::getlime
} // io
