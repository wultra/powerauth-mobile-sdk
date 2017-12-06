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

#include "PrivateTypes.h"
#include "Constants.h"
#include "../crypto/ECC.h"
#include "../utils/DataReader.h"
#include "../utils/DataWriter.h"

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
	const cc7::byte PD_VERSION = '3';
	
	bool SerializePersistentData(const PersistentData & pd, utils::DataWriter & writer)
	{
		CC7_ASSERT(ValidatePersistentData(pd), "Invalid persistent data");
		
		writer.openVersion(PD_TAG, PD_VERSION);
		
		writer.writeU64		(pd.signatureCounter);
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
		
		writer.closeVersion();
		return true;
	}
	
	bool DeserializePersistentData(PersistentData & pd, utils::DataReader & reader)
	{
		bool result = reader.openVersion(PD_TAG, PD_VERSION);
		
		result = result && reader.readU64		(pd.signatureCounter);
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
		
		// close versioned section & validate data
		result = result && reader.closeVersion();
		result = result && ValidatePersistentData(pd);
		
		return result;
	}
	
	// MARK: - Support for old data format -
	
	//
	// For a historical reasons, we still have to support old persistent data format,
	// which has been used in very old, closed source version, of PowerAuth library.
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
