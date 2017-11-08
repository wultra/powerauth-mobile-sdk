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

#import "PA2Session.h"
#include <PowerAuth/Session.h>
#include <PowerAuth/Debug.h>
#import "PA2PrivateImpl.h"
#import "PA2Macros.h"

using namespace io::getlime::powerAuth;

@implementation PA2Session
{
	Session *	_session;
}

/**
 Dumps C++ error code to the debug log.
 */
void _DumpErrorCode(PA2Session * inst, NSString * message, ErrorCode code)
{
#ifdef DEBUG
	if (code != EC_Ok) {
		NSString * codeStr;
		switch (code) {
			case EC_Encryption: codeStr = @"EC_Encryption"; break;
			case EC_WrongParam: codeStr = @"EC_WrongParam"; break;
			case EC_WrongState: codeStr = @"EC_WrongState"; break;
			default:
				codeStr = [@(code) stringValue];
				break;
		}
		PALog(@"PA2Session(ID:%d): %@: Low level operation failed with error %@.", (unsigned int)inst.sessionIdentifier, message, codeStr);
	}
#endif
}

#pragma mark - Initialization / Reset

- (nullable instancetype) initWithSessionSetup:(nonnull PA2SessionSetup *)setup
{
	self = [super init];
	if (self) {
		SessionSetup cpp_setup;
		PA2SessionSetupToStruct(setup, cpp_setup);
		_session = new Session(cpp_setup);
		if (!_session) {
			// This is a low memory issue. Returning nil we guarantee that swift/objc
			// will not use this unitialized instance at all.
			return nil;
		}
	}
	return self;
}

- (nullable instancetype) init
{
	// Simple object init should always return nil
	return nil;
}

- (void) dealloc
{
	delete _session;
}

- (void) resetSession
{
	_session->resetSession();
}


+ (BOOL) hasDebugFeatures
{
	return io::getlime::powerAuth::HasDebugFeaturesTurnedOn();
}


#pragma mark - Read only getters

- (PA2SessionSetup*) sessionSetup
{
	const SessionSetup * cpp_setup = _session->sessionSetup();
	if (cpp_setup) {
		return PA2SessionSetupToObject(*cpp_setup);
	}
	return nil;
}

- (UInt32) sessionIdentifier
{
	return _session->sessionIdentifier();
}

- (BOOL) hasValidSetup
{
	return  _session->hasValidSetup();
}

- (BOOL) canStartActivation
{
	return _session->canStartActivation();
}

- (BOOL) hasPendingActivation
{
	return _session->hasPendingActivation();
}

- (BOOL) hasValidActivation
{
	return _session->hasValidActivation();
}



#pragma mark - Serialization

- (nonnull NSData*) serializedState
{
	return cc7::objc::CopyToNSData(_session->saveSessionState());
}


- (BOOL) deserializeState:(nonnull NSData *)state
{
	auto error = _session->loadSessionState(cc7::ByteRange(state.bytes, state.length));
	_DumpErrorCode(self, @"DeserializeState", error);
	return error == EC_Ok;
}



#pragma mark - Activation

- (nullable NSString*) activationIdentifier
{
	if (_session->hasValidActivation()) {
		return cc7::objc::CopyToNSString(_session->activationIdentifier());
	}
	return nil;
}


- (nullable PA2ActivationStep1Result*) startActivation:(nonnull PA2ActivationStep1Param*)param
{
	ActivationStep1Param cpp_p1;
	ActivationStep1Result cpp_r1;
	PA2ActivationStep1ParamToStruct(param, cpp_p1);
	auto error = _session->startActivation(cpp_p1, cpp_r1);
	if (error == EC_Ok) {
		return PA2ActivationStep1ResultToObject(cpp_r1);
	}
	_DumpErrorCode(self, @"StartActivation", error);
	return nil;
}


- (nullable PA2ActivationStep2Result*) validateActivationResponse:(nonnull PA2ActivationStep2Param*)param
{
	ActivationStep2Param cpp_p2;
	ActivationStep2Result cpp_r2;
	PA2ActivationStep2ParamToStruct(param, cpp_p2);
	auto error = _session->validateActivationResponse(cpp_p2, cpp_r2);
	if (error == EC_Ok) {
		return PA2ActivationStep2ResultToObject(cpp_r2);
	}
	_DumpErrorCode(self, @"ValidateActivation", error);
	return nil;
}


- (BOOL) completeActivation:(nonnull PA2SignatureUnlockKeys*)keys
{
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(keys, cpp_keys);
	auto error = _session->completeActivation(cpp_keys);
	_DumpErrorCode(self, @"CompleteActivation", error);
	return error == EC_Ok;
}



#pragma mark - Activation status

- (nullable PA2ActivationStatus*) decodeActivationStatus:(nonnull NSString *)statusBlob
													keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	SignatureUnlockKeys cpp_keys;
	ActivationStatus cpp_status;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto error = _session->decodeActivationStatus(cc7::objc::CopyFromNSString(statusBlob), cpp_keys, cpp_status);
	if (error == EC_Ok) {
		return PA2ActivationStatusToObject(cpp_status);
	}
	_DumpErrorCode(self, @"DecodeActivationStatus", error);
	return nil;
}



#pragma mark - Data signing

- (nullable NSData*) prepareKeyValueDictionaryForDataSigning:(nonnull NSDictionary<NSString*, NSString*>*)dictionary
{
	__block std::map<std::string, std::string> map;
	__block BOOL error = NO;
	[dictionary enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * stop) {
		if (![key isKindOfClass:[NSString class]] || ![value isKindOfClass:[NSString class]]) {
			CC7_ASSERT(false, "Wrong type of object or key in provided NSDictionary.");
			*stop = error = YES;
			return;
		}
		map[std::string(key.UTF8String)] = std::string(value.UTF8String);
	}];
	if (error) {
		return nil;
	}
	cc7::ByteArray normalized_data = Session::prepareKeyValueMapForDataSigning(map);
	return cc7::objc::CopyToNSData(normalized_data);
}


- (nullable PA2HTTPRequestDataSignature*) signHttpRequestData:(nonnull PA2HTTPRequestData*)requestData
														 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
													   factor:(PA2SignatureFactor)factor
{
	HTTPRequestData request;
	PA2HTTPRequestDataToStruct(requestData, request);
	SignatureFactor cpp_factor	= static_cast<SignatureFactor>(factor);
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	PA2HTTPRequestDataSignature * signature = [[PA2HTTPRequestDataSignature alloc] init];
	auto error = _session->signHTTPRequestData(request, cpp_keys, cpp_factor, [signature signatureStructRef]);
	if (error == EC_Ok) {
		return signature;
	}
	_DumpErrorCode(self, @"SignHttpRequestData", error);
	return nil;
}


- (NSString*) httpAuthHeaderName
{
	return cc7::objc::CopyToNSString(_session->httpAuthHeaderName());
}


- (BOOL) verifyServerSignedData:(nonnull PA2SignedData*)signedData
{
	ErrorCode error;
	if (signedData != nil) {
		error = _session->verifyServerSignedData(signedData.signedDataRef);
	} else {
		error = EC_WrongParam;
	}
	_DumpErrorCode(self, @"VerifyServerSignedData", error);
	return error == EC_Ok;
}


#pragma mark - Signature keys management

- (BOOL) changeUserPassword:(nonnull PA2Password *)old_password newPassword:(nonnull PA2Password*)new_password
{
	ErrorCode error;
	if (old_password != nil && new_password != nil) {
		error = _session->changeUserPassword([old_password passObjRef].passwordData(), [new_password passObjRef].passwordData());
	} else {
		error = EC_WrongParam;
		return NO;
	}
	_DumpErrorCode(self, @"ChangeUserPassword", error);
	return error == EC_Ok;
}

- (BOOL) addBiometryFactor:(nonnull NSString *)cVaultKey
					  keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto error = _session->addBiometryFactor(cpp_c_vault_key, cpp_keys);
	_DumpErrorCode(self, @"AddBiometryFactor", error);
	return error == EC_Ok;
}

- (BOOL) hasBiometryFactor
{
	bool result;
	auto error = _session->hasBiometryFactor(result);
	_DumpErrorCode(self, @"HasBiometryFactor", error);
	return result;
}

- (BOOL) removeBiometryFactor
{
	auto error = _session->removeBiometryFactor();
	_DumpErrorCode(self, @"RemoveBiometryFactor", error);
	return error == EC_Ok;
}


#pragma mark - Vault operations

- (nullable NSData*) deriveCryptographicKeyFromVaultKey:(nonnull NSString*)cVaultKey
												   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											   keyIndex:(UInt64)keyIndex
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_derived_key;
	auto error = _session->deriveCryptographicKeyFromVaultKey(cpp_c_vault_key, cpp_keys, keyIndex, cpp_derived_key);
	if (error == EC_Ok) {
		return cc7::objc::CopyToNSData(cpp_derived_key);
	}
	_DumpErrorCode(self, @"DeriveCryptographicKeyFromVaultKey", error);
	return nil;
}

- (nullable NSData*) signDataWithDevicePrivateKey:(nonnull NSString*)cVaultKey
											 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											 data:(nonnull NSData*)data
{
	std::string cpp_c_vault_key	= cc7::objc::CopyFromNSString(cVaultKey);
	cc7::ByteArray cpp_data		= cc7::objc::CopyFromNSData(data);
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_signature;
	auto error = _session->signDataWithDevicePrivateKey(cpp_c_vault_key, cpp_keys, cpp_data, cpp_signature);
	if (error == EC_Ok) {
		return cc7::objc::CopyToNSData(cpp_signature);
	}
	_DumpErrorCode(self, @"SignDataWithDevicePrivateKey", error);
	return nil;
}


#pragma mark - E2EE

- (nullable PA2Encryptor*) nonpersonalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex
{
	cc7::ByteArray cpp_session_index = cc7::objc::CopyFromNSData(sessionIndex);
	Encryptor * cpp_encryptor = nullptr;
	ErrorCode error = EC_Ok;
	std::tie(error, cpp_encryptor) = _session->createNonpersonalizedEncryptor(cpp_session_index);
	if (error == EC_Ok) {
		return [[PA2Encryptor alloc] initWithEncryptorPtr:cpp_encryptor];
	}
	_DumpErrorCode(self, @"NonpersonalizedEncryptorForSessionIndex", error);
	return nil;
}

- (nullable PA2Encryptor*) personalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex
														   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	cc7::ByteArray cpp_session_index = cc7::objc::CopyFromNSData(sessionIndex);
	SignatureUnlockKeys cpp_keys;
	PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	Encryptor * cpp_encryptor = nullptr;
	ErrorCode error = EC_Ok;
	std::tie(error, cpp_encryptor) = _session->createPersonalizedEncryptor(cpp_session_index, cpp_keys);
	if (error == EC_Ok) {
		return [[PA2Encryptor alloc] initWithEncryptorPtr:cpp_encryptor];
	}
	_DumpErrorCode(self, @"PersonalizedEncryptorForSessionIndex", error);
	return nil;
}


#pragma mark - External encryption key

- (BOOL) hasExternalEncryptionKey
{
	return _session->hasExternalEncryptionKey();
}

- (BOOL) setExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
{
	auto error = _session->setExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
	_DumpErrorCode(self, @"SetExternalEncryptionKey", error);
	return error == EC_Ok;
}

- (BOOL) addExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
{
	auto error = _session->addExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
	_DumpErrorCode(self, @"AddExternalEncryptionKey", error);
	return error == EC_Ok;
}

- (BOOL) removeExternalEncryptionKey
{
	auto error = _session->removeExternalEncryptionKey();
	_DumpErrorCode(self, @"RemoveExternalEncryptionKey", error);
	return error == EC_Ok;
}


#pragma mark - Utilities for generic keys

+ (nonnull NSData*) normalizeSignatureUnlockKeyFromData:(nonnull NSData*)data
{
	return cc7::objc::CopyToNSData(Session::normalizeSignatureUnlockKeyFromData(cc7::ByteRange(data.bytes, data.length)));
}


+ (nonnull NSData*) generateSignatureUnlockKey
{
	return cc7::objc::CopyToNSData(Session::generateSignatureUnlockKey());
}


@end
