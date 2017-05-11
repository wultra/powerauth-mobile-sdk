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

using namespace io::getlime::powerAuth;

@implementation PA2Session
{
	Session *	_session;
	ErrorCode	_error;
}

#pragma mark - Initialization / Reset


- (nullable instancetype) initWithSessionSetup:(nonnull PA2SessionSetup *)setup
{
	self = [super init];
	if (self) {
		SessionSetup cpp_setup;
		PA2SessionSetupToStruct(setup, cpp_setup);
		_session = new Session(cpp_setup);
	}
	return self;
}

- (void) dealloc
{
	delete _session;
}

- (void) resetSession
{
	if (_session) {
		_session->resetSession();
		_error = EC_Ok;
	} else {
		_error = EC_WrongParam;
	}
}


+ (BOOL) hasDebugFeatures
{
	return io::getlime::powerAuth::HasDebugFeaturesTurnedOn();
}


#pragma mark - Read only getters

- (PA2SessionSetup*) sessionSetup
{
	if (_session) {
		const SessionSetup * cpp_setup = _session->sessionSetup();
		if (cpp_setup) {
			return PA2SessionSetupToObject(*cpp_setup);
		}
	}
	return nil;
}

- (UInt32) sessionIdentifier
{
	return _session ? _session->sessionIdentifier() : 0;
}

- (PA2CoreErrorCode) lastErrorCode
{
	return static_cast<PA2CoreErrorCode>(_error);
}


- (BOOL) hasValidSetup
{
	return  _session ? _session->hasValidSetup() : NO;
}

- (BOOL) canStartActivation
{
	return _session ? _session->canStartActivation() : NO;
}

- (BOOL) hasPendingActivation
{
	return _session ? _session->hasPendingActivation() : NO;
}

- (BOOL) hasValidActivation
{
	return _session ? _session->hasValidActivation() : NO;
}



#pragma mark - Serialization

- (nonnull NSData*) serializedState
{
	if (_session) {
		return cc7::objc::CopyToNSData(_session->saveSessionState());
	}
	return [NSData data];
}


- (BOOL) deserializeState:(nonnull NSData *)state
{
	if (_session) {
		_error = _session->loadSessionState(cc7::ByteRange(state.bytes, state.length));
		return _error == EC_Ok;
	}
	_error = EC_WrongParam;
	return NO;
}



#pragma mark - Activation

- (nullable NSString*) activationIdentifier
{
	if (_session) {
		if (_session->hasValidActivation()) {
			return cc7::objc::CopyToNSString(_session->activationIdentifier());
		}
	}
	return nil;
}


- (nullable PA2ActivationStep1Result*) startActivation:(nonnull PA2ActivationStep1Param*)param
{
	if (_session) {
		ActivationStep1Param cpp_p1;
		ActivationStep1Result cpp_r1;
		PA2ActivationStep1ParamToStruct(param, cpp_p1);
		_error = _session->startActivation(cpp_p1, cpp_r1);
		if (_error == EC_Ok) {
			return PA2ActivationStep1ResultToObject(cpp_r1);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}


- (nullable PA2ActivationStep2Result*) validateActivationResponse:(nonnull PA2ActivationStep2Param*)param
{
	if (_session) {
		ActivationStep2Param cpp_p2;
		ActivationStep2Result cpp_r2;
		PA2ActivationStep2ParamToStruct(param, cpp_p2);
		_error = _session->validateActivationResponse(cpp_p2, cpp_r2);
		if (_error == EC_Ok) {
			return PA2ActivationStep2ResultToObject(cpp_r2);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}


- (BOOL) completeActivation:(nonnull PA2SignatureUnlockKeys*)keys
{
	if (_session) {
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(keys, cpp_keys);
		_error = _session->completeActivation(cpp_keys);
		return _error == EC_Ok;
	}
	_error = EC_WrongParam;
	return NO;
}



#pragma mark - Activation status

- (nullable PA2ActivationStatus*) decodeActivationStatus:(nonnull NSString *)statusBlob
													keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	if (_session) {
		SignatureUnlockKeys cpp_keys;
		ActivationStatus cpp_status;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		_error = _session->decodeActivationStatus(cc7::objc::CopyFromNSString(statusBlob), cpp_keys, cpp_status);
		if (_error == EC_Ok) {
			return PA2ActivationStatusToObject(cpp_status);
		}
	} else {
		_error = EC_WrongParam;
	}
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


- (nullable NSString*) httpAuthHeaderValueForBody:(nullable NSData*)body
									   httpMethod:(nonnull NSString*)httpMethod
											  uri:(nonnull NSString*)uri
											 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
										   factor:(PA2SignatureFactor)factor;
{
	if (_session) {
		HTTPRequestData request;
		request.body	= cc7::ByteRange(body.bytes, body.length);
		request.method	= cc7::objc::CopyFromNSString(httpMethod);
		request.uri		= cc7::objc::CopyFromNSString(uri);
		SignatureFactor cpp_factor	= static_cast<SignatureFactor>(factor);
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
		HTTPRequestDataSignature signature;
		_error = _session->signHTTPRequestData(request, cpp_keys, cpp_factor, signature);
		if (_error == EC_Ok) {
			return cc7::objc::CopyToNSString(signature.buildAuthHeaderValue());
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}


- (NSString*) httpAuthHeaderName
{
	return _session ? cc7::objc::CopyToNSString(_session->httpAuthHeaderName()) : nil;
}



#pragma mark - Signature keys management

- (BOOL) changeUserPassword:(nonnull PA2Password *)old_password newPassword:(nonnull PA2Password*)new_password
{
	if (_session) {
		if (old_password == nil || new_password == nil) {
			CC7_ASSERT(false, "Password object is nil");
			_error = EC_WrongParam;
			return NO;
		}
		_error = _session->changeUserPassword([old_password passObjRef].passwordData(), [new_password passObjRef].passwordData());
		return _error == EC_Ok;
	}
	_error = EC_WrongParam;
	return NO;
}

- (BOOL) addBiometryFactor:(nonnull NSString *)cVaultKey
					  keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	if (_session) {
		std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		_error = _session->addBiometryFactor(cpp_c_vault_key, cpp_keys);
		return _error == EC_Ok;
	}
	_error = EC_WrongParam;
	return NO;
}

- (BOOL) hasBiometryFactor
{
	if (!_session) {
		_error = EC_WrongParam;
		return NO;
	}
	bool result;
	_error = _session->hasBiometryFactor(result);
	return result;
}

- (BOOL) removeBiometryFactor
{
	if (_session) {
		_error = _session->removeBiometryFactor();
		return _error == EC_Ok;
	}
	_error = EC_WrongParam;
	return NO;
}


#pragma mark - Vault operations

- (nullable NSData*) deriveCryptographicKeyFromVaultKey:(nonnull NSString*)cVaultKey
												   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											   keyIndex:(UInt64)keyIndex
{
	if (_session) {
		std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
		cc7::ByteArray cpp_derived_key;
		_error = _session->deriveCryptographicKeyFromVaultKey(cpp_c_vault_key, cpp_keys, keyIndex, cpp_derived_key);
		if (_error == EC_Ok) {
			return cc7::objc::CopyToNSData(cpp_derived_key);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}

- (nullable NSData*) signDataWithDevicePrivateKey:(nonnull NSString*)cVaultKey
											 keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
											 data:(nonnull NSData*)data
{
	if (_session) {
		std::string cpp_c_vault_key	= cc7::objc::CopyFromNSString(cVaultKey);
		cc7::ByteArray cpp_data		= cc7::objc::CopyFromNSData(data);
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
		cc7::ByteArray cpp_signature;
		_error = _session->signDataWithDevicePrivateKey(cpp_c_vault_key, cpp_keys, cpp_data, cpp_signature);
		if (_error == EC_Ok) {
			return cc7::objc::CopyToNSData(cpp_signature);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}


#pragma mark - E2EE

- (nullable PA2Encryptor*) nonpersonalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex
{
	if (_session) {
		cc7::ByteArray cpp_session_index = cc7::objc::CopyFromNSData(sessionIndex);
		Encryptor * cpp_encryptor = nullptr;
		std::tie(_error, cpp_encryptor) = _session->createNonpersonalizedEncryptor(cpp_session_index);
		if (_error == EC_Ok) {
			return [[PA2Encryptor alloc] initWithEncryptorPtr:cpp_encryptor];
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}

- (nullable PA2Encryptor*) personalizedEncryptorForSessionIndex:(nonnull NSData*)sessionIndex
														   keys:(nonnull PA2SignatureUnlockKeys*)unlockKeys
{
	if (_session) {
		cc7::ByteArray cpp_session_index = cc7::objc::CopyFromNSData(sessionIndex);
		SignatureUnlockKeys cpp_keys;
		PA2SignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		Encryptor * cpp_encryptor = nullptr;
		std::tie(_error, cpp_encryptor) = _session->createPersonalizedEncryptor(cpp_session_index, cpp_keys);
		if (_error == EC_Ok) {
			return [[PA2Encryptor alloc] initWithEncryptorPtr:cpp_encryptor];
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}


#pragma mark - External encryption key

- (BOOL) hasExternalEncryptionKey
{
	if (_session) {
		return _session->hasExternalEncryptionKey();
	}
	return NO;
}

- (BOOL) setExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
{
	if (_session) {
		_error = _session->setExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
		if (_error == EC_Ok) {
			return YES;
		}
	} else {
		_error = EC_WrongParam;
	}
	return NO;
}

- (BOOL) addExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
{
	if (_session) {
		_error = _session->addExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
		if (_error == EC_Ok) {
			return YES;
		}
	} else {
		_error = EC_WrongParam;
	}
	return NO;
}

- (BOOL) removeExternalEncryptionKey
{
	if (_session) {
		return _session->removeExternalEncryptionKey();
	}
	return NO;
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
