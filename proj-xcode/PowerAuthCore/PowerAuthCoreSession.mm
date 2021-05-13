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

#include <PowerAuth/Session.h>
#include <PowerAuth/Debug.h>

#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace io::getlime::powerAuth;

@implementation PowerAuthCoreSession
{
	Session *	_session;
}

#pragma mark - Initialization / Reset

- (nullable instancetype) initWithSessionSetup:(nonnull PowerAuthCoreSessionSetup *)setup
{
	self = [super init];
	if (self) {
		SessionSetup cpp_setup;
		PowerAuthCoreSessionSetupToStruct(setup, cpp_setup);
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
	BOOL debug_features = io::getlime::powerAuth::HasDebugFeaturesTurnedOn();
#if defined(ENABLE_POWERAUTH_CORE_LOG) || defined(DEBUG)
	debug_features |= YES;
#endif
	return debug_features;
}


#pragma mark - Read only getters

- (PowerAuthCoreSessionSetup*) sessionSetup
{
	const SessionSetup * cpp_setup = _session->sessionSetup();
	if (cpp_setup) {
		return PowerAuthCoreSessionSetupToObject(*cpp_setup);
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

- (BOOL) hasProtocolUpgradeAvailable
{
	return _session->hasProtocolUpgradeAvailable();
}

- (BOOL) hasPendingProtocolUpgrade
{
	return _session->hasPendingProtocolUpgrade();
}

- (PowerAuthCoreProtocolVersion) protocolVersion
{
	return (PowerAuthCoreProtocolVersion) _session->protocolVersion();
}

#pragma mark - Serialization

- (nonnull NSData*) serializedState
{
	return cc7::objc::CopyToNSData(_session->saveSessionState());
}


- (BOOL) deserializeState:(nonnull NSData *)state
{
	auto error = _session->loadSessionState(cc7::ByteRange(state.bytes, state.length));
	PowerAuthCoreObjc_DebugDumpError(self, @"DeserializeState", error);
	return error == EC_Ok;
}



#pragma mark - Activation

- (nullable NSString*) activationIdentifier
{
	return cc7::objc::CopyToNullableNSString(_session->activationIdentifier());
}

- (nullable NSString*) activationFingerprint
{
	return cc7::objc::CopyToNullableNSString(_session->activationFingerprint());
}

- (nullable PowerAuthCoreActivationStep1Result*) startActivation:(nonnull PowerAuthCoreActivationStep1Param*)param
{
	ActivationStep1Param cpp_p1;
	ActivationStep1Result cpp_r1;
	PowerAuthCoreActivationStep1ParamToStruct(param, cpp_p1);
	auto error = _session->startActivation(cpp_p1, cpp_r1);
	if (error == EC_Ok) {
		return PowerAuthCoreActivationStep1ResultToObject(cpp_r1);
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"StartActivation", error);
	return nil;
}


- (nullable PowerAuthCoreActivationStep2Result*) validateActivationResponse:(nonnull PowerAuthCoreActivationStep2Param*)param
{
	ActivationStep2Param cpp_p2;
	ActivationStep2Result cpp_r2;
	PowerAuthCoreActivationStep2ParamToStruct(param, cpp_p2);
	auto error = _session->validateActivationResponse(cpp_p2, cpp_r2);
	if (error == EC_Ok) {
		return PowerAuthCoreActivationStep2ResultToObject(cpp_r2);
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"ValidateActivation", error);
	return nil;
}


- (BOOL) completeActivation:(nonnull PowerAuthCoreSignatureUnlockKeys*)keys
{
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(keys, cpp_keys);
	auto error = _session->completeActivation(cpp_keys);
	PowerAuthCoreObjc_DebugDumpError(self, @"CompleteActivation", error);
	return error == EC_Ok;
}



#pragma mark - Activation status

- (nullable PowerAuthCoreActivationStatus*) decodeActivationStatus:(nonnull PowerAuthCoreEncryptedActivationStatus *)encryptedStatus
															  keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
{
	EncryptedActivationStatus cpp_encrypted_status;
	SignatureUnlockKeys cpp_keys;
	ActivationStatus cpp_status;
	PowerAuthCoreEncryptedActivationStatusToStruct(encryptedStatus, cpp_encrypted_status);
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto error = _session->decodeActivationStatus(cpp_encrypted_status, cpp_keys, cpp_status);
	if (error == EC_Ok) {
		return PowerAuthCoreActivationStatusToObject(cpp_status);
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"DecodeActivationStatus", error);
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


- (nullable PowerAuthCoreHTTPRequestDataSignature*) signHttpRequestData:(nonnull PowerAuthCoreHTTPRequestData*)requestData
																   keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
															     factor:(PowerAuthCoreSignatureFactor)factor
{
	HTTPRequestData request;
	PowerAuthCoreHTTPRequestDataToStruct(requestData, request);
	SignatureFactor cpp_factor	= static_cast<SignatureFactor>(factor);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	PowerAuthCoreHTTPRequestDataSignature * signature = [[PowerAuthCoreHTTPRequestDataSignature alloc] init];
	auto error = _session->signHTTPRequestData(request, cpp_keys, cpp_factor, [signature signatureStructRef]);
	if (error == EC_Ok) {
		return signature;
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"SignHttpRequestData", error);
	return nil;
}


- (NSString*) httpAuthHeaderName
{
	return cc7::objc::CopyToNSString(_session->httpAuthHeaderName());
}


- (BOOL) verifyServerSignedData:(nonnull PowerAuthCoreSignedData*)signedData
{
	ErrorCode error;
	if (signedData != nil) {
		error = _session->verifyServerSignedData(signedData.signedDataRef);
	} else {
		error = EC_WrongParam;
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"VerifyServerSignedData", error);
	return error == EC_Ok;
}


#pragma mark - Signature keys management

- (BOOL) changeUserPassword:(nonnull PowerAuthCorePassword *)old_password newPassword:(nonnull PowerAuthCorePassword*)new_password
{
	ErrorCode error;
	if (old_password != nil && new_password != nil) {
		error = _session->changeUserPassword([old_password passObjRef].passwordData(), [new_password passObjRef].passwordData());
	} else {
		error = EC_WrongParam;
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"ChangeUserPassword", error);
	return error == EC_Ok;
}

- (BOOL) addBiometryFactor:(nonnull NSString *)cVaultKey
					  keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto error = _session->addBiometryFactor(cpp_c_vault_key, cpp_keys);
	PowerAuthCoreObjc_DebugDumpError(self, @"AddBiometryFactor", error);
	return error == EC_Ok;
}

- (BOOL) hasBiometryFactor
{
	bool result;
	CC7_UNUSED_VAR auto error = _session->hasBiometryFactor(result);
	PowerAuthCoreObjc_DebugDumpError(self, @"HasBiometryFactor", error);
	return result;
}

- (BOOL) removeBiometryFactor
{
	auto error = _session->removeBiometryFactor();
	PowerAuthCoreObjc_DebugDumpError(self, @"RemoveBiometryFactor", error);
	return error == EC_Ok;
}


#pragma mark - Vault operations

- (nullable NSData*) deriveCryptographicKeyFromVaultKey:(nonnull NSString*)cVaultKey
												   keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
											   keyIndex:(UInt64)keyIndex
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_derived_key;
	auto error = _session->deriveCryptographicKeyFromVaultKey(cpp_c_vault_key, cpp_keys, keyIndex, cpp_derived_key);
	if (error == EC_Ok) {
		return cc7::objc::CopyToNSData(cpp_derived_key);
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"DeriveCryptographicKeyFromVaultKey", error);
	return nil;
}

- (nullable NSData*) signDataWithDevicePrivateKey:(nonnull NSString*)cVaultKey
											 keys:(nonnull PowerAuthCoreSignatureUnlockKeys*)unlockKeys
											 data:(nonnull NSData*)data
{
	std::string cpp_c_vault_key	= cc7::objc::CopyFromNSString(cVaultKey);
	cc7::ByteArray cpp_data		= cc7::objc::CopyFromNSData(data);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_signature;
	auto error = _session->signDataWithDevicePrivateKey(cpp_c_vault_key, cpp_keys, cpp_data, cpp_signature);
	if (error == EC_Ok) {
		return cc7::objc::CopyToNSData(cpp_signature);
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"SignDataWithDevicePrivateKey", error);
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
	PowerAuthCoreObjc_DebugDumpError(self, @"SetExternalEncryptionKey", error);
	return error == EC_Ok;
}

- (BOOL) addExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
{
	auto error = _session->addExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
	PowerAuthCoreObjc_DebugDumpError(self, @"AddExternalEncryptionKey", error);
	return error == EC_Ok;
}

- (BOOL) removeExternalEncryptionKey
{
	auto error = _session->removeExternalEncryptionKey();
	PowerAuthCoreObjc_DebugDumpError(self, @"RemoveExternalEncryptionKey", error);
	return error == EC_Ok;
}


#pragma mark - ECIES

- (nullable PowerAuthCoreEciesEncryptor*) eciesEncryptorForScope:(PowerAuthCoreEciesEncryptorScope)scope
															keys:(nullable PowerAuthCoreSignatureUnlockKeys*)unlockKeys
													 sharedInfo1:(nullable NSData*)sharedInfo1
{
	ECIESEncryptorScope cpp_scope   = (ECIESEncryptorScope)scope;
	cc7::ByteArray cpp_shared_info1 = cc7::objc::CopyFromNSData(sharedInfo1);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	PowerAuthCoreEciesEncryptor * encryptor = [[PowerAuthCoreEciesEncryptor alloc] init];
	auto error = _session->getEciesEncryptor(cpp_scope, cpp_keys, cpp_shared_info1, encryptor.encryptorRef);
	PowerAuthCoreObjc_DebugDumpError(self, @"GetEciesEncryptor", error);
	return error == EC_Ok ? encryptor : nil;
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


- (nonnull NSString*) generateActivationStatusChallenge
{
	return cc7::objc::CopyToNSString(Session::generateSignatureUnlockKey().base64String());
}


#pragma mark - Protocol upgrade

- (BOOL) startProtocolUpgrade
{
	ErrorCode error = _session->startProtocolUpgrade();
	PowerAuthCoreObjc_DebugDumpError(self, @"StartProtocolUpgrade", error);
	return error == EC_Ok;
}

- (PowerAuthCoreProtocolVersion) pendingProtocolUpgradeVersion
{
	return (PowerAuthCoreProtocolVersion) _session->pendingProtocolUpgradeVersion();
}

- (BOOL) applyProtocolUpgradeData:(nonnull id<PowerAuthCoreProtocolUpgradeData>)upgradeData
{
	ErrorCode error;
	if ([upgradeData conformsToProtocol:@protocol(PowerAuthCoreProtocolUpgradeDataPrivate)]) {
		id<PowerAuthCoreProtocolUpgradeDataPrivate> upgradeDataObject = (id<PowerAuthCoreProtocolUpgradeDataPrivate>)upgradeData;
		// Convert data to C++ & commit to underlying session
		ProtocolUpgradeData cpp_upgrade_data;
		[upgradeDataObject setupStructure:cpp_upgrade_data];
		error = _session->applyProtocolUpgradeData(cpp_upgrade_data);
	} else {
		error = EC_WrongParam;
	}
	PowerAuthCoreObjc_DebugDumpError(self, @"ApplyProtocolUpgradeData", error);
	return error == EC_Ok;
}

- (BOOL) finishProtocolUpgrade
{
	ErrorCode error = _session->finishProtocolUpgrade();
	PowerAuthCoreObjc_DebugDumpError(self, @"FinishProtocolUpgrade", error);
	return error == EC_Ok;
}

+ (NSString*) maxSupportedHttpProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
{
	return cc7::objc::CopyToNSString(Session::maxSupportedHttpProtocolVersion(static_cast<Version>(protocolVersion)));
}

#pragma mark - Recovery codes

- (BOOL) hasActivationRecoveryData
{
	return _session->hasActivationRecoveryData();
}

- (PowerAuthCoreRecoveryData*) activationRecoveryData:(NSString *)cVaultKey keys:(PowerAuthCoreSignatureUnlockKeys *)unlockKeys
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	RecoveryData cpp_recovery_data;
	ErrorCode error = _session->getActivationRecoveryData(cpp_c_vault_key, cpp_keys, cpp_recovery_data);
	if (error != EC_Ok) {
		PowerAuthCoreObjc_DebugDumpError(self, @"ActivationRecoveryData", error);
		return nil;
	}
	return PowerAuthCoreRecoveryDataToObject(cpp_recovery_data);
}

@end
