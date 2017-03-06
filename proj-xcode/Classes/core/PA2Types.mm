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

#import "PA2Types.h"
#import "PA2PrivateImpl.h"

#pragma mark - Constants

const PA2SignatureFactor PA2SignatureFactor_Possession						= 0x0001;
const PA2SignatureFactor PA2SignatureFactor_Knowledge						= 0x0010;
const PA2SignatureFactor PA2SignatureFactor_Biometry						= 0x0100;
const PA2SignatureFactor PA2SignatureFactor_Possession_Knowledge			= 0x0011;
const PA2SignatureFactor PA2SignatureFactor_Possession_Biometry				= 0x0101;
const PA2SignatureFactor PA2SignatureFactor_Possession_Knowledge_Biometry	= 0x0111;
const PA2SignatureFactor PA2SignatureFactor_PrepareForVaultUnlock			= 0x1000;

#pragma mark - Public types implementation

@implementation PA2SessionSetup
@end

@implementation PA2SignatureUnlockKeys
@end

@implementation PA2ActivationStep1Param
@end

@implementation PA2ActivationStep1Result
@end

@implementation PA2ActivationStep2Param
@end

@implementation PA2ActivationStep2Result
@end


@implementation PA2ActivationStatus
{
	io::getlime::powerAuth::ActivationStatus _status;
}

- (id) initWithStatusStruct:(const io::getlime::powerAuth::ActivationStatus&)statusStruct
{
	self = [super init];
	if (self) {
		_status = statusStruct;
	}
	return self;
}

- (PA2ActivationState) state
{
	return static_cast<PA2ActivationState>(_status.state);
}

- (UInt64) counter
{
	return _status.counter;
}

- (UInt32) failCount
{
	return _status.failCount;
}

- (UInt32) maxFailCount
{
	return _status.maxFailCount;
}

@end

@implementation PA2EncryptedMessage
@end


#pragma mark - Conversion routines

void PA2SessionSetupToStruct(PA2SessionSetup * setup, io::getlime::powerAuth::SessionSetup & cpp_setup)
{
	cpp_setup.applicationKey		= cc7::objc::CopyFromNSString(setup.applicationKey);
	cpp_setup.applicationSecret		= cc7::objc::CopyFromNSString(setup.applicationSecret);
	cpp_setup.masterServerPublicKey	= cc7::objc::CopyFromNSString(setup.masterServerPublicKey);
	cpp_setup.externalEncryptionKey = cc7::objc::CopyFromNSData(setup.externalEncryptionKey);
	cpp_setup.sessionIdentifier		= setup.sessionIdentifier;
}

PA2SessionSetup * PA2SessionSetupToObject(const io::getlime::powerAuth::SessionSetup & cpp_setup)
{
	PA2SessionSetup * result = [[PA2SessionSetup alloc] init];
	result.applicationKey			= cc7::objc::CopyToNSString(cpp_setup.applicationKey);
	result.applicationSecret		= cc7::objc::CopyToNSString(cpp_setup.applicationSecret);
	result.masterServerPublicKey	= cc7::objc::CopyToNSString(cpp_setup.masterServerPublicKey);
	result.sessionIdentifier		= cpp_setup.sessionIdentifier;
	result.externalEncryptionKey	= cc7::objc::CopyToNullableNSData(cpp_setup.externalEncryptionKey);
	return result;
}

void PA2SignatureUnlockKeysToStruct(PA2SignatureUnlockKeys * keys, io::getlime::powerAuth::SignatureUnlockKeys & cpp_keys)
{
	cpp_keys.possessionUnlockKey	= cc7::objc::CopyFromNSData(keys.possessionUnlockKey);
	cpp_keys.biometryUnlockKey		= cc7::objc::CopyFromNSData(keys.biometryUnlockKey);
	if (keys.userPassword != nil) {
		cpp_keys.userPassword		= [keys.userPassword passObjRef].passwordData();
	} else {
		cpp_keys.userPassword.clear();
	}
}

PA2ActivationStatus * PA2ActivationStatusToObject(const io::getlime::powerAuth::ActivationStatus& cpp_status)
{
	return [[PA2ActivationStatus alloc] initWithStatusStruct:cpp_status];
}

void PA2ActivationStep1ParamToStruct(PA2ActivationStep1Param * p1, io::getlime::powerAuth::ActivationStep1Param & cpp_p1)
{
	cpp_p1.activationIdShort		= cc7::objc::CopyFromNSString(p1.activationIdShort);
	cpp_p1.activationOtp			= cc7::objc::CopyFromNSString(p1.activationOtp);
	cpp_p1.activationSignature		= cc7::objc::CopyFromNSString(p1.activationSignature);
}

PA2ActivationStep1Result * PA2ActivationStep1ResultToObject(const io::getlime::powerAuth::ActivationStep1Result& cpp_r1)
{
	PA2ActivationStep1Result * res = [[PA2ActivationStep1Result alloc] init];
	res.activationNonce				= cc7::objc::CopyToNSString(cpp_r1.activationNonce);
	res.cDevicePublicKey			= cc7::objc::CopyToNSString(cpp_r1.cDevicePublicKey);
	res.applicationSignature		= cc7::objc::CopyToNSString(cpp_r1.applicationSignature);
    res.ephemeralPublicKey          = cc7::objc::CopyToNSString(cpp_r1.ephemeralPublicKey);
	return res;
}

void PA2ActivationStep2ParamToStruct(PA2ActivationStep2Param * p2, io::getlime::powerAuth::ActivationStep2Param & cpp_p2)
{
	cpp_p2.activationId				= cc7::objc::CopyFromNSString(p2.activationId);
	cpp_p2.ephemeralNonce			= cc7::objc::CopyFromNSString(p2.ephemeralNonce);
	cpp_p2.ephemeralPublicKey		= cc7::objc::CopyFromNSString(p2.ephemeralPublicKey);
	cpp_p2.encryptedServerPublicKey	= cc7::objc::CopyFromNSString(p2.encryptedServerPublicKey);
	cpp_p2.serverDataSignature		= cc7::objc::CopyFromNSString(p2.serverDataSignature);
}

PA2ActivationStep2Result * PA2ActivationStep2ResultToObject(const io::getlime::powerAuth::ActivationStep2Result& cpp_r2)
{
	PA2ActivationStep2Result * res = [[PA2ActivationStep2Result alloc] init];
	res.hkDevicePublicKey			= cc7::objc::CopyToNSString(cpp_r2.hkDevicePublicKey);
	return res;
}

void PA2EncryptedMessageToStruct(PA2EncryptedMessage * msg, io::getlime::powerAuth::EncryptedMessage& cpp_msg)
{
	cpp_msg.applicationKey			= cc7::objc::CopyFromNSString(msg.applicationKey);
	cpp_msg.activationId			= cc7::objc::CopyFromNSString(msg.activationId);
	cpp_msg.encryptedData			= cc7::objc::CopyFromNSString(msg.encryptedData);
	cpp_msg.mac						= cc7::objc::CopyFromNSString(msg.mac);
	cpp_msg.sessionIndex			= cc7::objc::CopyFromNSString(msg.sessionIndex);
	cpp_msg.adHocIndex				= cc7::objc::CopyFromNSString(msg.adHocIndex);
	cpp_msg.macIndex				= cc7::objc::CopyFromNSString(msg.macIndex);
	cpp_msg.nonce					= cc7::objc::CopyFromNSString(msg.nonce);
	cpp_msg.ephemeralPublicKey		= cc7::objc::CopyFromNSString(msg.ephemeralPublicKey);
}

PA2EncryptedMessage * PA2EncryptedMessageToObject(const io::getlime::powerAuth::EncryptedMessage& cpp_msg)
{
	PA2EncryptedMessage * res = [[PA2EncryptedMessage alloc] init];
	res.applicationKey				= cc7::objc::CopyToNullableNSString(cpp_msg.applicationKey);
	res.activationId				= cc7::objc::CopyToNullableNSString(cpp_msg.activationId);
	res.encryptedData				= cc7::objc::CopyToNSString(cpp_msg.encryptedData);
	res.mac							= cc7::objc::CopyToNSString(cpp_msg.mac);
	res.sessionIndex				= cc7::objc::CopyToNSString(cpp_msg.sessionIndex);
	res.adHocIndex					= cc7::objc::CopyToNSString(cpp_msg.adHocIndex);
	res.macIndex					= cc7::objc::CopyToNSString(cpp_msg.macIndex);
	res.nonce						= cc7::objc::CopyToNSString(cpp_msg.nonce);
	res.ephemeralPublicKey			= cc7::objc::CopyToNullableNSString(cpp_msg.ephemeralPublicKey);
	return res;
}
