/*
 * Copyright 2016-2017 Wultra s.r.o.
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

#import "PA2PrivateImpl.h"
#import "PA2Types.h"

using namespace io::getlime::powerAuth;

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

@implementation PA2HTTPRequestData
@end

@implementation PA2HTTPRequestDataSignature
{
	io::getlime::powerAuth::HTTPRequestDataSignature _signature;
}

- (io::getlime::powerAuth::HTTPRequestDataSignature&) signatureStructRef
{
	return _signature;
}

- (NSString*) version
{
	return cc7::objc::CopyToNSString(_signature.version);
}

- (NSString*) activationId
{
	return cc7::objc::CopyToNSString(_signature.activationId);
}

- (NSString*) applicationKey
{
	return cc7::objc::CopyToNSString(_signature.applicationKey);
}

- (NSString*) nonce
{
	return cc7::objc::CopyToNSString(_signature.nonce);
}

- (NSString*) factor
{
	return cc7::objc::CopyToNSString(_signature.factor);
}

- (NSString*) signature
{
	return cc7::objc::CopyToNSString(_signature.signature);
}

- (NSString*) authHeaderValue
{
	return cc7::objc::CopyToNSString(_signature.buildAuthHeaderValue());
}

@end

@implementation PA2SignedData
{
	io::getlime::powerAuth::SignedData _signedData;
}

- (io::getlime::powerAuth::SignedData&) signedDataRef
{
	return _signedData;
}

// Signing key

- (PA2SigningDataKey) signingDataKey
{
	return static_cast<PA2SigningDataKey>(_signedData.signingKey);
}

- (void) setSigningDataKey:(PA2SigningDataKey)signingDataKey
{
	_signedData.signingKey = static_cast<SignedData::SigningKey>(signingDataKey);
}


// Bytes setters and getters

- (NSData*) data
{
	return cc7::objc::CopyToNSData(_signedData.data);
}

- (void) setData:(NSData *)data
{
	_signedData.data = cc7::objc::CopyFromNSData(data);
}

- (NSData*) signature
{
	return cc7::objc::CopyToNSData(_signedData.signature);
}

- (void) setSignature:(NSData *)signature
{
	_signedData.signature = cc7::objc::CopyFromNSData(signature);
}

// Base64 setters and getters

- (NSString*) dataBase64
{
	return cc7::objc::CopyToNSString(_signedData.data.base64String());
}

- (void) setDataBase64:(NSString *)dataBase64
{
	_signedData.data.readFromBase64String(cc7::objc::CopyFromNSString(dataBase64));
}

- (NSString*) signatureBase64
{
	return cc7::objc::CopyToNSString(_signedData.signature.base64String());
}

- (void) setSignatureBase64:(NSString *)signatureBase64
{
	_signedData.signature.readFromBase64String(cc7::objc::CopyFromNSString(signatureBase64));
}

#ifdef DEBUG
- (NSString*) description
{
	return [NSString stringWithFormat:@"<PA2SignedData data=%@, signature=%@>", self.dataBase64, self.signatureBase64];
}
#endif

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

- (UInt32) failCount
{
	return _status.failCount;
}

- (UInt32) maxFailCount
{
	return _status.maxFailCount;
}

- (UInt32) remainingAttempts
{
	if (_status.state == ActivationStatus::Active) {
		if (_status.maxFailCount >= _status.failCount) {
			return _status.maxFailCount - _status.failCount;
		}
	}
	return 0;
}

#ifdef DEBUG
- (NSString*) description
{
	NSString * status_str;
	switch (_status.state) {
		case ActivationStatus::Created:		status_str = @"CREATED"; break;
		case ActivationStatus::OTP_Used:	status_str = @"OTP_USED"; break;
		case ActivationStatus::Active:		status_str = @"ACTIVE"; break;
		case ActivationStatus::Blocked:		status_str = @"BLOCKED"; break;
		case ActivationStatus::Removed:		status_str = @"REMOVED"; break;
		default:
			status_str = @"<<unknown>>"; break;
			
	}
	bool migration = _status.isMigrationAvailable();
	return [NSString stringWithFormat:@"<PA2ActivationStatus %@, fails %@/%@%@>", status_str, @(_status.failCount), @(_status.maxFailCount), migration ? @", migration" : @""];
}
#endif

// Private

- (UInt8) currentActivationVersion
{
	return _status.currentVersion;
}

- (UInt8) upgradeActivationVersion
{
	return _status.upgradeVersion;
}

- (BOOL) isMigrationAvailable
{
	return _status.isMigrationAvailable();
}

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

void PA2HTTPRequestDataToStruct(PA2HTTPRequestData * req, io::getlime::powerAuth::HTTPRequestData & cpp_req)
{
	cpp_req.body					= cc7::objc::CopyFromNSData(req.body);
	cpp_req.method					= cc7::objc::CopyFromNSString(req.method);
	cpp_req.uri						= cc7::objc::CopyFromNSString(req.uri);
	cpp_req.offlineNonce			= cc7::objc::CopyFromNSString(req.offlineNonce);
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
	res.activationFingerprint		= cc7::objc::CopyToNSString(cpp_r2.activationFingerprint);
	return res;
}
