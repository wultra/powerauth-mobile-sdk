/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2ECIESEncryptor.h"
#include <PowerAuth/ECIES.h>
#include <cc7/objc/ObjcHelper.h>
#import "PA2PrivateImpl.h"

using namespace io::getlime::powerAuth;


#pragma mark - ECIES Encryptor implementation -

@implementation PA2ECIESEncryptor
{
	ECIESEncryptor _encryptor;
}


#pragma mark Initialization

- (id) initWithObject:(const ECIESEncryptor &)objectRef
{
	self = [super init];
	if (self) {
		_encryptor = objectRef;
	}
	return self;
}

- (id) initWithPublicKey:(NSData*)publicKey sharedInfo2:(NSData*)sharedInfo
{
	return [self initWithObject: ECIESEncryptor(cc7::objc::CopyFromNSData(publicKey), cc7::objc::CopyFromNSData(sharedInfo))];
}

- (id) initWithEnvelopeKey:(NSData*)envelopeKey sharedInfo2:(NSData*)sharedInfo
{
	ECIESEnvelopeKey key = cc7::MakeRange(cc7::objc::CopyFromNSData(envelopeKey));
	return [self initWithObject: ECIESEncryptor(key, cc7::objc::CopyFromNSData(sharedInfo))];
}


#pragma mark Setters & Getters

- (ECIESEncryptor &) encryptorRef
{
	return _encryptor;
}

- (NSData*) publicKey
{
	return cc7::objc::CopyToNullableNSData(_encryptor.publicKey());
}

- (void) setSharedInfo2:(NSData *)sharedInfo2
{
	_encryptor.setSharedInfo2(cc7::objc::CopyFromNSData(sharedInfo2));
}

- (NSData*) sharedInfo2
{
	return cc7::objc::CopyToNullableNSData(_encryptor.sharedInfo2());
}


#pragma mark - Encrypt & Decrypt

- (nullable PA2ECIESCryptogram *) encryptRequest:(nullable NSData *)data
{
	PA2ECIESCryptogram * cryptogram = [[PA2ECIESCryptogram alloc] init];
	auto ec = _encryptor.encryptRequest(cc7::objc::CopyFromNSData(data), cryptogram.cryptogramRef);
	PA2Objc_DebugDumpError(self, @"EncryptRequest", ec);
	return ec == EC_Ok ? cryptogram : nil;
}

- (nullable NSData *) decryptResponse:(nonnull PA2ECIESCryptogram *)cryptogram
{
	cc7::ByteArray data;
	auto ec = _encryptor.decryptResponse(cryptogram.cryptogramRef, data);
	PA2Objc_DebugDumpError(self, @"DecryptResponse", ec);
	return ec == EC_Ok ? cc7::objc::CopyToNSData(data) : nil;
}

@end




#pragma mark - ECIES Cryptogram implementation -

@implementation PA2ECIESCryptogram
{
	ECIESCryptogram _c;
}

- (ECIESCryptogram &) cryptogramRef
{
	return _c;
}

// NSData setters and getters

- (void) setBody:(NSData *)body
{
	_c.body = cc7::objc::CopyFromNSData(body);
}
- (NSData*) body
{
	return cc7::objc::CopyToNullableNSData(_c.body);
}

- (void) setMac:(NSData *)mac
{
	_c.mac = cc7::objc::CopyFromNSData(mac);
}
- (NSData*) mac
{
	return cc7::objc::CopyToNullableNSData(_c.mac);
}

- (void) setKey:(NSData *)key
{
	_c.key = cc7::objc::CopyFromNSData(key);
}
- (NSData*) key
{
	return cc7::objc::CopyToNullableNSData(_c.key);
}


// Base64 setters and getters

- (void) setBodyBase64:(NSString *)bodyBase64
{
	_c.body.readFromBase64String(cc7::objc::CopyFromNSString(bodyBase64));
}
- (NSString*) bodyBase64
{
	return cc7::objc::CopyToNullableNSString(_c.body.base64String());
}

- (void) setMacBase64:(NSString *)macBase64
{
	_c.mac.readFromBase64String(cc7::objc::CopyFromNSString(macBase64));
}
- (NSString*) macBase64
{
	return cc7::objc::CopyToNullableNSString(_c.mac.base64String());
}

- (void) setKeyBase64:(NSString *)keyBase64
{
	_c.key.readFromBase64String(cc7::objc::CopyFromNSString(keyBase64));
}
- (NSString*) keyBase64
{
	return cc7::objc::CopyToNullableNSString(_c.key.base64String());
}

@end

