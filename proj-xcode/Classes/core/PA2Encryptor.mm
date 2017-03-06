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

#import "PA2Encryptor.h"
#import "PA2PrivateImpl.h"

#pragma mark - PA2Encryptor -

using namespace io::getlime::powerAuth;

@implementation PA2Encryptor
{
	Encryptor * _encryptor;
	ErrorCode _error;
}

- (void) dealloc
{
	delete _encryptor;
}

- (PA2CoreErrorCode) lastErrorCode
{
	return (PA2CoreErrorCode)_error;
}

- (PA2EncryptorMode) encryptionMode
{
	if (_encryptor) {
		return (PA2EncryptorMode)_encryptor->encryptionMode();
	}
	return PA2EncryptorMode_Nonpersonalized;
}

- (nonnull NSData*) sessionIndex
{
	if (_encryptor) {
		return cc7::objc::CopyToNSData(_encryptor->sessionIndex());
	}
	return [NSData data];
}

- (nullable PA2EncryptedMessage*) encrypt:(nonnull NSData*)data
{
	if (_encryptor) {
		cc7::ByteArray cpp_data = cc7::objc::CopyFromNSData(data);
		EncryptedMessage cpp_message;
		_error = _encryptor->encrypt(cpp_data, cpp_message);
		if (_error == EC_Ok) {
			return PA2EncryptedMessageToObject(cpp_message);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}

- (nullable NSData*) decrypt:(nonnull PA2EncryptedMessage*)message
{
	if (_encryptor) {
		EncryptedMessage cpp_message;
		PA2EncryptedMessageToStruct(message, cpp_message);
		cc7::ByteArray cpp_data;
		_error = _encryptor->decrypt(cpp_message, cpp_data);
		if (_error == EC_Ok) {
			return cc7::objc::CopyToNSData(cpp_data);
		}
	} else {
		_error = EC_WrongParam;
	}
	return nil;
}

@end


#pragma mark -
#pragma mark PA2Encryptor (Private) -

@implementation PA2Encryptor (Private)

- (id) initWithEncryptorPtr:(io::getlime::powerAuth::Encryptor*)encryptor
{
	self = [super init];
	if (self) {
		self->_encryptor = encryptor;
	}
	return self;
}

@end
