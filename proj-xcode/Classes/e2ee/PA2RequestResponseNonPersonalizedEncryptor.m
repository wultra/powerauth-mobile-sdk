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

#import "PA2RequestResponseNonPersonalizedEncryptor.h"
#import "PA2ErrorConstants.h"

@implementation PA2RequestResponseNonPersonalizedEncryptor {
	PA2Encryptor *_encryptor;
}

- (instancetype)initWithEncryptor:(PA2Encryptor *)encryptor {
	self = [super init];
	if (self) {
		_encryptor = encryptor;
	}
	return self;
}

- (PA2Request<PA2NonPersonalizedEncryptedObject*>*) encryptRequestData:(NSData*)requestData error:(NSError **)error {
	PA2EncryptedMessage *message = [_encryptor encrypt:requestData];
	
	if (_encryptor.lastErrorCode != PA2CoreErrorCode_Ok) {
		if (error) {
			*error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil];
		}
		return nil;
	}
	
	PA2NonPersonalizedEncryptedObject *requestObject = [[PA2NonPersonalizedEncryptedObject alloc] init];
	requestObject.applicationKey = message.applicationKey;
	requestObject.sessionIndex = message.sessionIndex;
	requestObject.adHocIndex = message.adHocIndex;
	requestObject.macIndex = message.macIndex;
	requestObject.nonce = message.nonce;
	requestObject.ephemeralPublicKey = message.ephemeralPublicKey;
	requestObject.mac = message.mac;
	requestObject.encryptedData = message.encryptedData;
	
	PA2Request<PA2NonPersonalizedEncryptedObject*>* request = [[PA2Request alloc] init];
	request.encryption = PA2RestRequestEncryption_NonPersonalized;
	request.requestObject = requestObject;
	return request;
}

- (NSData*) decryptResponse:(PA2Response<PA2NonPersonalizedEncryptedObject*>*)response error:(NSError **)error {
	if (response.encryption == PA2RestRequestEncryption_NonPersonalized) {
		
		PA2NonPersonalizedEncryptedObject *responseObject = response.responseObject;
		
		// Prepare the decrypted message payload
		PA2EncryptedMessage *message = [[PA2EncryptedMessage alloc] init];
		message.applicationKey = responseObject.applicationKey;
		message.sessionIndex = responseObject.sessionIndex;
		message.adHocIndex = responseObject.adHocIndex;
		message.macIndex = responseObject.macIndex;
		message.nonce = responseObject.nonce;
		message.ephemeralPublicKey = responseObject.ephemeralPublicKey;
		message.mac = responseObject.mac;
		message.encryptedData = responseObject.encryptedData;
		
		// Return decrypted data
		NSData *originalData = [_encryptor decrypt:message];
		
		if (_encryptor.lastErrorCode != PA2CoreErrorCode_Ok) {
			if (error) {
				*error = [NSError errorWithDomain:PA2ErrorDomain code:PA2ErrorCodeEncryption userInfo:nil];
			}
			return nil;
		}
		
		return originalData;
	}
	return nil;
}

@end
